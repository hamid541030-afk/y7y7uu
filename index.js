// tunnel-node روی Cloudflare Workers — نسخه‌ی ۲.۲ (کم‌مصرف + کم‌لگ)
// تفاوت با نسخه‌ی قبل:
//  • به‌جای یک Durable Object برای هر اتصال، فقط «یک» Durable Object (hub) همه‌ی اتصال‌ها رو نگه می‌داره.
//    هر batch = ۱ درخواست Worker + ۱ درخواست DO (نه یکی برای هر عملیات).
//  • batch بعد از اولین داده فقط تا وقتی داده‌ی تازه می‌رسه صبر می‌کنه (سریع برای پاسخ کوچیک، پر برای دانلود).
//  • اتصال‌های بیکار بعد از ۳۰ ثانیه بسته می‌شن تا مصرف Duration متوقف بشه.
//  • (۲.۲) اتصال کند به یه سایت، بقیه‌ی batch رو معطل نمی‌کنه؛ poll بیکار موقع استفاده کوتاه‌تره.
//  • آدرس‌های خصوصی (مثل 10.x.x.x که DNS فیلترشده می‌ده) سریع رد می‌شن.
// پشتیبانی: TCP. پشتیبانی نمی‌شود: UDP، فشرده‌سازی (zops/zc)
import { connect } from "cloudflare:sockets";
import { DurableObject } from "cloudflare:workers";

// ───── تنظیمات قابل تغییر ─────
const CONNECT_TIMEOUT_MS = 5000;   // حداکثر صبر برای باز شدن اتصال TCP
const WRITE_WAIT_MS = 800;         // بعد از نوشتن داده، حداکثر صبر برای اولین جواب
const POLL_ACTIVE_WAIT_MS = 300;   // poll خالی وقتی تازه ترافیک بوده: کوتاه (لگ کمتر)
const POLL_IDLE_WAIT_MS = 1500;    // poll خالی وقتی چند ثانیه ترافیکی نبوده: بلند (درخواست کمتر)
const ACTIVE_WINDOW_MS = 4000;     // «تازه ترافیک بوده» یعنی در همین چند میلی‌ثانیه اخیر
const CONNECT_SOFT_MS = 1200;      // اتصال کندتر از این batch رو معطل نمی‌کنه؛ پشت‌صحنه ادامه می‌ده
const SLOW_BATCH_LOG_MS = 1800;    // batchهای کندتر از این توی لاگ Cloudflare ثبت می‌شن
const QUIET_MS = 60;               // بعد از اولین داده، تا وقتی داده‌ی تازه می‌رسه صبر می‌کنه (هر بار این‌قدر)
const MAX_COALESCE_MS = 350;       // سقف این صبر؛ هرچی بیشتر باشه داده‌ی بیشتری با هر رفت‌وبرگشت می‌ره
const SESSION_IDLE_MS = 30000;     // اتصالی که این‌قدر بدون عملیات بمونه بسته می‌شه
const SWEEP_MS = 5000;             // هر چند وقت یک‌بار اتصال‌های بیکار چک بشن
const MAX_SESSIONS = 150;          // حداکثر اتصال هم‌زمان
const MAX_BUFFER = 2 * 1024 * 1024;        // سقف بافر خوانده‌نشده‌ی هر اتصال
const MAX_TOTAL_BUFFER = 40 * 1024 * 1024; // سقف بافر کل اتصال‌ها (محافظ حافظه)
const MAX_REPLY_BYTES = 1024 * 1024;   // سقف حجم جواب هر عملیات
const MAX_BATCH_REPLY = 6 * 1024 * 1024; // سقف حجم کل جواب هر batch
const HUB_NAME = "hub-v1";
const SID_RE = /^[0-9a-f-]{36}$/;

// ───── ابزارها ─────
function b64ToBytes(s) {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToB64(u8) {
  let s = "";
  const CH = 0x8000;
  for (let i = 0; i < u8.length; i += CH) {
    s += String.fromCharCode.apply(null, u8.subarray(i, i + CH));
  }
  return btoa(s);
}

async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  const x = new Uint8Array(ha);
  const y = new Uint8Array(hb);
  let d = 0;
  for (let i = 0; i < x.length; i++) d |= x[i] ^ y[i];
  return d === 0;
}

function withTimeout(promise, ms, msg) {
  let t;
  const timeout = new Promise((_, rej) => {
    t = setTimeout(() => rej(new Error(msg)), ms);
  });
  return Promise.race([promise, timeout]).finally(() => clearTimeout(t));
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// منتظر p می‌مونه ولی بیشتر از ms نه (بدون خطا)
function softWait(p, ms) {
  let t;
  const timer = new Promise((r) => (t = setTimeout(r, ms)));
  return Promise.race([p, timer]).finally(() => clearTimeout(t));
}

// آدرس‌های خصوصی/محلی (مثل جواب DNS فیلترشده: 10.10.34.x) قابل‌اتصال نیستن
function isPrivateHost(h) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(h);
  if (m) {
    const a = +m[1], b = +m[2];
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true;
    if (a === 192 && b === 0) return true; // 192.0.0.0/24 و 192.0.2.0/24
    if (a >= 224) return true;
  }
  const l = h.toLowerCase();
  return l === "localhost" || l === "::1" || l.endsWith(".local") || l.endsWith(".internal");
}

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), {
    status,
    headers: { "content-type": "application/json" },
  });

const decoy = () => new Response("Not Found", { status: 404 });

// ───── Worker (ورودی HTTP) ─────
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "");
    if (request.method !== "POST" || (path !== "/tunnel" && path !== "/tunnel/batch")) {
      return decoy();
    }
    if (!env.TUNNEL_AUTH_KEY) return json({ e: "server not configured" }, 500);

    let body;
    try {
      body = await request.json();
    } catch (_) {
      return decoy();
    }
    if (!body || typeof body.k !== "string" || !(await safeEqual(body.k, env.TUNNEL_AUTH_KEY))) {
      return decoy();
    }

    const hub = env.SESSION.get(env.SESSION.idFromName(HUB_NAME));

    try {
      if (path === "/tunnel") {
        const r = await hub.batch([body]);
        return json(r[0]);
      }
      if (body.zops) {
        return json({ e: "compression not supported", code: "UNSUPPORTED_OP" });
      }
      if (!Array.isArray(body.ops)) return json({ e: "bad request" });
      return json({ r: await hub.batch(body.ops) });
    } catch (err) {
      return json({ e: String((err && err.message) || err) });
    }
  },
};

// ───── یک اتصال TCP ─────
class Session {
  constructor(hub, host, port) {
    this.hub = hub;
    this.host = host;
    this.port = port;
    this.socket = null;
    this.writer = null;
    this.chunks = [];
    this.buffered = 0;
    this.eof = false;
    this.closed = false;
    this.drainWaiter = null;
    this.lastActive = Date.now();
    this.opening = null;
    this.isOpen = false;
    this.err = null;
    this.queue = []; // نوشته‌هایی که قبل از باز شدن اتصال رسیدن
  }

  // اتصال رو (پشت‌صحنه) باز می‌کنه و داده‌ی اول رو می‌نویسه. خطا توی this.err می‌مونه.
  start(firstB64) {
    this.opening = (async () => {
      this.socket = connect({ hostname: this.host, port: this.port });
      await withTimeout(this.socket.opened, CONNECT_TIMEOUT_MS, "connect timeout");
      this.writer = this.socket.writable.getWriter();
      this._readLoop(); // در پس‌زمینه
      if (firstB64) {
        const werr = await this._rawWrite(firstB64);
        if (werr) throw new Error(werr);
      }
      while (this.queue.length) {
        const werr = await this._rawWrite(this.queue.shift());
        if (werr) throw new Error(werr);
      }
      this.isOpen = true;
    })().catch((err) => {
      this.err = "connect failed: " + String((err && err.message) || err);
      this.eof = true;
      try { this.socket && this.socket.close(); } catch (_) {}
      this.hub._notify();
    });
    return this.opening;
  }

  async _rawWrite(b64) {
    try {
      await this.writer.write(b64ToBytes(b64));
      return null;
    } catch (err) {
      return "write failed: " + String((err && err.message) || err);
    }
  }

  async write(b64) {
    if (this.err) return this.err;
    if (this.closed) return "session closed";
    if (!this.isOpen) {
      // هنوز باز نشده: توی صف می‌ذاریم تا بعد از باز شدن به‌ترتیب نوشته بشه (batch معطل نمی‌شه)
      this.queue.push(b64);
      return null;
    }
    return this._rawWrite(b64);
  }

  async _readLoop() {
    const reader = this.socket.readable.getReader();
    try {
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (value && value.byteLength) {
          this.chunks.push(value);
          this.buffered += value.byteLength;
          this.hub.total += value.byteLength;
          this.hub._notify();
          while (
            (this.buffered > MAX_BUFFER || this.hub.total > MAX_TOTAL_BUFFER) &&
            !this.closed
          ) {
            await new Promise((r) => (this.drainWaiter = r));
          }
        }
        if (this.closed) break;
      }
    } catch (_) {
      // اتصال قطع شد
    }
    this.eof = true;
    this.hub._notify();
  }

  hasData() {
    return this.chunks.length > 0 || this.eof;
  }

  // حداکثر maxBytes از بافر رو برمی‌داره
  drain(maxBytes) {
    let total = 0;
    const parts = [];
    while (this.chunks.length && total < maxBytes) {
      const c = this.chunks[0];
      const take = Math.min(c.byteLength, maxBytes - total);
      if (take < c.byteLength) {
        parts.push(c.subarray(0, take));
        this.chunks[0] = c.subarray(take);
      } else {
        parts.push(c);
        this.chunks.shift();
      }
      total += take;
    }
    this.buffered -= total;
    this.hub.total -= total;
    this.hub._wakeDrainers();
    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
      out.set(p, off);
      off += p.byteLength;
    }
    return { bytes: out, eofNow: this.eof && this.chunks.length === 0 };
  }

  close() {
    this.closed = true;
    this.hub.total -= this.buffered;
    this.buffered = 0;
    this.chunks = [];
    try { this.writer && this.writer.releaseLock(); } catch (_) {}
    try { this.socket && this.socket.close(); } catch (_) {}
    this.socket = null;
    this.writer = null;
    if (this.drainWaiter) {
      const d = this.drainWaiter;
      this.drainWaiter = null;
      d();
    }
  }
}

// ───── Durable Object: «hub» همه‌ی اتصال‌ها رو نگه می‌داره ─────
export class TunnelSession extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.sessions = new Map();
    this.wakers = new Set();
    this.sweeper = null;
    this.total = 0; // مجموع بایت‌های خوانده‌نشده‌ی همه‌ی اتصال‌ها
    this.lastActivity = 0; // آخرین زمانی که ترافیک واقعی بود
  }

  _wakeDrainers() {
    for (const s of this.sessions.values()) {
      if (s.drainWaiter && s.buffered <= MAX_BUFFER && this.total <= MAX_TOTAL_BUFFER) {
        const d = s.drainWaiter;
        s.drainWaiter = null;
        d();
      }
    }
  }

  async batch(ops) {
    const t0 = Date.now();
    const n = ops.length;
    const results = new Array(n);
    const sids = new Array(n).fill(null);
    const waits = new Array(n).fill(0);

    // ۱) اجرای عملیات‌ها (هم‌زمان؛ عملیات‌های یک sid پشت‌سرهم)
    const chains = new Map();
    const tasks = ops.map((op, i) => {
      const key = op && typeof op.sid === "string" ? op.sid : null;
      const run = () => this._apply(op, i, results, sids, waits);
      if (!key) return run();
      const prev = chains.get(key) || Promise.resolve();
      const p = prev.then(run);
      chains.set(key, p.catch(() => {}));
      return p;
    });
    await Promise.all(tasks);
    const tApplied = Date.now();

    // ۲) صبر تا اولین داده (یا پایان مهلت)
    const waitIdx = [];
    let budget = 0;
    for (let i = 0; i < n; i++) {
      if (sids[i] && waits[i] > 0 && results[i] === undefined) {
        waitIdx.push(i);
        budget = Math.max(budget, waits[i]);
      }
    }
    if (waitIdx.length) {
      const anyReady = () =>
        waitIdx.some((i) => {
          const s = this.sessions.get(sids[i]);
          return !s || s.hasData();
        });
      if (!anyReady()) await this._waitUntil(anyReady, budget);
      if (anyReady()) {
        // تا وقتی داده‌ی تازه می‌رسه صبر کن (حداکثر MAX_COALESCE_MS) تا هر رفت‌وبرگشت پرتر بره
        const sizeNow = () =>
          waitIdx.reduce((a, i) => {
            const s = this.sessions.get(sids[i]);
            return a + (s ? s.buffered : 0);
          }, 0);
        const start = Date.now();
        let last = -1;
        for (;;) {
          const cur = sizeNow();
          if (cur === last || cur >= MAX_BATCH_REPLY) break;
          last = cur;
          if (Date.now() - start >= MAX_COALESCE_MS) break;
          await sleep(QUIET_MS);
        }
      }
    }

    const tWaited = Date.now();

    // ۳) جمع‌کردن جواب‌ها
    let remaining = MAX_BATCH_REPLY;
    for (let i = 0; i < n; i++) {
      if (results[i] !== undefined) continue;
      const sid = sids[i];
      const s = sid ? this.sessions.get(sid) : null;
      if (!s) {
        results[i] = { sid, d: "", eof: true };
        continue;
      }
      const { bytes, eofNow } = s.drain(Math.min(MAX_REPLY_BYTES, Math.max(remaining, 0)));
      remaining -= bytes.byteLength;
      if (bytes.byteLength) this.lastActivity = Date.now();
      const res = { sid, d: bytesToB64(bytes), eof: eofNow };
      if (s.err) res.e = s.err;
      results[i] = res;
      if (eofNow) this._drop(sid);
    }

    const tEnd = Date.now();
    if (tEnd - t0 > SLOW_BATCH_LOG_MS) {
      console.log(JSON.stringify({
        slowBatch: true, ops: n, totalMs: tEnd - t0, applyMs: tApplied - t0,
        waitMs: tWaited - tApplied, collectMs: tEnd - tWaited,
        sessions: this.sessions.size, bufferedKB: Math.round(this.total / 1024),
      }));
    }
    return results;
  }

  async _apply(op, i, results, sids, waits) {
    try {
      if (!op || typeof op.op !== "string") {
        results[i] = { e: "bad op" };
        return;
      }
      const data = op.d ?? op.data ?? "";

      switch (op.op) {
        case "connect":
        case "connect_data": {
          const host = String(op.host || "");
          const port = Number(op.port);
          if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
            results[i] = { e: "bad target" };
            return;
          }
          if (isPrivateHost(host)) {
            results[i] = { e: "blocked address: " + host, eof: true };
            return;
          }
          if (this.sessions.size >= MAX_SESSIONS) {
            results[i] = { e: "too many sessions", eof: true };
            return;
          }
          const sid = crypto.randomUUID();
          const s = new Session(this, host, port);
          const first = op.op === "connect_data" ? data : "";
          this.sessions.set(sid, s);
          this._ensureSweeper();
          sids[i] = sid;
          this.lastActivity = Date.now();
          // اتصال کند بقیه‌ی batch رو معطل نمی‌کنه: بعد از CONNECT_SOFT_MS بدون منتظر موندن ادامه می‌ده
          await softWait(s.start(first), CONNECT_SOFT_MS);
          if (s.err) {
            results[i] = { sid, e: s.err, eof: true };
            this._drop(sid);
            return;
          }
          if (first && s.isOpen) waits[i] = WRITE_WAIT_MS;
          return;
        }
        case "data": {
          const sid = String(op.sid || "");
          const s = SID_RE.test(sid) ? this.sessions.get(sid) : null;
          if (!s) {
            results[i] = { sid, e: "session closed", eof: true };
            return;
          }
          s.lastActive = Date.now();
          sids[i] = sid;
          if (data) {
            this.lastActivity = Date.now();
            const werr = await s.write(data);
            if (werr) {
              this._drop(sid);
              results[i] = { sid, e: werr, eof: true };
              return;
            }
            waits[i] = s.isOpen ? WRITE_WAIT_MS : 0;
          } else {
            waits[i] =
              Date.now() - this.lastActivity < ACTIVE_WINDOW_MS
                ? POLL_ACTIVE_WAIT_MS
                : POLL_IDLE_WAIT_MS;
          }
          return;
        }
        case "close": {
          const sid = String(op.sid || "");
          this._drop(sid);
          results[i] = { sid, eof: true };
          return;
        }
        case "udp_open":
        case "udp_data":
        case "udp_close":
          results[i] = { e: "udp not supported on worker", code: "UNSUPPORTED_OP" };
          return;
        default:
          results[i] = { e: "unknown tunnel op: " + op.op, code: "UNSUPPORTED_OP" };
      }
    } catch (err) {
      results[i] = { e: String((err && err.message) || err) };
    }
  }

  _drop(sid) {
    const s = this.sessions.get(sid);
    if (s) {
      s.close();
      this.sessions.delete(sid);
    }
  }

  _notify() {
    for (const w of [...this.wakers]) w();
  }

  _waitUntil(pred, ms) {
    return new Promise((resolve) => {
      const t = setTimeout(finish, ms);
      this.wakers.add(check);
      function check() {
        if (pred()) finish();
      }
      const wakers = this.wakers;
      function finish() {
        clearTimeout(t);
        wakers.delete(check);
        resolve();
      }
    });
  }

  // اتصال‌های بیکار رو می‌بنده؛ وقتی هیچ اتصالی نمونده متوقف می‌شه تا DO بتونه آزاد بشه
  _ensureSweeper() {
    if (this.sweeper) return;
    this.sweeper = setInterval(() => {
      const now = Date.now();
      for (const [sid, s] of this.sessions) {
        if (now - s.lastActive > SESSION_IDLE_MS) this._drop(sid);
      }
      if (this.sessions.size === 0) {
        clearInterval(this.sweeper);
        this.sweeper = null;
      }
    }, SWEEP_MS);
  }
}
