// tunnel-node روی Cloudflare Workers (تلاش برای سازگاری با پروتکل mhrv-rs)
// پروتکل از روی سمت Apps Script (CodeFull.gs) استنباط شده؛ با tunnel-node واقعی مقایسه نشده.
// پشتیبانی: TCP (connect / connect_data / data / close)
// پشتیبانی نمی‌شود: UDP، فشرده‌سازی (zops/zc)
import { connect } from "cloudflare:sockets";
import { DurableObject } from "cloudflare:workers";

// ───── تنظیمات قابل تغییر ─────
const CONNECT_TIMEOUT_MS = 8000;  // حداکثر صبر برای باز شدن اتصال TCP
const WRITE_WAIT_MS = 500;        // بعد از نوشتن داده، چقدر برای جواب صبر کنه
const POLL_WAIT_MS = 1000;        // برای درخواست خالی (poll)، چقدر منتظر داده بمونه
const COALESCE_MS = 80;           // بعد از رسیدن اولین داده، کمی صبر تا داده‌ی بیشتری جمع بشه
const MAX_BUFFER = 2 * 1024 * 1024;   // سقف بافر خوانده‌نشده در هر سشن
const MAX_REPLY_BYTES = 1024 * 1024;   // سقف حجم جواب هر عملیات
const SID_RE = /^[0-9a-f-]{36}$/;

// ───── ابزارها ─────
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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

    if (path === "/tunnel") {
      return json(await safeHandle(env, body));
    }

    // /tunnel/batch
    if (body.zops) {
      return json({ e: "compression not supported", code: "UNSUPPORTED_OP" });
    }
    const ops = Array.isArray(body.ops) ? body.ops : null;
    if (!ops) return json({ e: "bad request" });

    // عملیات‌های یک sid پشت‌سرهم اجرا می‌شن؛ بقیه موازی
    const chains = new Map();
    const results = ops.map((op) => {
      const key = op && typeof op.sid === "string" ? op.sid : null;
      if (!key) return safeHandle(env, op);
      const prev = chains.get(key) || Promise.resolve();
      const p = prev.then(() => safeHandle(env, op));
      chains.set(key, p.catch(() => {}));
      return p;
    });
    return json({ r: await Promise.all(results) });
  },
};

async function safeHandle(env, op) {
  try {
    return await handleOp(env, op);
  } catch (err) {
    return { e: String((err && err.message) || err) };
  }
}

async function handleOp(env, op) {
  if (!op || typeof op.op !== "string") return { e: "bad op" };
  const data = op.d ?? op.data ?? "";

  switch (op.op) {
    case "connect":
    case "connect_data": {
      const host = String(op.host || "");
      const port = Number(op.port);
      if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
        return { e: "bad target" };
      }
      const sid = crypto.randomUUID();
      const stub = env.SESSION.get(env.SESSION.idFromName(sid));
      return await stub.open(sid, host, port, op.op === "connect_data" ? data : "");
    }
    case "data": {
      if (!SID_RE.test(String(op.sid || ""))) return { e: "bad sid", eof: true };
      const stub = env.SESSION.get(env.SESSION.idFromName(op.sid));
      return await stub.send(op.sid, data);
    }
    case "close": {
      if (!SID_RE.test(String(op.sid || ""))) return { sid: op.sid, eof: true };
      const stub = env.SESSION.get(env.SESSION.idFromName(op.sid));
      return await stub.close(op.sid);
    }
    case "udp_open":
    case "udp_data":
    case "udp_close":
      return { e: "udp not supported on worker", code: "UNSUPPORTED_OP" };
    default:
      return { e: "unknown tunnel op: " + op.op, code: "UNSUPPORTED_OP" };
  }
}

// ───── Durable Object: یک اتصال TCP به ازای هر سشن ─────
export class TunnelSession extends DurableObject {
  constructor(ctx, env) {
    super(ctx, env);
    this.socket = null;
    this.writer = null;
    this.chunks = [];
    this.buffered = 0;
    this.eof = false;
    this.closed = false;
    this.waiter = null;
    this.drainWaiter = null;
  }

  async open(sid, host, port, firstB64) {
    try {
      this.socket = connect({ hostname: host, port });
      await withTimeout(this.socket.opened, CONNECT_TIMEOUT_MS, "connect timeout");
    } catch (err) {
      this._teardown();
      return { sid, e: "connect failed: " + String((err && err.message) || err), eof: true };
    }
    this.writer = this.socket.writable.getWriter();
    this._readLoop(); // در پس‌زمینه

    if (firstB64) {
      const werr = await this._write(firstB64);
      if (werr) {
        this._teardown();
        return { sid, e: werr, eof: true };
      }
    }
    return await this._collect(sid, firstB64 ? WRITE_WAIT_MS : 0);
  }

  async send(sid, b64) {
    if (!this.socket || this.closed) {
      return { sid, e: "session closed", eof: true };
    }
    if (b64) {
      const werr = await this._write(b64);
      if (werr) {
        this._teardown();
        return { sid, e: werr, eof: true };
      }
    }
    return await this._collect(sid, b64 ? WRITE_WAIT_MS : POLL_WAIT_MS);
  }

  async close(sid) {
    this._teardown();
    return { sid, eof: true };
  }

  // ── داخلی ──
  async _write(b64) {
    try {
      await this.writer.write(b64ToBytes(b64));
      return null;
    } catch (err) {
      return "write failed: " + String((err && err.message) || err);
    }
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
          this._wake();
          while (this.buffered > MAX_BUFFER && !this.closed) {
            await new Promise((r) => (this.drainWaiter = r));
          }
        }
        if (this.closed) break;
      }
    } catch (_) {
      // اتصال قطع شد
    }
    this.eof = true;
    this._wake();
  }

  _wake() {
    if (this.waiter) {
      const w = this.waiter;
      this.waiter = null;
      w();
    }
  }

  async _collect(sid, maxWaitMs) {
    if (!this.chunks.length && !this.eof && maxWaitMs > 0) {
      await Promise.race([new Promise((r) => (this.waiter = r)), sleep(maxWaitMs)]);
      this.waiter = null;
    }
    if (this.chunks.length && !this.eof) await sleep(COALESCE_MS);

    let total = 0;
    const parts = [];
    while (this.chunks.length && total < MAX_REPLY_BYTES) {
      const c = this.chunks.shift();
      parts.push(c);
      total += c.byteLength;
    }
    this.buffered -= total;
    if (this.drainWaiter && this.buffered <= MAX_BUFFER) {
      const d = this.drainWaiter;
      this.drainWaiter = null;
      d();
    }

    const out = new Uint8Array(total);
    let off = 0;
    for (const p of parts) {
      out.set(p, off);
      off += p.byteLength;
    }
    const eofNow = this.eof && this.chunks.length === 0;
    const res = { sid, d: bytesToB64(out), eof: eofNow };
    if (eofNow) this._teardown();
    return res;
  }

  _teardown() {
    this.closed = true;
    try { this.writer && this.writer.releaseLock(); } catch (_) {}
    try { this.socket && this.socket.close(); } catch (_) {}
    this.socket = null;
    this.writer = null;
    this._wake();
    if (this.drainWaiter) {
      const d = this.drainWaiter;
      this.drainWaiter = null;
      d();
    }
  }
}
