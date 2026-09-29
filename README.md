# tunnel-node روی Cloudflare Workers (آزمایشی)

جایگزین tunnel-node (که روی Railway/VPS اجرا می‌شد) برای اپ mhrv-rs و Apps Script.

## ⚠️ قبل از شروع
- **روی Cloudflare واقعی و با اپ mhrv-rs واقعی تست نشده.** فقط منطق کد با سرور آزمایشی محلی تست شده.
- پروتکل از روی کد Apps Script (`CodeFull.gs`) حدس زده شده، نه از کد اصلی tunnel-node.
- **UDP پشتیبانی نمی‌شه** (Workers فقط TCP باز می‌کنه).
- **فشرده‌سازی (zops/zc) پشتیبانی نمی‌شه.**
- اتصال به سایت‌هایی که خودشون پشت Cloudflare هستن ممکنه رد بشه.
- پلن رایگان Cloudflare سقف درخواست روزانه و سقف subrequest داره؛ ترافیک تونل زود مصرفش می‌کنه.
- شرایط استفاده‌ی Cloudflare از Worker برای تونل رو چک نکردم. خودت بخون.
- سشن‌ها توی Durable Object نگه داشته می‌شن؛ اگه آبجکت بین دو poll از حافظه بره، اتصال قطع می‌شه.

## مراحل
1. این پوشه رو توی یه ریپوی **Private** گیت‌هاب بذار (فایل‌ها: `src/index.js`، `wrangler.jsonc`، `package.json`، `.gitignore`).
2. Cloudflare Dashboard ← Workers & Pages ← Create ← **Import a repository** ← ریپو رو انتخاب کن.
   Deploy command: `npx wrangler deploy` (Build command خالی).
3. بعد از دیپلوی: Worker ← Settings ← Variables and Secrets ← Add ← نوع **Secret**:
   - نام: `TUNNEL_AUTH_KEY`
   - مقدار: کلید رندوم (حروف و عدد، حداقل ۱۶ کاراکتر)
   حتماً از نوع Secret باشه، نه Text، وگرنه با دیپلوی بعدی پاک می‌شه.
4. آدرس Worker رو بردار (مثلاً `https://mhrv-tunnel.xxxx.workers.dev`).
5. توی Apps Script:
   ```js
   const AUTH_KEY = "همون کلید";
   const TUNNEL_SERVER_URL = "https://mhrv-tunnel.xxxx.workers.dev";
   const TUNNEL_AUTH_KEY = "همون کلید";
   ```
   بعد Deploy ← **New deployment**.
6. اپ: Deployment ID و کلید رو وارد کن، Mode = Full Tunnel (no cert).

## تنظیم سرعت
بالای `src/index.js` چند ثابت هست (`WRITE_WAIT_MS`، `POLL_WAIT_MS`، `COALESCE_MS`).
عدد کمتر = تأخیر کمتر ولی تعداد درخواست بیشتر.
