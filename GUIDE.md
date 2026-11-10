# V2Ray Panel — Cloudflare Workers + Pages
# پنل V2Ray — کلودفلر Workers و Pages

نسخهٔ 1.0.0 · یک فایل، بدون npm، بدون مرحلهٔ build · Version 1.0.0 · one file, no npm, no build step

---

## 0) فایل‌ها · Files

| فایل · File | کاربرد · Purpose |
|---|---|
| `workers/src/index.js` | Workers: کد اصلی · main code |
| `workers/wrangler.jsonc` | Workers: تنظیمات (name، KV خودکار) · config (name, automatic KV) |
| `workers/package.json` | Workers: فقط ابزار wrangler ^4.45.0 · wrangler tool only |
| `pages/_worker.js` | Pages: **دقیقاً همان کد** (SHA-256 یکسان) · **exactly the same code** (identical SHA-256) |

مسیرها · Routes: `/` صفحهٔ بی‌خطر · harmless page, `/panel` پنل · panel, `/sub/<token>` اشتراک · subscription (`?format=raw` یا `?format=xray`), مسیر WebSocket (پیش‌فرض `/ws`) · WebSocket path (default `/ws`) = نقطهٔ VLESS · the VLESS endpoint.

متغیرها · Variables: `ADMIN_PASSWORD` (الزامی، نوع Secret · required, type Secret) · `PROXY_IP` (اختیاری · optional) · `SESSION_SECRET` (اختیاری · optional). اتصال · Binding: `KV` (KV namespace).

---

## 1) معماری کوتاه · Brief architecture

**فارسی**
- یک ماژول Worker همه‌کاره است: پروکسی VLESS روی WebSocket، پنل مدیریت (رابط فارسی/انگلیسی)، و خروجی اشتراک.
- داده‌ها (تنظیمات، آی‌پی‌ها، کاربران) در یک کلید KV به نام `db` ذخیره می‌شود. اگر KV وصل نباشد یا خطا بدهد، برنامه از حافظه کار می‌کند و در پنل یادداشت «یک مرحلهٔ باقی‌مانده» نشان می‌دهد؛ هیچ‌وقت خطا نمی‌دهد.
- ورود با `ADMIN_PASSWORD` و کوکی نشست امضاشده (HMAC با Web Crypto، ۷ روز). اگر متغیر تنظیم نشده باشد، پیام واضح (فارسی/انگلیسی) نشان داده می‌شود.
- لینک‌های `vless://` فقط گزینه‌های سطح لینک را حمل می‌کنند. **DNS، فرگمنت و مسدودسازی فقط در «اشتراک Xray JSON» هستند** (لینک vless نمی‌تواند آن‌ها را حمل کند).
- هیچ محدودیت سرعت، پهنای باند، ترافیک یا تعداد اتصال در کد وجود ندارد. «تاریخ انقضا» و «سقف ترافیک» اختیاری‌اند و به‌طور پیش‌فرض خاموش.

**English**
- One Worker module does everything: VLESS-over-WebSocket proxy, the management panel (Persian/English UI) and the subscription output.
- Data (settings, IPs, users) lives in one KV key named `db`. If KV is missing or failing, the app runs from memory and shows a “one step left” notice in the panel; it never throws.
- Sign-in uses `ADMIN_PASSWORD` and a signed session cookie (HMAC via Web Crypto, 7 days). If the variable is not set, a clear bilingual message is shown.
- `vless://` links carry link-level options only. **DNS, fragment and blocking are in the “Xray JSON subscription” only** (a vless link cannot carry them).
- The code adds no speed, bandwidth, traffic or connection limit. “Expiry date” and “traffic limit” are optional and OFF by default.

---

## 2) راه‌اندازی Workers با GitHub (پیشنهادی) · Workers via GitHub (recommended)

**فارسی**
1. در GitHub یک مخزن (repository) بسازید، مثلاً `v2ray-panel`.
2. سه فایل را بسازید: **Add file ← Create new file**. در کادر نام، `src/index.js` را بنویسید (نوشتن `/` پوشه می‌سازد)، محتوای `workers/src/index.js` را Paste کنید و Commit بزنید. همین کار را برای `wrangler.jsonc` و `package.json` تکرار کنید.
3. در داشبورد Cloudflare: **Workers & Pages ← Create ← Import a repository** و همان مخزن را انتخاب کنید. دستور Build را خالی بگذارید و دستور Deploy همان `npx wrangler deploy` پیش‌فرض باشد.
4. **مهم:** مقدار `name` در `wrangler.jsonc` (پیش‌فرض `v2ray-panel`) باید با نام Worker در داشبورد **دقیقاً یکی** باشد، وگرنه Build شکست می‌خورد. یا نام را در فایل عوض کنید یا هنگام ساخت همین نام را بدهید.
5. بعد از اولین دیپلوی: **Settings ← Variables and Secrets ← Add**، نوع **Secret**، نام `ADMIN_PASSWORD`، یک رمز قوی بدهید و **Deploy** بزنید.
6. آدرس `https://<نام>.<حساب>.workers.dev/panel` را باز کنید و وارد شوید. KV به‌طور خودکار ساخته می‌شود (Wrangler نسخهٔ 4.45.0 به بالا، منابع بدون `id` را هنگام دیپلوی می‌سازد) و کارت «ذخیره‌سازی متصل است» دیده می‌شود.
7. در پنل: **آی‌پی تمیز** ← آی‌پی‌ها را اضافه کنید (یا خالی بگذارید) ← **خروجی** ← لینک اشتراک را در برنامهٔ کلاینت اضافه کنید.

**English**
1. Create a GitHub repository, e.g. `v2ray-panel`.
2. Create the three files: **Add file → Create new file**. Type `src/index.js` as the name (typing `/` creates the folder), paste the content of `workers/src/index.js`, commit. Repeat for `wrangler.jsonc` and `package.json`.
3. In the Cloudflare dashboard: **Workers & Pages → Create → Import a repository** and pick that repository. Leave the build command empty; the deploy command stays the default `npx wrangler deploy`.
4. **Important:** the `name` in `wrangler.jsonc` (default `v2ray-panel`) must be **exactly the same** as the Worker name in the dashboard, otherwise the build fails. Either change the name in the file or use this name when creating the Worker.
5. After the first deploy: **Settings → Variables and Secrets → Add**, type **Secret**, name `ADMIN_PASSWORD`, set a strong password and **Deploy**.
6. Open `https://<name>.<account>.workers.dev/panel` and sign in. KV is created automatically (Wrangler 4.45.0+ creates resources declared without an `id` on deploy) and the “Storage connected” card appears.
7. In the panel: **Clean IPs** → add IPs (or leave empty) → **Export** → add the subscription link in your client app.

---

## 3) Workers بدون GitHub (فقط داشبورد) · Workers without GitHub (dashboard only)

**فارسی**
1. **Workers & Pages ← Create ← Start with Hello World**، یک نام بدهید و Deploy کنید، سپس **Edit code**.
2. همهٔ کد را پاک کنید، محتوای `workers/src/index.js` را Paste کنید و **Deploy** بزنید.
3. **Settings ← Bindings ← Add ← KV namespace**، نام متغیر **`KV`** (دقیقاً با حروف بزرگ)، یک namespace انتخاب یا بسازید.
4. **Settings ← Variables and Secrets**: Secret با نام `ADMIN_PASSWORD`. سپس دوباره Deploy.

**English**
1. **Workers & Pages → Create → Start with Hello World**, pick a name, deploy, then **Edit code**.
2. Delete all code, paste the content of `workers/src/index.js`, and **Deploy**.
3. **Settings → Bindings → Add → KV namespace**, variable name **`KV`** (exactly uppercase), pick or create a namespace.
4. **Settings → Variables and Secrets**: a Secret named `ADMIN_PASSWORD`. Deploy again.

---

## 4) راه‌اندازی Pages · Cloudflare Pages

**فارسی**
1. یک مخزن **جداگانه** بسازید که فقط فایل `_worker.js` (از پوشهٔ `pages`) در ریشهٔ آن باشد. فایل `wrangler.jsonc` را در مخزن Pages نگذارید (مخصوص Workers است).
2. **Workers & Pages ← Create ← Pages ← Connect to Git**. Framework preset: `None`، Build command: خالی، پوشهٔ خروجی: همان پوشه‌ای که `_worker.js` در آن است. طبق مستندات، در حالت پیشرفته (advanced mode) فایل `_worker.js` باید در پوشهٔ خروجی build باشد و پروژه از طریق Git دیپلوی شود.
3. یک KV بسازید (بخش KV در داشبورد) و در **Settings ← Bindings** با نام متغیر **`KV`** به پروژه وصل کنید. در **Settings ← Variables and Secrets** متغیر `ADMIN_PASSWORD` را اضافه کنید.
4. پروژه را **دوباره دیپلوی کنید** (تغییر متغیر و Binding برای دیپلوی بعدی اعمال می‌شود). سپس `https://<پروژه>.pages.dev/panel`.

**English**
1. Create a **separate** repository containing only `_worker.js` (from the `pages` folder) at its root. Do not put `wrangler.jsonc` in the Pages repository (it is for Workers).
2. **Workers & Pages → Create → Pages → Connect to Git**. Framework preset `None`, build command empty, output directory = the folder that holds `_worker.js`. Per the docs, in advanced mode `_worker.js` must be in the build output directory and the project is deployed through Git integration.
3. Create a KV namespace (KV section of the dashboard) and bind it in **Settings → Bindings** with variable name **`KV`**. Add `ADMIN_PASSWORD` in **Settings → Variables and Secrets**.
4. **Redeploy the project** (variable and binding changes apply to the next deployment). Then open `https://<project>.pages.dev/panel`.

> برچسب‌های منو ممکن است کمی تفاوت داشته باشند · Menu labels may differ slightly from what is written here.

---

## 5) دامنهٔ اختصاصی، پورت‌ها و محدودیت‌های Cloudflare · Custom domain, ports and Cloudflare limits

**فارسی**
- Cloudflare پورت‌های TLS زیر را پراکسی می‌کند: 443، 2053، 2083، 2087، 2096، 8443 و پورت‌های بدون TLS: 80، 8080، 8880، 2052، 2082، 2086، 2095. این مستندات دربارهٔ دامنه‌های پراکسی‌شده است. برای `*.workers.dev` و `*.pages.dev` بیانیهٔ رسمی پیدا نکردم؛ هر پورت را جدا آزمایش کنید.
- مستندات می‌گویند زیردامنهٔ workers.dev برای پروژه‌های شخصی/سرگرمی است و برای کارهای جدی‌تر دامنهٔ اختصاصی پیشنهاد می‌شود. افزودن دامنه: Worker ← **Settings ← Domains & Routes ← Add ← Custom Domain**.
- محدودیت‌های رسمی پلن رایگان Workers: ۱۰۰٬۰۰۰ درخواست در روز، ۱۰ میلی‌ثانیه زمان CPU برای هر فراخوانی، ۵۰ زیردرخواست در هر درخواست؛ KV رایگان: ۱۰۰٬۰۰۰ خواندن و ۱٬۰۰۰ نوشتن در روز. این‌ها از طرف Cloudflare است و با کد برداشته نمی‌شود؛ پلن پولی آن‌ها را بالا می‌برد.
- **هشدار شرایط استفاده:** Cloudflare Self-Serve Subscription Agreement (بند 2.2.1(j)) استفاده از سرویس‌ها برای ارائهٔ VPN یا سرویس پروکسی مشابه را ممنوع کرده است. حساب یا ترافیک شما ممکن است محدود یا مسدود شود. مسئولیت استفاده با خود شماست.

**English**
- Cloudflare proxies these TLS ports: 443, 2053, 2083, 2087, 2096, 8443 and these non-TLS ports: 80, 8080, 8880, 2052, 2082, 2086, 2095. That documentation covers proxied zones. I found no official statement for `*.workers.dev` or `*.pages.dev`; test each port separately.
- The docs say the workers.dev subdomain is meant for personal/hobby projects and recommend a custom domain for anything more serious. Add one at Worker → **Settings → Domains & Routes → Add → Custom Domain**.
- Official Workers Free limits: 100,000 requests per day, 10 ms CPU time per invocation, 50 subrequests per request; KV Free: 100,000 reads and 1,000 writes per day. These come from Cloudflare, code cannot remove them; paid plans raise them.
- **Terms warning:** Cloudflare’s Self-Serve Subscription Agreement (section 2.2.1(j)) prohibits using the Services to provide a virtual private network or similar proxy services. Your account or traffic can be restricted or blocked. You use this at your own risk.

---

## 6) عیب‌یابی (فارسی)

| مشکل | علت و راه‌حل |
|---|---|
| **Error 1101** (Worker threw exception) | یعنی خطای مدیریت‌نشده در کد. این کد همهٔ مسیرها را در try/catch گرفته است؛ اگر باز دیدید، احتمالاً فایل ناقص یا ویرایش‌شده Paste شده یا نسخهٔ قدیمی فعال است. فایل را کامل جایگزین کنید (باید با `export default` تمام شود)، دوباره دیپلوی کنید و در بخش Logs/Observability همان Worker پیام خطا را ببینید. |
| **Error 1011** | طبق مستندات Cloudflare یعنی «Hotlinking Denied» و به محافظت Hotlink در تنظیمات دامنه (Scrape Shield) مربوط است، نه به کد Worker. اگر روی دامنهٔ اختصاصی خودتان می‌بینید، آن تنظیم را بررسی کنید. |
| **Error 1102** | از سقف منابع (CPU) عبور شده. در پلن رایگان سقف ۱۰ میلی‌ثانیه است؛ پلن پولی سقف را بالا می‌برد. |
| Build: `Expected 'name' to be of type string` | فایل `wrangler.jsonc` نام معتبر ندارد. فایل همین بسته را بدون تغییر ساختار بگذارید: `"name": "v2ray-panel"` (رشتهٔ غیرخالی). |
| Build شکست می‌خورد و از نام می‌گوید | `name` در `wrangler.jsonc` باید با نام Worker در داشبورد یکی باشد. |
| Build دربارهٔ `kv_namespaces` یا `id` خطا می‌دهد | نسخهٔ Wrangler قدیمی است. `package.json` نسخهٔ `^4.45.0` را نصب می‌کند؛ مطمئن شوید این فایل در مخزن هست. یا KV را دستی بسازید و `"id": "..."` را در `wrangler.jsonc` بنویسید. |
| پنل «یک مرحلهٔ باقی‌مانده: اتصال KV» نشان می‌دهد | اتصالی با نام دقیق `KV` وجود ندارد. Workers: Settings ← Bindings. Pages: Settings ← Bindings و سپس دیپلوی مجدد. |
| «رمز مدیر تنظیم نشده است» | Secret با نام `ADMIN_PASSWORD` اضافه کنید و (در Pages) دوباره دیپلوی کنید. |
| تغییرات بعد از مدتی از بین می‌رود | KV وصل نیست یا خطا می‌دهد؛ کارت صفحهٔ «خانه» را ببینید. |
| کلاینت وصل نمی‌شود | مسیر WebSocket در تنظیمات با کانفیگ یکی نیست؛ کاربر غیرفعال/منقضی/پرشده است؛ پورت روی workers.dev/pages.dev کار نمی‌کند (پورت 443 را امتحان کنید)؛ Host/SNI اشتباه است. |
| کانفیگ بدون TLS کار نمی‌کند | تنظیم‌های zone مثل Always Use HTTPS را بررسی کنید (تأییدنشده)، یا از پورت‌های TLS استفاده کنید. |
| سایت‌های پشت Cloudflare باز نمی‌شوند | طبق مستندات، Workers نمی‌تواند به آی‌پی‌های Cloudflare وصل شود؛ در بخش «پروکسی آی‌پی» یک مورد اضافه کنید (نتیجه تضمین‌شده نیست). |
| بعد از رسیدن به سقف روزانه خطا می‌آید | تا بازنشانی سقف صبر کنید یا پلن پولی بگیرید. |

## 6) Troubleshooting (English)

| Problem | Cause and fix |
|---|---|
| **Error 1101** (Worker threw exception) | An unhandled exception in the code. This build wraps every route in try/catch; if you still see it, an incomplete or edited file was pasted or an old version is live. Replace the file completely (it must end with `export default`), redeploy, and read the error in the Worker’s Logs/Observability. |
| **Error 1011** | Per Cloudflare docs it means “Hotlinking Denied” and comes from the zone’s Hotlink Protection (Scrape Shield) setting, not from the Worker code. If it appears on your own custom domain, review that setting. |
| **Error 1102** | A resource limit (CPU) was exceeded. The Free plan allows 10 ms; paid plans raise it. |
| Build: `Expected 'name' to be of type string` | `wrangler.jsonc` has no valid name. Use the file from this package unchanged in structure: `"name": "v2ray-panel"` (non-empty string). |
| Build fails and mentions the name | The `name` in `wrangler.jsonc` must equal the Worker name in the dashboard. |
| Build complains about `kv_namespaces` or `id` | Old Wrangler. `package.json` installs `^4.45.0`; make sure that file is in the repo. Or create KV manually and put `"id": "..."` in `wrangler.jsonc`. |
| Panel shows “One step left: connect KV storage” | No binding with the exact name `KV`. Workers: Settings → Bindings. Pages: Settings → Bindings, then redeploy. |
| “Admin password is not set” | Add a Secret named `ADMIN_PASSWORD` and (on Pages) redeploy. |
| Changes disappear after a while | KV is not bound or failing; check the card on the Home tab. |
| Client cannot connect | WebSocket path in Settings differs from the config; user disabled/expired/over limit; the port is not available on workers.dev/pages.dev (try 443); wrong Host/SNI. |
| Non-TLS config fails | Check zone settings such as Always Use HTTPS (not verified), or use TLS ports. |
| Sites hosted on Cloudflare do not open | Per the docs Workers cannot connect to Cloudflare IP ranges; add an entry under Proxy IPs (no guarantee). |
| Errors after reaching the daily limit | Wait for the limit to reset or move to a paid plan. |

---

## 7) آنچه نمی‌توانم تضمین کنم · What I cannot guarantee

**فارسی**
- من نتوانستم روی Cloudflare واقعی اجرا کنم. آزمایش‌ها: ۴۳ تست Node (مسیرها، ورود، KV و حالت حافظه، اعتبارسنجی، اشتراک، Xray JSON، رله TCP و DNS با سوکت شبیه‌سازی‌شده، پروکسی آی‌پی، محدودیت‌ها)، ۴۴ بررسی در مرورگر واقعی (کروم) به فارسی و انگلیسی، رمزگشایی QR با OpenCV، و بررسی نحو/متغیرهای تعریف‌نشده/بلااستفاده با TypeScript.
- تأییدنشده روی Cloudflare واقعی: رفتار `connect()` (از جمله آدرس‌های IPv6)، سقف CPU پلن رایگان برای اتصال‌های طولانی WebSocket، در دسترس بودن پورت‌های غیر 443 روی workers.dev/pages.dev، و فیلتر بودن آدرس‌های workers.dev/pages.dev در شبکهٔ شما.
- پذیرفته شدن «اشتراک Xray JSON» توسط هر کلاینت و بودن فهرست‌های geosite (`category-ads-all` و `category-porn`) در فایل geo کلاینت را برای همهٔ کلاینت‌ها بررسی نکرده‌ام. مسدودسازی بدافزار/فیشینگ فقط با DNS فیلترکننده انجام می‌شود.
- KV هم‌گامی نهایی دارد (تغییر ممکن است تا حدود یک دقیقه یا بیشتر در سایر مناطق دیده شود). سقف ترافیک تقریبی است و فقط برای کاربرانی که سقف دارند شمرده می‌شود.
- فقط VLESS روی WebSocket و TCP پشتیبانی می‌شود؛ Reality و UDP غیر از DNS پشتیبانی نمی‌شود. فرگمنت و پورت‌ها ابزار آزمایشی‌اند و اثر آن‌ها به شبکهٔ شما بستگی دارد.

**English**
- I could not run this on real Cloudflare. What was tested: 43 Node tests (routes, sign-in, KV and memory mode, validation, subscription, Xray JSON, TCP relay and DNS with a simulated socket, proxy IP, limits), 44 checks in a real browser (Chromium) in Persian and English, QR decoding with OpenCV, and a syntax / undefined / unused-variable check with TypeScript.
- Unverified on real Cloudflare: `connect()` behavior (including IPv6 addresses), the Free-plan CPU limit for long WebSocket sessions, availability of non-443 ports on workers.dev/pages.dev, and whether workers.dev/pages.dev addresses are filtered on your network.
- Not verified per client: that each client accepts the “Xray JSON subscription”, and that the client’s geo file contains the geosite lists (`category-ads-all`, `category-porn`). Malware/phishing blocking relies on the filtering DNS only.
- KV is eventually consistent (a change can take about a minute or more to appear in other locations). The traffic limit is approximate and is counted only for users that have a limit.
- Only VLESS over WebSocket and TCP is supported; Reality and UDP other than DNS are not. Fragment and port choices are experiments whose effect depends on your network.
