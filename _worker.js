/**
 * V2Ray (VLESS over WebSocket) panel for Cloudflare Workers and Cloudflare Pages (advanced mode _worker.js).
 *
 * - One ES module, no build step, no npm dependencies.
 * - The very same file is used as src/index.js (Workers) and as _worker.js (Pages).
 * - Binding:    KV               KV namespace (needed to persist data; the app still runs without it)
 * - Variables:  ADMIN_PASSWORD   required for the panel (store it as a Secret)
 *               PROXY_IP         optional, comma separated fallback addresses (ip, ip:port or domain)
 *               SESSION_SECRET   optional, extra secret mixed into the session signing key
 * - Routes:     /  harmless page,  /panel  panel,  /sub/<token>  subscription,  /api/*  panel API,
 *               and the WebSocket path from the panel settings (default /ws)  VLESS endpoint.
 * - No speed, bandwidth, traffic or connection limit is added by this code. Optional per-user expiry
 *   and traffic limit are OFF by default.
 */
import { connect } from 'cloudflare:sockets';

const VERSION = '1.0.0';
const DB_KEY = 'db';
const USAGE_KEY = 'usage';
const SESSION_TTL = 7 * 24 * 3600; // seconds
const CACHE_MS = 15000;
const MAX_ITEMS = { ips: 1000, proxyIps: 100, users: 200 };

const TLS_PORTS = [443, 2053, 2083, 2087, 2096, 8443];
const PLAIN_PORTS = [80, 8080, 8880, 2052, 2082, 2086, 2095];
const FINGERPRINTS = ['chrome', 'firefox', 'safari', 'ios', 'android', 'edge', 'randomized', 'random'];
const FRAG_PRESETS = {
  light: { packets: 'tlshello', length: '100-200', interval: '1-1' },
  medium: { packets: 'tlshello', length: '50-100', interval: '10-20' },
  strong: { packets: '1-3', length: '10-30', interval: '10-20' },
};
// Static addresses for well-known DoH hostnames, so the client never has to resolve them first.
const DOH_HOSTS = {
  'cloudflare-dns.com': ['1.1.1.1', '1.0.0.1'],
  'security.cloudflare-dns.com': ['1.1.1.2', '1.0.0.2'],
  'family.cloudflare-dns.com': ['1.1.1.3', '1.0.0.3'],
  'dns.adguard-dns.com': ['94.140.14.14', '94.140.15.15'],
  'family.adguard-dns.com': ['94.140.14.15', '94.140.15.16'],
  'dns.google': ['8.8.8.8', '8.8.4.4'],
  'dns.quad9.net': ['9.9.9.9', '149.112.112.112'],
};
const DEFAULT_DOH = 'https://1.1.1.1/dns-query';

/* ------------------------------------------------------------------------------------------------
 * Translations. One dictionary, two languages. Add a key to BOTH "fa" and "en".
 * ---------------------------------------------------------------------------------------------- */
const I18N = {
  en: {
    appName: 'V2Ray Panel',
    switchLang: 'فارسی',
    langToggle: 'Switch language',
    themeToggle: 'Toggle light/dark theme',
    loading: 'Loading…',
    login: 'Sign in',
    logout: 'Sign out',
    password: 'Password',
    loginTitle: 'Admin sign-in',
    loginHint: 'Enter the admin password you stored in the ADMIN_PASSWORD variable.',
    noPassTitle: 'Admin password is not set',
    noPassBody: 'Add a secret variable named ADMIN_PASSWORD to this deployment, redeploy, then reload this page.',
    noPassWorkers: 'Workers: Settings → Variables and Secrets → Add → type Secret → name ADMIN_PASSWORD → Deploy.',
    noPassPages: 'Pages: Settings → Variables and Secrets → Add → name ADMIN_PASSWORD → then redeploy the project.',
    rootTitle: 'Welcome',
    rootText: 'This is a personal web service. There is nothing to see here.',
    notFound: 'Not found',
    serverError: 'Something went wrong. Please try again later.',
    noscript: 'Please enable JavaScript to use the panel.',

    tabHome: 'Home',
    tabUsers: 'Users',
    tabIps: 'Clean IPs',
    tabProxy: 'Proxy IPs',
    tabSettings: 'Settings',
    tabExport: 'Export',
    tabHelp: 'Help',

    add: 'Add',
    edit: 'Edit',
    del: 'Delete',
    save: 'Save',
    apply: 'Apply',
    cancel: 'Cancel',
    close: 'Close',
    copy: 'Copy',
    copyAll: 'Copy all',
    copied: 'Copied',
    copyFailed: 'Copy failed',
    qr: 'QR',
    qrTitle: 'QR code',
    qrTooLong: 'The text is too long for a QR code.',
    enabled: 'Enabled',
    disabled: 'Disabled',
    remark: 'Remark',
    port: 'Port',
    address: 'Address',
    unlimited: 'Unlimited',
    randomize: 'Randomize',
    generate: 'Generate',
    saved: 'Saved',
    deleted: 'Deleted',
    confirmTitle: 'Confirm',
    confirmDelete: 'Delete this item?',
    confirmDeleteAll: 'Delete ALL items in this list?',

    kvOkTitle: 'Storage connected',
    kvOkBody: 'Your changes are saved in KV and survive restarts.',
    kvMissingTitle: 'One step left: connect KV storage',
    kvMissingBody: 'No KV namespace named KV is bound yet. The panel runs in temporary memory mode, so changes may be lost. Bind a KV namespace to finish the setup:',
    kvStepGit: 'GitHub / Workers Builds: wrangler.jsonc already declares the KV binding and Wrangler creates the namespace on deploy. Redeploy once.',
    kvStepWorkers: 'Workers (dashboard): Settings → Bindings → Add → KV namespace → variable name KV → pick or create a namespace → Deploy.',
    kvStepPages: 'Pages: Settings → Bindings → Add → KV namespace → variable name KV → pick a namespace → redeploy the project.',
    kvErrorTitle: 'KV error',
    kvErrorBody: 'KV is bound but reading or writing failed. Changes are kept in memory only. Check the binding name (KV) and the KV limits.',
    statUsers: 'Users',
    statIps: 'Clean IPs',
    statProxy: 'Proxy IPs',
    statLinks: 'Links per user',
    workerHost: 'Panel domain',
    version: 'Version',
    qsTitle: 'Quick start',
    qs1: '1. Open Clean IPs and add your IPs (or leave it empty to use the domain directly).',
    qs2: '2. Open Settings and review ports, DNS, fragment and blocking.',
    qs3: '3. Open Export and copy the subscription link into your client app.',

    usersTitle: 'Users',
    addUser: 'Add user',
    editUser: 'Edit user',
    userName: 'Name',
    uuid: 'UUID',
    expiryDate: 'Expiry date (UTC, optional)',
    limitGb: 'Traffic limit in GB (optional)',
    limitHint: 'Empty = unlimited',
    resetUsage: 'Reset used traffic',
    noUsers: 'No users yet.',
    badgeExpired: 'Expired',
    badgeDisabled: 'Disabled',
    badgeLimit: 'Limit reached',
    expires: 'Expires',
    traffic: 'Traffic',
    userNote: 'Expiry is enforced at connection start and while connections run. The traffic limit is approximate and is counted only when you set it (KV is eventually consistent and has limited writes).',
    userDeleteConfirm: 'Delete this user? Their links stop working.',

    ipsTitle: 'Clean IPs',
    addIp: 'Add IP',
    bulkAdd: 'Bulk add',
    bulkTitle: 'Add many IPs',
    bulkHint: 'One per line, or separated by spaces or commas. Formats: ip, ip:port, domain, ip#remark, [ipv6]:port',
    bulkResult: '{added} added, {skipped} skipped, {invalid} invalid',
    ipAddress: 'IP or domain',
    portOverride: 'Port override (optional)',
    noIps: 'No clean IPs yet. The panel domain is used directly.',
    deleteAll: 'Delete all',
    ipNote: 'Without a port override, every selected port is generated for the IP.',

    proxyTitle: 'Proxy IPs (fallback)',
    proxyMode: 'How proxy IPs are used',
    modeFallback: 'Fallback: only when the direct connection fails or returns nothing',
    modeAlways: 'Always: connect through a proxy IP first',
    modeOff: 'Off: never use proxy IPs',
    addProxy: 'Add proxy IP',
    noProxy: 'No proxy IPs yet.',
    proxyEnv: 'A PROXY_IP environment variable is set and is always included.',
    proxyNote: 'Cloudflare documents that Workers cannot open TCP connections to Cloudflare IP ranges, so sites hosted on Cloudflare usually need a proxy IP. Results are not guaranteed.',

    secConn: 'Connection',
    host: 'Host / SNI override (optional)',
    hostHint: 'Empty = use this panel domain',
    wsPath: 'WebSocket path',
    earlyData: 'Early data bytes (0 = off)',
    fingerprint: 'TLS fingerprint',
    remarkPrefix: 'Remark prefix',
    includeHost: 'Also add configs that use the panel domain directly',
    secPorts: 'Ports',
    tlsPorts: 'TLS ports',
    plainPorts: 'Non-TLS ports',
    portsHint: 'Every selected port is generated for every clean IP.',
    secDns: 'DNS',
    dnsRemote: 'Remote DNS (DoH URL or IPv4)',
    dnsDirect: 'Direct DNS (plain IPv4)',
    dnsEffective: 'DNS used in generated configs:',
    dnsHint: 'Used by the Xray JSON export. vless:// links cannot carry DNS settings.',
    secFrag: 'TLS fragment',
    fragEnabled: 'Enable fragment',
    fragPreset: 'Preset',
    presetLight: 'Light',
    presetMedium: 'Medium',
    presetStrong: 'Strong',
    presetCustom: 'Custom',
    fragPackets: 'Packets',
    fragLength: 'Length (bytes)',
    fragInterval: 'Interval (ms)',
    fragHint: 'TLS configs in the Xray JSON export only. Effectiveness depends on your network, and fragment can slow the handshake slightly.',
    secBlock: 'Content blocking',
    blockAds: 'Block ads and trackers',
    blockPorn: 'Block adult sites',
    blockSecurity: 'Block malware and phishing',
    blockDns: 'Use a filtering DNS provider while blocking is on (AdGuard / Cloudflare Families)',
    blockHint: 'Ads and adult sites are blocked by routing rules (geosite lists) and, if enabled above, by a filtering DNS provider. Malware and phishing rely on the filtering DNS only. AdGuard Family DNS also enables SafeSearch where possible. Applies to the Xray JSON export.',
    applySettings: 'Apply settings',

    expTitle: 'Export',
    expUser: 'User',
    subTitle: 'Subscription link (Base64)',
    subHint: 'Add this link as a subscription in your client app.',
    xrayTitle: 'Xray JSON subscription',
    xrayHint: 'Includes DNS, fragment and blocking rules. Works in clients that import Xray JSON subscriptions; otherwise use the Base64 link.',
    rawTitle: 'RAW links',
    rawHint: 'Plain vless:// links. Copy one, or all at once.',
    regen: 'Regenerate token',
    regenConfirm: 'The old subscription link will stop working. Continue?',
    regenDone: 'New token generated',
    linksCount: '{n} links',
    noLinks: 'No links. Select at least one port in Settings.',

    helpTitle: 'Help and platform notes',
    h1t: 'Domains and ports',
    h1: 'Cloudflare lists these ports as proxied: TLS 443, 2053, 2083, 2087, 2096, 8443 and non-TLS 80, 8080, 8880, 2052, 2082, 2086, 2095. That documentation is about proxied zones (custom domains). I found no official statement for *.workers.dev or *.pages.dev, so test each port. If non-TLS configs fail on a custom domain, check zone settings such as “Always Use HTTPS” (not verified).',
    h2t: 'Cloudflare limits',
    h2: 'Workers Free: 100,000 requests per day, 10 ms CPU time per invocation, 50 subrequests per request. KV Free: 100,000 reads and 1,000 writes per day. These limits come from Cloudflare and cannot be removed by code; paid plans raise them. Exceeding the CPU limit shows Error 1102.',
    h3t: 'What can be enforced',
    h3: 'Expiry date: enforced at every new connection and while a connection runs. Traffic limit: approximate (counted in memory, saved to KV about once a minute, not atomic across locations). Both are off by default.',
    h4t: 'Terms and account risk',
    h4: 'Cloudflare’s Self-Serve Subscription Agreement (section 2.2.1(j)) prohibits using the Services to provide a virtual private network or similar proxy services. Your account or traffic can be restricted. You use this software at your own risk.',
    h5t: 'Clients',
    h5: 'A Base64 subscription is the common format most v2ray clients accept. DNS, fragment and blocking are carried only by the Xray JSON export. This Worker relays TCP only; UDP DNS (port 53) is answered through DoH and other UDP traffic is not supported.',

    err_generic: 'Something went wrong.',
    err_network: 'Network error. Check your connection.',
    err_unauthorized: 'Please sign in again.',
    err_forbidden: 'Request blocked.',
    err_bad_json: 'Invalid request.',
    err_bad_response: 'Unexpected server response.',
    err_wrong_password: 'Wrong password.',
    err_too_many: 'Too many attempts. Try again later.',
    err_no_pass: 'Admin password is not set.',
    err_bad_uuid: 'Invalid UUID.',
    err_dup_uuid: 'This UUID already exists.',
    err_bad_date: 'Invalid date.',
    err_bad_limit: 'Invalid traffic limit.',
    err_bad_ip: 'Invalid IP or domain.',
    err_bad_port: 'Invalid port.',
    err_bad_path: 'Invalid path. Use letters, digits and / - _ . ~ and do not use /api, /sub or /panel.',
    err_bad_host: 'Invalid host name.',
    err_bad_dns: 'Invalid DNS value.',
    err_bad_frag: 'Invalid fragment values.',
    err_bad_value: 'Invalid value.',
    err_limit: 'The list is full.',
    err_not_found: 'Item not found.',
    err_kv_write: 'Saved in memory only: writing to KV failed.',
    err_no_bulk: 'Nothing to add.',
  },

  fa: {
    appName: 'پنل V2Ray',
    switchLang: 'English',
    langToggle: 'تغییر زبان',
    themeToggle: 'تغییر پوستهٔ روشن/تیره',
    loading: 'در حال بارگذاری…',
    login: 'ورود',
    logout: 'خروج',
    password: 'رمز عبور',
    loginTitle: 'ورود مدیر',
    loginHint: 'رمز مدیر را که در متغیر ADMIN_PASSWORD ذخیره کرده‌اید وارد کنید.',
    noPassTitle: 'رمز مدیر تنظیم نشده است',
    noPassBody: 'یک متغیر محرمانه با نام ADMIN_PASSWORD به این استقرار اضافه کنید، دوباره دیپلوی کنید و سپس این صفحه را بازآوری کنید.',
    noPassWorkers: 'ورکرز: وارد Settings شوید، سپس Variables and Secrets، گزینهٔ Add، نوع Secret، نام ADMIN_PASSWORD و در پایان Deploy.',
    noPassPages: 'پیجز: در Settings به بخش Variables and Secrets بروید، متغیر ADMIN_PASSWORD را اضافه کنید و پروژه را دوباره دیپلوی کنید.',
    rootTitle: 'خوش آمدید',
    rootText: 'این یک سرویس وب شخصی است. چیزی برای نمایش وجود ندارد.',
    notFound: 'پیدا نشد',
    serverError: 'مشکلی پیش آمد. لطفاً بعداً دوباره تلاش کنید.',
    noscript: 'برای استفاده از پنل، جاوااسکریپت را فعال کنید.',

    tabHome: 'خانه',
    tabUsers: 'کاربران',
    tabIps: 'آی‌پی تمیز',
    tabProxy: 'پروکسی آی‌پی',
    tabSettings: 'تنظیمات',
    tabExport: 'خروجی',
    tabHelp: 'راهنما',

    add: 'افزودن',
    edit: 'ویرایش',
    del: 'حذف',
    save: 'ذخیره',
    apply: 'اعمال',
    cancel: 'انصراف',
    close: 'بستن',
    copy: 'کپی',
    copyAll: 'کپی همه',
    copied: 'کپی شد',
    copyFailed: 'کپی ناموفق بود',
    qr: 'QR',
    qrTitle: 'کد QR',
    qrTooLong: 'متن برای کد QR بیش از حد طولانی است.',
    enabled: 'فعال',
    disabled: 'غیرفعال',
    remark: 'توضیح',
    port: 'پورت',
    address: 'آدرس',
    unlimited: 'نامحدود',
    randomize: 'تصادفی',
    generate: 'ساخت',
    saved: 'ذخیره شد',
    deleted: 'حذف شد',
    confirmTitle: 'تأیید',
    confirmDelete: 'این مورد حذف شود؟',
    confirmDeleteAll: 'همهٔ موارد این فهرست حذف شود؟',

    kvOkTitle: 'ذخیره‌سازی متصل است',
    kvOkBody: 'تغییرات شما در KV ذخیره می‌شود و با راه‌اندازی مجدد از بین نمی‌رود.',
    kvMissingTitle: 'یک مرحله باقی مانده: اتصال KV',
    kvMissingBody: 'هنوز هیچ KV Namespace با نام KV متصل نشده است. پنل در حالت حافظهٔ موقت کار می‌کند و ممکن است تغییرات از بین برود. برای تکمیل راه‌اندازی یک KV متصل کنید:',
    kvStepGit: 'گیت‌هاب / Workers Builds: فایل wrangler.jsonc اتصال KV را از قبل تعریف کرده و Wrangler هنگام دیپلوی آن را می‌سازد. یک بار دیگر دیپلوی کنید.',
    kvStepWorkers: 'ورکرز (داشبورد): در Settings بخش Bindings، گزینهٔ Add، نوع KV namespace، نام متغیر KV، انتخاب یا ساخت namespace و سپس Deploy.',
    kvStepPages: 'پیجز: در Settings بخش Bindings، گزینهٔ Add، نوع KV namespace، نام متغیر KV، انتخاب namespace و سپس دیپلوی مجدد پروژه.',
    kvErrorTitle: 'خطای KV',
    kvErrorBody: 'KV متصل است اما خواندن یا نوشتن ناموفق بود. تغییرات فقط در حافظه نگه داشته می‌شود. نام اتصال (KV) و محدودیت‌های KV را بررسی کنید.',
    statUsers: 'کاربران',
    statIps: 'آی‌پی‌های تمیز',
    statProxy: 'پروکسی آی‌پی‌ها',
    statLinks: 'لینک برای هر کاربر',
    workerHost: 'دامنهٔ پنل',
    version: 'نسخه',
    qsTitle: 'شروع سریع',
    qs1: '۱. به بخش آی‌پی تمیز بروید و آی‌پی‌های خود را اضافه کنید (یا خالی بگذارید تا مستقیماً از دامنه استفاده شود).',
    qs2: '۲. در تنظیمات، پورت‌ها، DNS، فرگمنت و مسدودسازی را بررسی کنید.',
    qs3: '۳. در بخش خروجی، لینک اشتراک را در برنامهٔ کلاینت خود کپی کنید.',

    usersTitle: 'کاربران',
    addUser: 'افزودن کاربر',
    editUser: 'ویرایش کاربر',
    userName: 'نام',
    uuid: 'UUID',
    expiryDate: 'تاریخ انقضا (UTC، اختیاری)',
    limitGb: 'سقف ترافیک به گیگابایت (اختیاری)',
    limitHint: 'خالی = نامحدود',
    resetUsage: 'صفر کردن ترافیک مصرف‌شده',
    noUsers: 'هنوز کاربری وجود ندارد.',
    badgeExpired: 'منقضی',
    badgeDisabled: 'غیرفعال',
    badgeLimit: 'سقف پر شد',
    expires: 'انقضا',
    traffic: 'ترافیک',
    userNote: 'انقضا هنگام شروع اتصال و در طول اتصال اعمال می‌شود. سقف ترافیک تقریبی است و فقط وقتی تنظیم شود شمارش می‌شود (KV هم‌گامی نهایی دارد و تعداد نوشتن آن محدود است).',
    userDeleteConfirm: 'این کاربر حذف شود؟ لینک‌های او از کار می‌افتد.',

    ipsTitle: 'آی‌پی‌های تمیز',
    addIp: 'افزودن آی‌پی',
    bulkAdd: 'افزودن گروهی',
    bulkTitle: 'افزودن چند آی‌پی',
    bulkHint: 'هر مورد در یک خط، یا جداشده با فاصله یا ویرگول. قالب‌ها: ip ، ip:port ، دامنه ، ip#توضیح ، [ipv6]:port',
    bulkResult: '{added} اضافه شد، {skipped} تکراری، {invalid} نامعتبر',
    ipAddress: 'آی‌پی یا دامنه',
    portOverride: 'پورت اختصاصی (اختیاری)',
    noIps: 'هنوز آی‌پی تمیزی وجود ندارد. مستقیماً از دامنهٔ پنل استفاده می‌شود.',
    deleteAll: 'حذف همه',
    ipNote: 'اگر پورت اختصاصی ندهید، همهٔ پورت‌های انتخاب‌شده برای این آی‌پی ساخته می‌شود.',

    proxyTitle: 'پروکسی آی‌پی (پشتیبان)',
    proxyMode: 'نحوهٔ استفاده از پروکسی آی‌پی',
    modeFallback: 'پشتیبان: فقط وقتی اتصال مستقیم شکست بخورد یا پاسخی نیاید',
    modeAlways: 'همیشه: اول از طریق پروکسی آی‌پی وصل شود',
    modeOff: 'خاموش: هرگز از پروکسی آی‌پی استفاده نشود',
    addProxy: 'افزودن پروکسی آی‌پی',
    noProxy: 'هنوز پروکسی آی‌پی‌ای وجود ندارد.',
    proxyEnv: 'متغیر محیطی PROXY_IP تنظیم شده و همیشه در فهرست است.',
    proxyNote: 'طبق مستندات Cloudflare، ورکرز نمی‌تواند به بازه‌های آی‌پی Cloudflare اتصال TCP بسازد؛ بنابراین برای سایت‌های پشت Cloudflare معمولاً پروکسی آی‌پی لازم است. نتیجه تضمین‌شده نیست.',

    secConn: 'اتصال',
    host: 'جایگزین Host / SNI (اختیاری)',
    hostHint: 'خالی = دامنهٔ همین پنل',
    wsPath: 'مسیر WebSocket',
    earlyData: 'بایت Early Data (۰ = خاموش)',
    fingerprint: 'اثر انگشت TLS',
    remarkPrefix: 'پیشوند نام کانفیگ',
    includeHost: 'کانفیگ‌هایی که مستقیماً از دامنهٔ پنل استفاده می‌کنند هم ساخته شود',
    secPorts: 'پورت‌ها',
    tlsPorts: 'پورت‌های TLS',
    plainPorts: 'پورت‌های بدون TLS',
    portsHint: 'هر پورت انتخاب‌شده برای هر آی‌پی تمیز ساخته می‌شود.',
    secDns: 'DNS',
    dnsRemote: 'DNS ریموت (آدرس DoH یا IPv4)',
    dnsDirect: 'DNS مستقیم (IPv4 ساده)',
    dnsEffective: 'DNS مورد استفاده در کانفیگ‌ها:',
    dnsHint: 'در خروجی Xray JSON استفاده می‌شود. لینک‌های vless:// نمی‌توانند تنظیمات DNS را حمل کنند.',
    secFrag: 'فرگمنت TLS',
    fragEnabled: 'فعال‌سازی فرگمنت',
    fragPreset: 'پیش‌تنظیم',
    presetLight: 'سبک',
    presetMedium: 'متوسط',
    presetStrong: 'قوی',
    presetCustom: 'سفارشی',
    fragPackets: 'بسته‌ها (Packets)',
    fragLength: 'طول (بایت)',
    fragInterval: 'فاصله (میلی‌ثانیه)',
    fragHint: 'فقط برای کانفیگ‌های TLS در خروجی Xray JSON. اثربخشی به شبکهٔ شما بستگی دارد و فرگمنت می‌تواند سرعت هندشیک را کمی کم کند.',
    secBlock: 'مسدودسازی محتوا',
    blockAds: 'مسدودسازی تبلیغات و ردیاب‌ها',
    blockPorn: 'مسدودسازی سایت‌های بزرگسال',
    blockSecurity: 'مسدودسازی بدافزار و فیشینگ',
    blockDns: 'تا وقتی مسدودسازی روشن است از DNS فیلترکننده (AdGuard / Cloudflare Families) استفاده شود',
    blockHint: 'تبلیغات و سایت‌های بزرگسال با قوانین مسیریابی (فهرست‌های geosite) و در صورت فعال بودن گزینهٔ بالا با DNS فیلترکننده مسدود می‌شوند. بدافزار و فیشینگ فقط به DNS فیلترکننده متکی است. DNS فامیلی AdGuard در حد امکان SafeSearch را هم فعال می‌کند. در خروجی Xray JSON اعمال می‌شود.',
    applySettings: 'اعمال تنظیمات',

    expTitle: 'خروجی',
    expUser: 'کاربر',
    subTitle: 'لینک اشتراک (Base64)',
    subHint: 'این لینک را در برنامهٔ کلاینت به‌عنوان اشتراک اضافه کنید.',
    xrayTitle: 'اشتراک Xray JSON',
    xrayHint: 'شامل DNS، فرگمنت و قوانین مسدودسازی است. در کلاینت‌هایی کار می‌کند که اشتراک Xray JSON را می‌پذیرند؛ در غیر این صورت از لینک Base64 استفاده کنید.',
    rawTitle: 'لینک‌های RAW',
    rawHint: 'لینک‌های ساده vless://. یکی را یا همه را یک‌جا کپی کنید.',
    regen: 'ساخت دوبارهٔ توکن',
    regenConfirm: 'لینک اشتراک قبلی از کار می‌افتد. ادامه می‌دهید؟',
    regenDone: 'توکن جدید ساخته شد',
    linksCount: '{n} لینک',
    noLinks: 'لینکی وجود ندارد. در تنظیمات حداقل یک پورت انتخاب کنید.',

    helpTitle: 'راهنما و نکات پلتفرم',
    h1t: 'دامنه‌ها و پورت‌ها',
    h1: 'Cloudflare این پورت‌ها را پراکسی می‌کند: TLS شامل 443، 2053، 2083، 2087، 2096، 8443 و بدون TLS شامل 80، 8080، 8880، 2052، 2082، 2086، 2095. این مستندات دربارهٔ دامنه‌های پراکسی‌شده (دامنهٔ اختصاصی) است. برای *.workers.dev و *.pages.dev بیانیهٔ رسمی پیدا نکردم؛ پس هر پورت را آزمایش کنید. اگر روی دامنهٔ اختصاصی کانفیگ بدون TLS کار نکرد، تنظیمات zone مثل Always Use HTTPS را بررسی کنید (تأییدنشده).',
    h2t: 'محدودیت‌های Cloudflare',
    h2: 'ورکرز رایگان: ۱۰۰٬۰۰۰ درخواست در روز، ۱۰ میلی‌ثانیه زمان CPU برای هر فراخوانی، ۵۰ زیردرخواست برای هر درخواست. KV رایگان: ۱۰۰٬۰۰۰ خواندن و ۱٬۰۰۰ نوشتن در روز. این محدودیت‌ها از طرف Cloudflare است و با کد حذف نمی‌شود؛ پلن پولی آن‌ها را بالا می‌برد. عبور از سقف CPU خطای 1102 نشان می‌دهد.',
    h3t: 'چه چیزی قابل اعمال است',
    h3: 'تاریخ انقضا: در هر اتصال جدید و در طول اتصال اعمال می‌شود. سقف ترافیک: تقریبی (در حافظه شمرده می‌شود، حدوداً هر دقیقه در KV ذخیره می‌شود و بین مناطق مختلف اتمی نیست). هر دو به‌طور پیش‌فرض خاموش‌اند.',
    h4t: 'شرایط استفاده و ریسک حساب',
    h4: 'قرارداد Self-Serve Subscription Agreement شرکت Cloudflare (بند 2.2.1(j)) استفاده از سرویس‌ها برای ارائهٔ VPN یا سرویس‌های پروکسی مشابه را ممنوع کرده است. ممکن است حساب یا ترافیک شما محدود شود. استفاده از این نرم‌افزار با مسئولیت خودتان است.',
    h5t: 'کلاینت‌ها',
    h5: 'اشتراک Base64 قالب رایجی است که بیشتر کلاینت‌های v2ray می‌پذیرند. DNS، فرگمنت و مسدودسازی فقط در خروجی Xray JSON وجود دارد. این ورکر فقط TCP را رله می‌کند؛ DNS روی UDP (پورت 53) از طریق DoH پاسخ داده می‌شود و سایر ترافیک UDP پشتیبانی نمی‌شود.',

    err_generic: 'مشکلی پیش آمد.',
    err_network: 'خطای شبکه. اتصال خود را بررسی کنید.',
    err_unauthorized: 'لطفاً دوباره وارد شوید.',
    err_forbidden: 'درخواست مسدود شد.',
    err_bad_json: 'درخواست نامعتبر است.',
    err_bad_response: 'پاسخ نامنتظرهٔ سرور.',
    err_wrong_password: 'رمز عبور اشتباه است.',
    err_too_many: 'تلاش‌های زیاد. بعداً دوباره امتحان کنید.',
    err_no_pass: 'رمز مدیر تنظیم نشده است.',
    err_bad_uuid: 'UUID نامعتبر است.',
    err_dup_uuid: 'این UUID قبلاً وجود دارد.',
    err_bad_date: 'تاریخ نامعتبر است.',
    err_bad_limit: 'سقف ترافیک نامعتبر است.',
    err_bad_ip: 'آی‌پی یا دامنه نامعتبر است.',
    err_bad_port: 'پورت نامعتبر است.',
    err_bad_path: 'مسیر نامعتبر است. از حروف، ارقام و / - _ . ~ استفاده کنید و از /api، /sub و /panel استفاده نکنید.',
    err_bad_host: 'نام میزبان نامعتبر است.',
    err_bad_dns: 'مقدار DNS نامعتبر است.',
    err_bad_frag: 'مقادیر فرگمنت نامعتبر است.',
    err_bad_value: 'مقدار نامعتبر است.',
    err_limit: 'فهرست پر است.',
    err_not_found: 'مورد پیدا نشد.',
    err_kv_write: 'فقط در حافظه ذخیره شد: نوشتن در KV ناموفق بود.',
    err_no_bulk: 'چیزی برای افزودن نیست.',
  },
};

/* ------------------------------------------------------------------------------------------------
 * Core helpers
 * ---------------------------------------------------------------------------------------------- */
const enc = new TextEncoder();
const dec = new TextDecoder();

function jsonResponse(obj, status, extra) {
  return new Response(JSON.stringify(obj), {
    status: status || 200,
    headers: Object.assign({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }, extra || {}),
  });
}

function htmlResponse(html, status, extra) {
  return new Response(html, {
    status: status || 200,
    headers: Object.assign(
      {
        'content-type': 'text/html; charset=utf-8',
        'cache-control': 'no-store',
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
        'x-robots-tag': 'noindex, nofollow',
      },
      extra || {}
    ),
  });
}

function textResponse(text, status, extra) {
  return new Response(text, {
    status: status || 200,
    headers: Object.assign({ 'content-type': 'text/plain; charset=utf-8', 'cache-control': 'no-store' }, extra || {}),
  });
}

const esc = (s) =>
  String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function tr(lang, key) {
  const d = I18N[lang] || I18N.en;
  if (d[key] !== undefined) return d[key];
  return I18N.en[key] !== undefined ? I18N.en[key] : key;
}

// JSON that is safe to embed inside a <script> element.
function safeJson(obj) {
  return JSON.stringify(obj).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');
}

function rndBytes(n) {
  const a = new Uint8Array(n);
  crypto.getRandomValues(a);
  return a;
}

function hex(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}

function b64(bytes) {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}

function b64url(bytes) {
  return b64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function unb64url(str) {
  let s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function concat(a, b) {
  const o = new Uint8Array(a.length + b.length);
  o.set(a, 0);
  o.set(b, a.length);
  return o;
}

const newId = () => hex(rndBytes(4));
const newToken = () => b64url(rndBytes(24));
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

/* ------------------------------ cookies and language ------------------------------ */
function getCookie(request, name) {
  const raw = request.headers.get('cookie') || '';
  const parts = raw.split(';');
  for (const part of parts) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    if (part.slice(0, i).trim() === name) {
      try {
        return decodeURIComponent(part.slice(i + 1).trim());
      } catch {
        return '';
      }
    }
  }
  return '';
}

function cookieStr(request, name, value, maxAge, httpOnly) {
  const https = new URL(request.url).protocol === 'https:';
  return (
    name + '=' + encodeURIComponent(value) + '; Path=/; SameSite=Lax; Max-Age=' + maxAge +
    (httpOnly ? '; HttpOnly' : '') + (https ? '; Secure' : '')
  );
}

// Language order: ?lang= query, "lang" cookie, Accept-Language (Persian if it is the preferred of fa/en), else English.
function pickLang(request, url) {
  const q = url ? url.searchParams.get('lang') : null;
  if (q === 'fa' || q === 'en') return q;
  const c = getCookie(request, 'lang');
  if (c === 'fa' || c === 'en') return c;
  const tags = String(request.headers.get('accept-language') || '')
    .split(',')
    .map((part, i) => {
      const bits = part.trim().split(';');
      const code = (bits[0] || '').toLowerCase().split('-')[0];
      const m = (bits[1] || '').match(/q=([0-9.]+)/);
      const w = m ? parseFloat(m[1]) : 1;
      return { code, w: Number.isFinite(w) ? w : 0, i };
    })
    .filter((x) => x.code === 'fa' || x.code === 'en');
  tags.sort((a, b) => b.w - a.w || a.i - b.i);
  return tags.length && tags[0].code === 'fa' ? 'fa' : 'en';
}

function pickTheme(request) {
  const t = getCookie(request, 'theme');
  return t === 'dark' || t === 'light' ? t : '';
}

/* ------------------------------ admin session (HMAC, Web Crypto) ------------------------------ */
async function hmacKey(env) {
  const secret = 'v2panel|' + String(env.ADMIN_PASSWORD || '') + '|' + String(env.SESSION_SECRET || '');
  return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']);
}

async function signSession(env, exp) {
  const payload = 'v1.' + exp;
  const sig = await crypto.subtle.sign('HMAC', await hmacKey(env), enc.encode(payload));
  return payload + '.' + b64url(new Uint8Array(sig));
}

async function checkSession(env, value) {
  const p = String(value || '').split('.');
  if (p.length !== 3 || p[0] !== 'v1') return false;
  const exp = Number(p[1]);
  if (!Number.isFinite(exp) || exp * 1000 < Date.now()) return false;
  try {
    return await crypto.subtle.verify('HMAC', await hmacKey(env), unb64url(p[2]), enc.encode(p[0] + '.' + p[1]));
  } catch {
    return false;
  }
}

async function isAuthed(request, env) {
  if (!env.ADMIN_PASSWORD) return false;
  return checkSession(env, getCookie(request, 'sid'));
}

// Constant-time comparison of SHA-256 digests.
async function passwordOk(env, given) {
  const a = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(String(given == null ? '' : given))));
  const b = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(String(env.ADMIN_PASSWORD))));
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// Simple in-memory brute-force guard for the login endpoint (per isolate).
const LOGIN_FAILS = new Map();
function loginAllowed(ip) {
  const r = LOGIN_FAILS.get(ip);
  if (!r) return true;
  if (r.until < Date.now()) {
    LOGIN_FAILS.delete(ip);
    return true;
  }
  return r.n < 8;
}
function loginFailed(ip) {
  const r = LOGIN_FAILS.get(ip) || { n: 0, until: 0 };
  r.n += 1;
  r.until = Date.now() + 10 * 60 * 1000;
  LOGIN_FAILS.set(ip, r);
  if (LOGIN_FAILS.size > 500) LOGIN_FAILS.clear();
}

/* ------------------------------------------------------------------------------------------------
 * Validation, defaults and normalization (everything coming from the panel or from KV passes here)
 * ---------------------------------------------------------------------------------------------- */
class VErr extends Error {
  constructor(code) {
    super(code);
    this.code = code;
  }
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const HOST_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/i;
const V4_RE = /^(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)$/;
const V6_RE = /^[0-9a-f:.]{2,45}$/i;

const clean = (v, n) =>
  String(v == null ? '' : v).replace(/[\u0000-\u001f\u007f<>]/g, '').trim().slice(0, n);
const cleanId = (v) => String(v == null ? '' : v).replace(/[^\w-]/g, '').slice(0, 16);
const isV4 = (a) => V4_RE.test(a);
const isV6 = (a) => V6_RE.test(a) && (a.match(/:/g) || []).length >= 2;
const isIp = (a) => isV4(a) || isV6(a);
const validAddr = (a) => isIp(a) || HOST_RE.test(a);

// "1.2.3.4", "1.2.3.4:2053", "example.com#remark", "[2606:4700::1]:443#remark" -> { address, port, remark } or null.
function parseEntry(raw) {
  let s = String(raw == null ? '' : raw).trim();
  if (!s) return null;
  let remark = '';
  const hash = s.indexOf('#');
  if (hash >= 0) {
    remark = clean(s.slice(hash + 1), 40);
    s = s.slice(0, hash).trim();
  }
  let address = s;
  let port = 0;
  const m6 = s.match(/^\[([0-9a-fA-F:.]+)\](?::(\d{1,5}))?$/);
  const m4 = s.match(/^([^:\s]+):(\d{1,5})$/);
  if (m6) {
    address = m6[1];
    port = m6[2] ? Number(m6[2]) : 0;
  } else if (m4) {
    address = m4[1];
    port = Number(m4[2]);
  }
  address = address.toLowerCase();
  if (!validAddr(address)) return null;
  if (port && (port < 1 || port > 65535)) return null;
  return { address, port, remark };
}

function defaults() {
  return {
    v: 1,
    settings: {
      host: '',
      wsPath: '/ws',
      earlyData: 2560,
      fingerprint: 'chrome',
      remarkPrefix: 'V2',
      includeHost: true,
      tlsPorts: TLS_PORTS.slice(),
      plainPorts: PLAIN_PORTS.slice(),
      proxyMode: 'fallback',
      dns: { remote: DEFAULT_DOH, direct: '1.1.1.1' },
      fragment: { enabled: true, preset: 'light', packets: 'tlshello', length: '100-200', interval: '1-1' },
      block: { ads: true, porn: true, security: false, useDns: false },
    },
    ips: [],
    proxyIps: [],
    users: [],
  };
}

const okPackets = (v) => {
  if (v === 'tlshello') return true;
  if (!/^\d{1,3}(-\d{1,3})?$/.test(v)) return false;
  return Number(v.split('-')[0]) >= 1;
};
const okRange = (v, min) => /^\d{1,4}(-\d{1,4})?$/.test(v) && v.split('-').every((x) => Number(x) >= min);

// strict = true: throw VErr on the first invalid field (panel API). strict = false: ignore invalid fields (stored data).
function cleanSettings(inp, base, strict) {
  const o = JSON.parse(JSON.stringify(base));
  const src = inp && typeof inp === 'object' ? inp : {};
  const fail = (code) => {
    if (strict) throw new VErr(code);
  };
  const has = (k) => Object.prototype.hasOwnProperty.call(src, k);

  if (has('host')) {
    const v = clean(src.host, 253).toLowerCase();
    if (v === '' || HOST_RE.test(v)) o.host = v;
    else fail('bad_host');
  }
  if (has('wsPath')) {
    const v = clean(src.wsPath, 80);
    if (/^\/[A-Za-z0-9_\-.\/~]{0,70}$/.test(v) && !/^\/(api|sub|panel)(\/|$)/.test(v)) o.wsPath = v;
    else fail('bad_path');
  }
  if (has('earlyData')) {
    const n = Number(src.earlyData);
    if (Number.isInteger(n) && n >= 0 && n <= 8192) o.earlyData = n;
    else fail('bad_value');
  }
  if (has('fingerprint')) {
    if (FINGERPRINTS.includes(src.fingerprint)) o.fingerprint = src.fingerprint;
    else fail('bad_value');
  }
  if (has('remarkPrefix')) o.remarkPrefix = clean(src.remarkPrefix, 24);
  if (has('includeHost')) o.includeHost = !!src.includeHost;

  const ports = (key, allowed) => {
    if (!has(key)) return;
    if (!Array.isArray(src[key])) {
      fail('bad_value');
      return;
    }
    const wanted = src[key].map(Number);
    o[key] = allowed.filter((p) => wanted.includes(p));
  };
  ports('tlsPorts', TLS_PORTS);
  ports('plainPorts', PLAIN_PORTS);

  if (has('proxyMode')) {
    if (['fallback', 'always', 'off'].includes(src.proxyMode)) o.proxyMode = src.proxyMode;
    else fail('bad_value');
  }

  if (src.dns && typeof src.dns === 'object') {
    if ('remote' in src.dns) {
      const v = clean(src.dns.remote, 200);
      if (v === '') o.dns.remote = DEFAULT_DOH;
      else if (/^https:\/\/[A-Za-z0-9.\-:\[\]]+(?:\/[A-Za-z0-9._~\-\/]*)?$/.test(v) || isV4(v)) o.dns.remote = v;
      else fail('bad_dns');
    }
    if ('direct' in src.dns) {
      const v = clean(src.dns.direct, 45);
      if (v === '') o.dns.direct = '1.1.1.1';
      else if (isV4(v)) o.dns.direct = v;
      else fail('bad_dns');
    }
  }

  if (src.fragment && typeof src.fragment === 'object') {
    const f = src.fragment;
    const fr = o.fragment;
    if ('enabled' in f) fr.enabled = !!f.enabled;
    if ('preset' in f) {
      if (Object.prototype.hasOwnProperty.call(FRAG_PRESETS, f.preset)) {
        fr.preset = f.preset;
        Object.assign(fr, FRAG_PRESETS[f.preset]);
      } else if (f.preset === 'custom') {
        fr.preset = 'custom';
      } else {
        fail('bad_frag');
      }
    }
    if (fr.preset === 'custom') {
      const pk = clean(f.packets === undefined ? fr.packets : f.packets, 12);
      const ln = clean(f.length === undefined ? fr.length : f.length, 12);
      const iv = clean(f.interval === undefined ? fr.interval : f.interval, 12);
      if (okPackets(pk) && okRange(ln, 1) && okRange(iv, 0)) {
        fr.packets = pk;
        fr.length = ln;
        fr.interval = iv;
      } else {
        fail('bad_frag');
      }
    }
  }

  if (src.block && typeof src.block === 'object') {
    for (const k of ['ads', 'porn', 'security', 'useDns']) if (k in src.block) o.block[k] = !!src.block[k];
  }
  return o;
}

// Clean IP / proxy IP item coming from the panel (throws VErr).
function cleanAddrItem(body) {
  const address = clean(body.address, 253).toLowerCase().replace(/^\[|\]$/g, '');
  if (!validAddr(address)) throw new VErr('bad_ip');
  let port = 0;
  if (body.port !== undefined && body.port !== null && String(body.port).trim() !== '') {
    port = Number(body.port);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new VErr('bad_port');
  }
  return { address, port, remark: clean(body.remark, 40), enabled: body.enabled !== false };
}

// User input from the panel (throws VErr). "self" is the existing user when editing.
function cleanUserInput(body, users, self) {
  const name = clean(body.name, 40);
  let uuid = clean(body.uuid, 40).toLowerCase();
  if (uuid === '') uuid = crypto.randomUUID();
  if (!UUID_RE.test(uuid)) throw new VErr('bad_uuid');
  if (users.some((u) => u.uuid === uuid && (!self || u.id !== self.id))) throw new VErr('dup_uuid');
  const expiry = clean(body.expiry, 10);
  if (expiry !== '') {
    const t = Date.parse(expiry + 'T00:00:00Z');
    if (!/^\d{4}-\d{2}-\d{2}$/.test(expiry) || !Number.isFinite(t) || new Date(t).toISOString().slice(0, 10) !== expiry) {
      throw new VErr('bad_date');
    }
  }
  let limitBytes = 0;
  const g = String(body.limitGb === undefined || body.limitGb === null ? '' : body.limitGb).trim();
  if (g !== '') {
    const n = Number(g);
    if (!Number.isFinite(n) || n < 0 || n > 100000) throw new VErr('bad_limit');
    limitBytes = Math.round(n * 1073741824);
  }
  return { name, uuid, expiry, limitBytes, enabled: body.enabled !== false };
}

function storedAddr(x) {
  if (!x || typeof x !== 'object') return null;
  try {
    const a = cleanAddrItem(x);
    return Object.assign({ id: cleanId(x.id) || newId() }, a);
  } catch {
    return null;
  }
}

function storedUser(u) {
  if (!u || typeof u !== 'object') return null;
  const uuid = String(u.uuid || '').toLowerCase();
  if (!UUID_RE.test(uuid)) return null;
  return {
    id: cleanId(u.id) || newId(),
    name: clean(u.name, 40),
    uuid,
    token: /^[A-Za-z0-9_-]{16,64}$/.test(String(u.token || '')) ? u.token : newToken(),
    enabled: u.enabled !== false,
    expiry: /^\d{4}-\d{2}-\d{2}$/.test(String(u.expiry || '')) ? u.expiry : '',
    limitBytes: Number.isFinite(u.limitBytes) && u.limitBytes > 0 ? Math.floor(u.limitBytes) : 0,
  };
}

// Turn whatever is in KV (or null) into a complete, valid database object.
function normalize(raw) {
  const d = defaults();
  const r = raw && typeof raw === 'object' ? raw : {};
  d.settings = cleanSettings(r.settings, d.settings, false);
  d.users = (Array.isArray(r.users) ? r.users : []).slice(0, MAX_ITEMS.users).map(storedUser).filter(Boolean);
  d.ips = (Array.isArray(r.ips) ? r.ips : []).slice(0, MAX_ITEMS.ips).map(storedAddr).filter(Boolean);
  d.proxyIps = (Array.isArray(r.proxyIps) ? r.proxyIps : []).slice(0, MAX_ITEMS.proxyIps).map(storedAddr).filter(Boolean);
  return d;
}

function newUser(input) {
  return Object.assign({ id: newId(), token: newToken() }, input);
}

function userStatus(u, used) {
  if (!u.enabled) return 'disabled';
  if (u.expiry && Date.now() > Date.parse(u.expiry + 'T23:59:59Z')) return 'expired';
  if (u.limitBytes > 0 && used >= u.limitBytes) return 'limit';
  return 'ok';
}

/* ------------------------------------------------------------------------------------------------
 * Storage: one KV key ("db") holds settings, IPs, proxy IPs and users. If the KV binding is missing or fails,
 * everything keeps working from memory (nothing throws, the panel shows a setup notice).
 * KV is eventually consistent: a change is visible at once in the location that made it, other
 * locations can take 60 seconds or more.
 * ---------------------------------------------------------------------------------------------- */
let MEM = null;
let CACHE = { at: 0, db: null };
let KV_STATE = 'ok';
const USAGE = { at: 0, map: {}, lastPut: 0 };

const hasKV = (env) => !!(env && env.KV && typeof env.KV.get === 'function' && typeof env.KV.put === 'function');
const kvStatus = (env) => (hasKV(env) ? KV_STATE : 'missing');

// Deterministic fallback user used only when KV is not working, so the proxy keeps a stable UUID across isolates.
async function defaultUser(env) {
  const seed = 'v2panel-default-user|' + String(env.ADMIN_PASSWORD || '') + '|' + String(env.SESSION_SECRET || '');
  const h = new Uint8Array(await crypto.subtle.digest('SHA-256', enc.encode(seed)));
  const u = h.slice(0, 16);
  u[6] = (u[6] & 0x0f) | 0x40;
  u[8] = (u[8] & 0x3f) | 0x80;
  const x = hex(u);
  return {
    id: 'default',
    name: 'default',
    uuid: x.slice(0, 8) + '-' + x.slice(8, 12) + '-' + x.slice(12, 16) + '-' + x.slice(16, 20) + '-' + x.slice(20),
    token: b64url(h.slice(16, 28)),
    enabled: true,
    expiry: '',
    limitBytes: 0,
  };
}

async function loadDB(env) {
  if (CACHE.db && Date.now() - CACHE.at < CACHE_MS) return CACHE.db;
  let db = null;
  if (hasKV(env)) {
    try {
      db = normalize(await env.KV.get(DB_KEY, 'json'));
      KV_STATE = 'ok';
    } catch {
      KV_STATE = 'error';
      db = null;
    }
  }
  if (!db) db = MEM || normalize(null);
  // Without a working KV the account cannot be saved, so keep one stable user. Never done without a password.
  if (kvStatus(env) !== 'ok' && !db.users.length && env.ADMIN_PASSWORD) db.users.push(await defaultUser(env));
  MEM = db;
  CACHE = { at: Date.now(), db };
  return db;
}

// Returns 'ok' | 'missing' | 'error' (the data is always kept in memory as well).
async function saveDB(env, db) {
  MEM = db;
  CACHE = { at: Date.now(), db };
  if (!hasKV(env)) return 'missing';
  try {
    await env.KV.put(DB_KEY, JSON.stringify(db));
    KV_STATE = 'ok';
  } catch {
    KV_STATE = 'error';
  }
  return KV_STATE;
}

/* ------------------------------ optional traffic accounting ------------------------------
 * Only users that have a traffic limit are counted. The counters live in memory and are written to KV
 * at most once a minute, so the value is approximate (not atomic across locations or isolates). */
async function loadUsage(env) {
  if (Date.now() - USAGE.at < 20000) return USAGE.map;
  if (hasKV(env)) {
    try {
      const m = await env.KV.get(USAGE_KEY, 'json');
      if (m && typeof m === 'object') {
        for (const k of Object.keys(m)) USAGE.map[k] = Math.max(Number(m[k]) || 0, Number(USAGE.map[k]) || 0);
      }
    } catch {
      /* ignore: keep the in-memory numbers */
    }
  }
  USAGE.at = Date.now();
  return USAGE.map;
}

async function flushUsage(env) {
  USAGE.lastPut = Date.now();
  if (!hasKV(env)) return;
  try {
    await env.KV.put(USAGE_KEY, JSON.stringify(USAGE.map));
  } catch {
    /* ignore */
  }
}

function bumpUsage(env, id, n) {
  USAGE.map[id] = (Number(USAGE.map[id]) || 0) + n;
  if (Date.now() - USAGE.lastPut > 60000) flushUsage(env);
}

async function resetUsage(env, id) {
  USAGE.map[id] = 0;
  await flushUsage(env);
}

async function dropUsage(env, id) {
  delete USAGE.map[id];
  await flushUsage(env);
}

/* ------------------------------------------------------------------------------------------------
 * VLESS over WebSocket endpoint.
 * - TCP is relayed with the Workers connect() API (Cloudflare blocks sockets to its own IP ranges, hence the
 *   optional proxy IP list). UDP is not available in Workers: only DNS (port 53) is answered through DoH.
 * - No speed, bandwidth or connection limit is applied here. Optional per-user expiry / traffic limit only
 *   closes a connection when the administrator configured one.
 * ---------------------------------------------------------------------------------------------- */
const WS_OPEN = 1;
const WS_CLOSING = 2;

function closeWs(ws) {
  try {
    if (ws.readyState === WS_OPEN || ws.readyState === WS_CLOSING) ws.close(1000, 'done');
  } catch {
    /* already closed */
  }
}

// Promise based reader for WebSocket messages; early data (Sec-WebSocket-Protocol) is delivered first.
function wsReader(ws, early) {
  const queue = [];
  let wake = null;
  let ended = false;
  const kick = () => {
    if (wake) {
      const w = wake;
      wake = null;
      w();
    }
  };
  if (early && early.length) queue.push(early);
  ws.addEventListener('message', (ev) => {
    const d = ev.data;
    queue.push(typeof d === 'string' ? enc.encode(d) : new Uint8Array(d));
    kick();
  });
  ws.addEventListener('close', () => {
    ended = true;
    kick();
  });
  ws.addEventListener('error', () => {
    ended = true;
    kick();
  });
  return {
    async read() {
      while (!queue.length) {
        if (ended) return null;
        await new Promise((resolve) => {
          wake = resolve;
        });
      }
      return queue.shift();
    },
    stop() {
      ended = true;
      kick();
    },
  };
}

// VLESS request header -> { ok, version, uuid(hex), cmd, port, addr, payload } | { short } | { bad }
function parseVless(buf) {
  if (buf.length > 0 && buf[0] !== 0) return { bad: true }; // VLESS has only version 0
  if (buf.length < 24) return { short: true };
  const version = buf[0];
  let uuid = '';
  for (let i = 1; i < 17; i++) uuid += buf[i].toString(16).padStart(2, '0');
  let p = 18 + buf[17];
  if (buf.length < p + 4) return { short: true };
  const cmd = buf[p++];
  const port = (buf[p] << 8) | buf[p + 1];
  p += 2;
  const type = buf[p++];
  let addr = '';
  if (type === 1) {
    if (buf.length < p + 4) return { short: true };
    addr = buf[p] + '.' + buf[p + 1] + '.' + buf[p + 2] + '.' + buf[p + 3];
    p += 4;
  } else if (type === 2) {
    const len = buf[p++];
    if (len === 0) return { bad: true };
    if (buf.length < p + len) return { short: true };
    addr = dec.decode(buf.subarray(p, p + len));
    p += len;
  } else if (type === 3) {
    if (buf.length < p + 16) return { short: true };
    const g = [];
    for (let i = 0; i < 8; i++) g.push(((buf[p + i * 2] << 8) | buf[p + i * 2 + 1]).toString(16));
    addr = g.join(':');
    p += 16;
  } else {
    return { bad: true };
  }
  if (port === 0) return { bad: true };
  return { ok: true, version, uuid, cmd, port, addr, payload: buf.subarray(p) };
}

function envProxies(env) {
  return String(env.PROXY_IP || '')
    .split(/[\s,]+/)
    .map((t) => parseEntry(t))
    .filter(Boolean);
}

function proxyList(db, env) {
  const out = db.proxyIps.filter((p) => p.enabled).map((p) => ({ address: p.address, port: p.port || 0 }));
  for (const p of envProxies(env)) out.push({ address: p.address, port: p.port || 0 });
  return out;
}

// DNS server used by the generated configs (filtering provider when the administrator enabled it).
function effectiveDoh(s) {
  const b = s.block;
  if (b.useDns) {
    if (b.ads && b.porn) return 'https://family.adguard-dns.com/dns-query';
    if (b.ads) return 'https://dns.adguard-dns.com/dns-query';
    if (b.porn) return 'https://family.cloudflare-dns.com/dns-query';
    if (b.security) return 'https://security.cloudflare-dns.com/dns-query';
  }
  return s.dns.remote;
}

const workerDoh = (s) => (/^https:\/\//.test(effectiveDoh(s)) ? effectiveDoh(s) : DEFAULT_DOH);

function wsPathMatch(pathname, wsPath) {
  return pathname === wsPath || (wsPath !== '/' && pathname === wsPath + '/');
}

// Opens a TCP socket and waits until it is connected. IPv6 literals are tried with brackets first.
async function openTcp(host, port) {
  const hosts = host.indexOf(':') >= 0 && host[0] !== '[' ? ['[' + host + ']', host] : [host];
  let lastErr = null;
  for (const h of hosts) {
    let sock = null;
    try {
      sock = connect({ hostname: h, port });
      sock.closed.catch(() => {});
      await sock.opened;
      return sock;
    } catch (e) {
      lastErr = e;
      try {
        if (sock) sock.close();
      } catch {
        /* ignore */
      }
    }
  }
  throw lastErr || new Error('connect failed');
}

async function runTcp(ws, rd, hdr, db, env, meter) {
  const mode = db.settings.proxyMode;
  const proxies = mode === 'off' ? [] : proxyList(db, env);
  const respHeader = new Uint8Array([hdr.version, 0]);
  const firstPayload = hdr.payload;
  let headerSent = false;
  let closed = false;
  let retried = false;
  /** @type {{ sock: any, writer: any } | null} */
  let cur = null;
  let switching = null;

  const shutdown = () => {
    if (closed) return;
    closed = true;
    try {
      if (cur) cur.sock.close();
    } catch {
      /* ignore */
    }
    rd.stop();
    closeWs(ws);
  };

  const sendDown = (chunk) => {
    if (ws.readyState !== WS_OPEN) return false;
    try {
      if (headerSent) {
        ws.send(chunk);
      } else {
        headerSent = true;
        ws.send(concat(respHeader, chunk));
      }
    } catch {
      return false;
    }
    return true;
  };

  // Remote -> client. If the remote never sends anything, retry once through a proxy IP (fallback mode).
  const pump = async (sock, port) => {
    let got = false;
    try {
      const reader = sock.readable.getReader();
      for (;;) {
        const r = await reader.read();
        if (r.done) break;
        const v = r.value;
        if (v && v.length) {
          got = true;
          if (!meter(v.length) || !sendDown(v)) break;
        }
      }
    } catch {
      /* remote reset */
    }
    if (closed) return;
    if (!got && !retried && mode === 'fallback' && proxies.length && cur && cur.sock === sock) {
      retried = true;
      /** @type {(v?: any) => void} */
      let release = () => {};
      switching = new Promise((resolve) => {
        release = resolve;
      });
      try {
        const p = pick(proxies);
        await dial(p.address, p.port || port, firstPayload);
        return;
      } catch {
        /* fall through to shutdown */
      } finally {
        switching = null;
        release();
      }
    }
    shutdown();
  };

  const dial = async (host, port, payload) => {
    const sock = await openTcp(host, port);
    let writer = null;
    try {
      writer = sock.writable.getWriter();
      if (payload && payload.length) await writer.write(payload);
    } catch (e) {
      try {
        sock.close();
      } catch {
        /* ignore */
      }
      throw e;
    }
    cur = { sock, writer };
    pump(sock, port).catch(() => shutdown());
  };

  let ok = false;
  try {
    if (mode === 'always' && proxies.length) {
      const p = pick(proxies);
      await dial(p.address, p.port || hdr.port, firstPayload);
    } else {
      await dial(hdr.addr, hdr.port, firstPayload);
    }
    ok = true;
  } catch {
    ok = false;
  }
  if (!ok && mode === 'fallback' && proxies.length) {
    retried = true;
    try {
      const p = pick(proxies);
      await dial(p.address, p.port || hdr.port, firstPayload);
      ok = true;
    } catch {
      ok = false;
    }
  }
  if (!ok) {
    shutdown();
    return;
  }

  // Client -> remote.
  for (;;) {
    const m = await rd.read();
    if (!m) break;
    if (!meter(m.length)) break;
    if (switching) await switching;
    try {
      if (cur) await cur.writer.write(m);
    } catch {
      /* the pump notices a dead socket */
    }
  }
  shutdown();
}

// UDP is not available in Workers. DNS queries (UDP port 53) are answered through DNS over HTTPS.
async function runDns(ws, rd, hdr, db, meter) {
  const doh = workerDoh(db.settings);
  const respHeader = new Uint8Array([hdr.version, 0]);
  let headerSent = false;
  let buf = new Uint8Array(0);

  const reply = (arrayBuf) => {
    if (ws.readyState !== WS_OPEN) return;
    const body = new Uint8Array(arrayBuf);
    const lead = headerSent ? 0 : 2;
    const out = new Uint8Array(lead + 2 + body.length);
    if (!headerSent) {
      out.set(respHeader, 0);
      headerSent = true;
    }
    out[lead] = (body.length >> 8) & 0xff;
    out[lead + 1] = body.length & 0xff;
    out.set(body, lead + 2);
    try {
      ws.send(out);
    } catch {
      /* socket closed */
    }
  };

  const ask = (q) => {
    fetch(doh, {
      method: 'POST',
      headers: { 'content-type': 'application/dns-message', accept: 'application/dns-message' },
      body: q,
    })
      .then((r) => (r.ok ? r.arrayBuffer() : Promise.reject(new Error('doh'))))
      .then(reply)
      .catch(() => {});
  };

  const feed = (chunk) => {
    buf = buf.length ? concat(buf, chunk) : chunk;
    while (buf.length >= 2) {
      const len = (buf[0] << 8) | buf[1];
      if (buf.length < 2 + len) break;
      ask(buf.slice(2, 2 + len));
      buf = buf.slice(2 + len);
    }
  };

  feed(hdr.payload);
  for (;;) {
    const m = await rd.read();
    if (!m) break;
    if (!meter(m.length)) break;
    feed(m);
  }
  closeWs(ws);
}

const HEADER_TIMEOUT_MS = 10000;

// rd.read() with a deadline (resolves null on timeout).
function readWithin(rd, ms) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), ms);
    rd.read().then(
      (v) => {
        clearTimeout(timer);
        resolve(v);
      },
      () => {
        clearTimeout(timer);
        resolve(null);
      }
    );
  });
}

async function vlessSession(ws, request, env, db) {
  // Early data (0-RTT style): the first bytes may arrive base64url encoded in Sec-WebSocket-Protocol.
  let early = null;
  const proto = request.headers.get('sec-websocket-protocol');
  if (proto) {
    try {
      early = unb64url(proto.split(',')[0].trim());
    } catch {
      early = null;
    }
  }
  const rd = wsReader(ws, early); // attaches listeners synchronously, before the first await

  let buf = await readWithin(rd, HEADER_TIMEOUT_MS);
  if (!buf) {
    rd.stop();
    closeWs(ws);
    return;
  }
  let hdr = parseVless(buf);
  while (hdr.short && buf.length < 4096) {
    const more = await readWithin(rd, HEADER_TIMEOUT_MS);
    if (!more) break;
    buf = concat(buf, more);
    hdr = parseVless(buf);
  }
  if (!hdr.ok) {
    rd.stop();
    closeWs(ws);
    return;
  }
  const user = db.users.find((u) => u.uuid.replace(/-/g, '') === hdr.uuid);
  if (!user) {
    rd.stop();
    closeWs(ws);
    return;
  }
  const limited = user.limitBytes > 0;
  const used = limited ? Number((await loadUsage(env))[user.id]) || 0 : 0;
  if (userStatus(user, used) !== 'ok') {
    rd.stop();
    closeWs(ws);
    return;
  }
  const expTs = user.expiry ? Date.parse(user.expiry + 'T23:59:59Z') : 0;
  // Called for every chunk; returns false when the optional expiry / traffic limit says "stop".
  const meter = (n) => {
    if (expTs && Date.now() > expTs) return false;
    if (!limited) return true;
    bumpUsage(env, user.id, n);
    return (Number(USAGE.map[user.id]) || 0) < user.limitBytes;
  };

  if (hdr.cmd === 1) {
    await runTcp(ws, rd, hdr, db, env, meter);
    return;
  }
  if (hdr.cmd === 2 && hdr.port === 53) {
    await runDns(ws, rd, hdr, db, meter);
    return;
  }
  rd.stop();
  closeWs(ws); // MUX and non-DNS UDP are not supported
}

// Returns a 101 response for a valid WebSocket path, or null so the router can answer normally.
async function wsEntry(request, env, url) {
  const db = await loadDB(env);
  if (!wsPathMatch(url.pathname, db.settings.wsPath)) return null;
  if (typeof WebSocketPair === 'undefined') return null;
  const pair = new WebSocketPair();
  const client = pair[0];
  const server = pair[1];
  server.accept();
  vlessSession(server, request, env, db).catch(() => closeWs(server));
  return new Response(null, { status: 101, webSocket: client });
}

/* ------------------------------------------------------------------------------------------------
 * Config generation
 *  - vless:// links (RAW) and their Base64 subscription: link level options only (path, early data, TLS, SNI...).
 *  - Xray JSON export: full client configs that also carry DNS servers, TLS fragment and blocking rules,
 *    because a vless:// link cannot carry those.
 * No artificial speed limit is written anywhere (mux is off, no rate/bandwidth policy is set).
 * ---------------------------------------------------------------------------------------------- */
const hostOf = (s, reqHost) => s.host || reqHost;
const uriHost = (a) => (a.indexOf(':') >= 0 && a[0] !== '[' ? '[' + a + ']' : a);

// Every enabled clean IP (and optionally the panel domain itself) x selected TLS and non-TLS ports.
function targetsOf(db, host) {
  const s = db.settings;
  const addrs = db.ips
    .filter((i) => i.enabled)
    .map((i) => ({ address: i.address, port: i.port, label: i.remark || i.address }));
  if (s.includeHost || addrs.length === 0) addrs.push({ address: host, port: 0, label: 'direct' });
  const out = [];
  for (const a of addrs) {
    const list = a.port ? [a.port] : s.tlsPorts.concat(s.plainPorts);
    for (const port of list) out.push({ address: a.address, port, tls: !PLAIN_PORTS.includes(port), label: a.label });
  }
  return out;
}

const remarkOf = (s, t) => [s.remarkPrefix, t.label, t.tls ? 'TLS' : 'NTLS', t.port].filter((x) => x !== '').join('-');
const wsPathOf = (s) => s.wsPath + (s.earlyData > 0 ? '?ed=' + s.earlyData : '');

function vlessUri(user, t, s, host) {
  const q = ['encryption=none', 'security=' + (t.tls ? 'tls' : 'none')];
  if (t.tls) q.push('sni=' + encodeURIComponent(host), 'fp=' + s.fingerprint, 'alpn=' + encodeURIComponent('http/1.1'));
  q.push('type=ws', 'host=' + encodeURIComponent(host), 'path=' + encodeURIComponent(wsPathOf(s)));
  return (
    'vless://' + user.uuid + '@' + uriHost(t.address) + ':' + t.port + '?' + q.join('&') + '#' +
    encodeURIComponent(remarkOf(s, t))
  );
}

function buildLinks(db, user, host) {
  const s = db.settings;
  return targetsOf(db, host).map((t) => ({ remark: remarkOf(s, t), uri: vlessUri(user, t, s, host) }));
}

function xrayConfig(user, t, s, host) {
  const remote = effectiveDoh(s);
  const frag = s.fragment;
  const useFrag = t.tls && frag.enabled;
  const sockopt = { tcpNoDelay: true };
  if (useFrag) sockopt.dialerProxy = 'fragment';
  const stream = {
    network: 'ws',
    security: t.tls ? 'tls' : 'none',
    wsSettings: { path: wsPathOf(s), headers: { Host: host } },
    sockopt,
  };
  if (t.tls) {
    stream.tlsSettings = { serverName: host, fingerprint: s.fingerprint, alpn: ['http/1.1'], allowInsecure: false };
  }
  /** @type {any[]} */
  const outbounds = [
    {
      tag: 'proxy',
      protocol: 'vless',
      settings: { vnext: [{ address: t.address, port: t.port, users: [{ id: user.uuid, encryption: 'none', level: 8 }] }] },
      streamSettings: stream,
      mux: { enabled: false, concurrency: -1 },
    },
  ];
  if (useFrag) {
    outbounds.push({
      tag: 'fragment',
      protocol: 'freedom',
      settings: { fragment: { packets: frag.packets, length: frag.length, interval: frag.interval } },
      streamSettings: { sockopt: { tcpNoDelay: true, tcpKeepAliveIdle: 100 } },
    });
  }
  outbounds.push(
    { tag: 'direct', protocol: 'freedom', settings: {} },
    { tag: 'block', protocol: 'blackhole', settings: { response: { type: 'http' } } }
  );

  // DNS: the Worker domain, domain-type clean IPs and an unknown DoH host are resolved by the plain "direct" server;
  // well-known DoH hostnames get static addresses. Everything else goes to the remote (DoH) server.
  const names = [host];
  if (!isIp(t.address)) names.push(t.address);
  let dohHost = '';
  try {
    dohHost = new URL(remote).hostname;
  } catch {
    dohHost = '';
  }
  const dns = { servers: [] };
  if (dohHost && DOH_HOSTS[dohHost]) dns.hosts = { [dohHost]: DOH_HOSTS[dohHost] };
  else if (dohHost && dohHost[0] !== '[' && !isIp(dohHost)) names.push(dohHost);
  dns.servers.push(
    { address: s.dns.direct, domains: Array.from(new Set(names)).map((n) => 'full:' + n), skipFallback: true },
    remote
  );

  /** @type {any[]} */
  const rules = [{ type: 'field', ip: [s.dns.direct], port: '53', network: 'udp', outboundTag: 'direct' }];
  if (s.block.ads) rules.push({ type: 'field', domain: ['geosite:category-ads-all'], outboundTag: 'block' });
  if (s.block.porn) rules.push({ type: 'field', domain: ['geosite:category-porn'], outboundTag: 'block' });
  rules.push({ type: 'field', network: 'tcp,udp', outboundTag: 'proxy' });

  const sniffing = { enabled: true, destOverride: ['http', 'tls'], routeOnly: true };
  return {
    remarks: remarkOf(s, t),
    log: { loglevel: 'warning' },
    dns,
    inbounds: [
      { tag: 'socks-in', listen: '127.0.0.1', port: 10808, protocol: 'socks', settings: { auth: 'noauth', udp: true, userLevel: 8 }, sniffing },
      { tag: 'http-in', listen: '127.0.0.1', port: 10809, protocol: 'http', settings: { userLevel: 8 }, sniffing },
    ],
    outbounds,
    routing: { domainStrategy: 'IPIfNonMatch', rules },
  };
}

function buildXray(db, user, host) {
  return targetsOf(db, host).map((t) => xrayConfig(user, t, db.settings, host));
}

// Body of /sub/<token>: base64 list of vless:// links (default), plain list (?format=raw) or Xray JSON (?format=xray).
function subscriptionBody(format, db, user, host) {
  if (format === 'xray') return { type: 'application/json; charset=utf-8', body: JSON.stringify(buildXray(db, user, host)) };
  const lines = buildLinks(db, user, host).map((l) => l.uri).join('\n');
  if (format === 'raw') return { type: 'text/plain; charset=utf-8', body: lines };
  return { type: 'text/plain; charset=utf-8', body: b64(enc.encode(lines)) };
}

// Usage header understood by many clients. Fields are only sent when a limit or expiry exists.
function userinfoHeader(user, used) {
  if (!(user.limitBytes > 0) && !user.expiry) return null;
  const parts = ['upload=0', 'download=' + Math.floor(used)];
  if (user.limitBytes > 0) parts.push('total=' + user.limitBytes);
  if (user.expiry) parts.push('expire=' + Math.floor(Date.parse(user.expiry + 'T23:59:59Z') / 1000));
  return parts.join('; ');
}

/* ---------------- browser code kept as strings (QR encoder + panel client) ---------------- */
const QR_JS = String.raw`/* Pure JavaScript QR code encoder: byte mode, versions 1-20, error correction M (falls back to L). */
var QR_ECC = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28],
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26]
];
var QR_BLK = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16]
];
var QR_FMT = [1, 0];

function qrRawModules(ver) {
  var r = (16 * ver + 128) * ver + 64;
  if (ver >= 2) {
    var na = Math.floor(ver / 7) + 2;
    r -= (25 * na - 10) * na - 55;
    if (ver >= 7) r -= 36;
  }
  return r;
}

function qrDataCodewords(ver, lvl) {
  return Math.floor(qrRawModules(ver) / 8) - QR_ECC[lvl][ver] * QR_BLK[lvl][ver];
}

function qrGfMul(x, y) {
  var z = 0;
  for (var i = 7; i >= 0; i--) {
    z = (z << 1) ^ ((z >>> 7) * 0x11D);
    z ^= ((y >>> i) & 1) * x;
  }
  return z;
}

function qrRsDivisor(deg) {
  var res = [];
  for (var i = 0; i < deg; i++) res.push(0);
  res[deg - 1] = 1;
  var root = 1;
  for (var r = 0; r < deg; r++) {
    for (var j = 0; j < deg; j++) {
      res[j] = qrGfMul(res[j], root);
      if (j + 1 < deg) res[j] ^= res[j + 1];
    }
    root = qrGfMul(root, 2);
  }
  return res;
}

function qrRsRemainder(data, div) {
  var res = [];
  for (var i = 0; i < div.length; i++) res.push(0);
  for (var k = 0; k < data.length; k++) {
    var factor = data[k] ^ res.shift();
    res.push(0);
    for (var j = 0; j < div.length; j++) res[j] ^= qrGfMul(div[j], factor);
  }
  return res;
}

function qrAlignPositions(ver, size) {
  if (ver === 1) return [];
  var num = Math.floor(ver / 7) + 2;
  var step = ver === 32 ? 26 : Math.ceil((ver * 4 + 4) / (num * 2 - 2)) * 2;
  var res = [6];
  for (var pos = size - 7; res.length < num; pos -= step) res.splice(1, 0, pos);
  return res;
}

/* Returns { size, get(x, y) } or null when the text does not fit into version 20. */
function qrEncode(text) {
  var bytes = new TextEncoder().encode(String(text));
  var ver = 0;
  var lvl = 0;
  var found = false;
  var order = [1, 0];
  for (var oi = 0; oi < order.length && !found; oi++) {
    for (var v = 1; v <= 20; v++) {
      var need = 4 + (v < 10 ? 8 : 16) + bytes.length * 8;
      if (need <= qrDataCodewords(v, order[oi]) * 8) {
        ver = v;
        lvl = order[oi];
        found = true;
        break;
      }
    }
  }
  if (!found) return null;

  // 1) data bits
  var bits = [];
  function put(val, len) {
    for (var i = len - 1; i >= 0; i--) bits.push((val >>> i) & 1);
  }
  put(4, 4);
  put(bytes.length, ver < 10 ? 8 : 16);
  for (var bi = 0; bi < bytes.length; bi++) put(bytes[bi], 8);
  var cap = qrDataCodewords(ver, lvl) * 8;
  put(0, Math.min(4, cap - bits.length));
  put(0, (8 - (bits.length % 8)) % 8);
  for (var pad = 0xEC; bits.length < cap; pad ^= 0xEC ^ 0x11) put(pad, 8);
  var data = [];
  for (var di = 0; di < bits.length; di += 8) {
    var b = 0;
    for (var bk = 0; bk < 8; bk++) b = (b << 1) | bits[di + bk];
    data.push(b);
  }

  // 2) error correction and interleaving
  var nb = QR_BLK[lvl][ver];
  var el = QR_ECC[lvl][ver];
  var raw = Math.floor(qrRawModules(ver) / 8);
  var nShort = nb - (raw % nb);
  var shortLen = Math.floor(raw / nb);
  var blocks = [];
  var pos = 0;
  var div = qrRsDivisor(el);
  for (var bn = 0; bn < nb; bn++) {
    var dl = shortLen - el + (bn < nShort ? 0 : 1);
    var dat = data.slice(pos, pos + dl);
    pos += dl;
    var ecc = qrRsRemainder(dat, div);
    if (bn < nShort) dat.push(0);
    blocks.push(dat.concat(ecc));
  }
  var all = [];
  for (var ci = 0; ci < blocks[0].length; ci++) {
    for (var cj = 0; cj < blocks.length; cj++) {
      if (ci !== shortLen - el || cj >= nShort) all.push(blocks[cj][ci]);
    }
  }

  // 3) matrix with function patterns
  var size = ver * 4 + 17;
  var mod = [];
  var fn = [];
  for (var yy = 0; yy < size; yy++) {
    var ra = [];
    var rb = [];
    for (var xx = 0; xx < size; xx++) {
      ra.push(false);
      rb.push(false);
    }
    mod.push(ra);
    fn.push(rb);
  }
  function setFn(x, y, dark) {
    mod[y][x] = !!dark;
    fn[y][x] = true;
  }
  function finder(cx, cy) {
    for (var dy = -4; dy <= 4; dy++) {
      for (var dx = -4; dx <= 4; dx++) {
        var dist = Math.max(Math.abs(dx), Math.abs(dy));
        var px = cx + dx;
        var py = cy + dy;
        if (px >= 0 && px < size && py >= 0 && py < size) setFn(px, py, dist !== 2 && dist !== 4);
      }
    }
  }
  function alignment(cx, cy) {
    for (var dy = -2; dy <= 2; dy++) {
      for (var dx = -2; dx <= 2; dx++) setFn(cx + dx, cy + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1);
    }
  }
  function drawFormat(mask) {
    var d = (QR_FMT[lvl] << 3) | mask;
    var rem = d;
    for (var i = 0; i < 10; i++) rem = (rem << 1) ^ ((rem >>> 9) * 0x537);
    var fb = ((d << 10) | rem) ^ 0x5412;
    var bit = function (n) {
      return ((fb >>> n) & 1) !== 0;
    };
    for (var a = 0; a <= 5; a++) setFn(8, a, bit(a));
    setFn(8, 7, bit(6));
    setFn(8, 8, bit(7));
    setFn(7, 8, bit(8));
    for (var c = 9; c < 15; c++) setFn(14 - c, 8, bit(c));
    for (var e = 0; e < 8; e++) setFn(size - 1 - e, 8, bit(e));
    for (var f = 8; f < 15; f++) setFn(8, size - 15 + f, bit(f));
    setFn(8, size - 8, true);
  }
  for (var tt = 0; tt < size; tt++) {
    setFn(6, tt, tt % 2 === 0);
    setFn(tt, 6, tt % 2 === 0);
  }
  finder(3, 3);
  finder(size - 4, 3);
  finder(3, size - 4);
  var al = qrAlignPositions(ver, size);
  var na = al.length;
  for (var ai = 0; ai < na; ai++) {
    for (var aj = 0; aj < na; aj++) {
      if (!((ai === 0 && aj === 0) || (ai === 0 && aj === na - 1) || (ai === na - 1 && aj === 0))) alignment(al[ai], al[aj]);
    }
  }
  drawFormat(0);
  if (ver >= 7) {
    var vr = ver;
    for (var vi = 0; vi < 12; vi++) vr = (vr << 1) ^ ((vr >>> 11) * 0x1F25);
    var vb = (ver << 12) | vr;
    for (var vk = 0; vk < 18; vk++) {
      var col = ((vb >>> vk) & 1) !== 0;
      var va = size - 11 + (vk % 3);
      var vc = Math.floor(vk / 3);
      setFn(va, vc, col);
      setFn(vc, va, col);
    }
  }

  // 4) data codewords in the zigzag order
  var idx = 0;
  for (var right = size - 1; right >= 1; right -= 2) {
    if (right === 6) right = 5;
    for (var vert = 0; vert < size; vert++) {
      for (var j = 0; j < 2; j++) {
        var x = right - j;
        var upward = ((right + 1) & 2) === 0;
        var y = upward ? size - 1 - vert : vert;
        if (!fn[y][x] && idx < all.length * 8) {
          mod[y][x] = ((all[idx >>> 3] >>> (7 - (idx & 7))) & 1) !== 0;
          idx++;
        }
      }
    }
  }

  // 5) mask selection
  function applyMask(m) {
    for (var y2 = 0; y2 < size; y2++) {
      for (var x2 = 0; x2 < size; x2++) {
        var inv;
        switch (m) {
          case 0: inv = (x2 + y2) % 2 === 0; break;
          case 1: inv = y2 % 2 === 0; break;
          case 2: inv = x2 % 3 === 0; break;
          case 3: inv = (x2 + y2) % 3 === 0; break;
          case 4: inv = (Math.floor(x2 / 3) + Math.floor(y2 / 2)) % 2 === 0; break;
          case 5: inv = ((x2 * y2) % 2) + ((x2 * y2) % 3) === 0; break;
          case 6: inv = (((x2 * y2) % 2) + ((x2 * y2) % 3)) % 2 === 0; break;
          default: inv = (((x2 + y2) % 2) + ((x2 * y2) % 3)) % 2 === 0;
        }
        if (inv && !fn[y2][x2]) mod[y2][x2] = !mod[y2][x2];
      }
    }
  }
  function countPat(s) {
    var n = 0;
    var k = s.indexOf('10111010000');
    while (k >= 0) {
      n++;
      k = s.indexOf('10111010000', k + 1);
    }
    k = s.indexOf('00001011101');
    while (k >= 0) {
      n++;
      k = s.indexOf('00001011101', k + 1);
    }
    return n;
  }
  function penalty() {
    var p = 0;
    var dark = 0;
    var a;
    var c;
    var run;
    var rowStr;
    var colStr;
    for (a = 0; a < size; a++) {
      rowStr = '';
      colStr = '';
      for (c = 0; c < size; c++) {
        rowStr += mod[a][c] ? '1' : '0';
        colStr += mod[c][a] ? '1' : '0';
        if (mod[a][c]) dark++;
      }
      p += countPat(rowStr) * 40 + countPat(colStr) * 40;
      var strs = [rowStr, colStr];
      for (var si = 0; si < 2; si++) {
        run = 1;
        for (c = 1; c < size; c++) {
          if (strs[si].charAt(c) === strs[si].charAt(c - 1)) {
            run++;
            if (run === 5) p += 3;
            else if (run > 5) p += 1;
          } else {
            run = 1;
          }
        }
      }
    }
    for (a = 0; a < size - 1; a++) {
      for (c = 0; c < size - 1; c++) {
        var v0 = mod[a][c];
        if (v0 === mod[a][c + 1] && v0 === mod[a + 1][c] && v0 === mod[a + 1][c + 1]) p += 3;
      }
    }
    var total = size * size;
    var k = Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1;
    return p + (k > 0 ? k * 10 : 0);
  }
  var best = 0;
  var bestP = Infinity;
  for (var mk = 0; mk < 8; mk++) {
    applyMask(mk);
    drawFormat(mk);
    var pp = penalty();
    if (pp < bestP) {
      bestP = pp;
      best = mk;
    }
    applyMask(mk);
  }
  applyMask(best);
  drawFormat(best);
  return {
    size: size,
    get: function (px, py) {
      return mod[py][px];
    }
  };
}
`;

const CLIENT_JS = String.raw`/* ---------------- panel client (vanilla JS, no libraries) ---------------- */
var boot = JSON.parse(document.getElementById('boot').textContent);
var D = boot.i18n;
var lang = boot.lang;
var S = null;
var tab = 'home';
var EX = null;
var exUser = '';
var exBusy = '';
var toastEl = null;
var toastTimer = 0;
var root = document.getElementById('app');

function lsGet(k) {
  try { return window.localStorage.getItem(k); } catch (e) { return null; }
}
function lsSet(k, v) {
  try { window.localStorage.setItem(k, v); } catch (e) { /* storage unavailable */ }
}
function setCookie(k, v) {
  try { document.cookie = k + '=' + encodeURIComponent(v) + '; Path=/; Max-Age=31536000; SameSite=Lax'; } catch (e) { /* ignore */ }
}

function t(k) {
  var l = D[lang];
  if (l && l[k] !== undefined) return l[k];
  return D.en[k] !== undefined ? D.en[k] : k;
}
function tf(k, o) {
  return t(k).replace(/\{(\w+)\}/g, function (m, n) {
    return o && o[n] !== undefined ? String(o[n]) : m;
  });
}
function errText(code) {
  var key = 'err_' + code;
  var l = D[lang];
  return l && l[key] !== undefined ? l[key] : t('err_generic');
}

function h(tag, attrs, kids) {
  var el = document.createElement(tag);
  var val = null;
  var hasVal = false;
  if (attrs) {
    for (var k in attrs) {
      if (!Object.prototype.hasOwnProperty.call(attrs, k)) continue;
      var v = attrs[k];
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k === 'value') { val = v; hasVal = true; }
      else if (k === 'checked') el.checked = !!v;
      else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : String(v));
    }
  }
  if (kids) {
    for (var i = 0; i < kids.length; i++) {
      var c = kids[i];
      if (c === null || c === undefined || c === false) continue;
      el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    }
  }
  if (hasVal) el.value = val;
  return el;
}

function btn(label, cls, fn, title) {
  return h('button', { type: 'button', class: 'btn ' + (cls || ''), onclick: fn, title: title || null, text: label });
}

function randId(n) {
  var chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
  var b = new Uint8Array(n);
  window.crypto.getRandomValues(b);
  var s = '';
  for (var i = 0; i < n; i++) s += chars.charAt(b[i] % chars.length);
  return s;
}

function genUuid() {
  try {
    if (window.crypto && window.crypto.randomUUID) return window.crypto.randomUUID();
  } catch (e) { /* fall back below */ }
  var b = new Uint8Array(16);
  window.crypto.getRandomValues(b);
  b[6] = (b[6] & 15) | 64;
  b[8] = (b[8] & 63) | 128;
  var x = '';
  for (var i = 0; i < 16; i++) x += (b[i] < 16 ? '0' : '') + b[i].toString(16);
  return x.slice(0, 8) + '-' + x.slice(8, 12) + '-' + x.slice(12, 16) + '-' + x.slice(16, 20) + '-' + x.slice(20);
}

function fmtGb(n) {
  return (n / 1073741824).toFixed(2) + ' GB';
}

/* ---------------- toast, modal, confirm, copy, QR ---------------- */
function toast(msg, kind) {
  if (!toastEl) {
    toastEl = h('div', { class: 'toast', role: 'status' });
    document.body.appendChild(toastEl);
  }
  toastEl.textContent = msg;
  toastEl.className = 'toast show ' + (kind || '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(function () {
    toastEl.className = 'toast ' + (kind || '');
  }, 2800);
}

function modal(title, nodes, buttons) {
  var ov = h('div', { class: 'ov' });
  var dlg = h('div', { class: 'dlg', role: 'dialog', 'aria-modal': 'true' }, [
    h('h3', { text: title }),
    h('div', { class: 'dbody' }, nodes),
    h('div', { class: 'drow' }, buttons)
  ]);
  ov.appendChild(dlg);
  ov.addEventListener('click', function (e) {
    if (e.target === ov) close();
  });
  document.body.appendChild(ov);
  function close() {
    if (ov.parentNode) ov.parentNode.removeChild(ov);
  }
  return { close: close };
}

function confirmBox(message) {
  return new Promise(function (resolve) {
    var m = modal(t('confirmTitle'), [h('p', { text: message })], [
      btn(t('cancel'), '', function () { m.close(); resolve(false); }),
      btn(t('del'), 'bad', function () { m.close(); resolve(true); })
    ]);
  });
}

function confirmAction(message) {
  return new Promise(function (resolve) {
    var m = modal(t('confirmTitle'), [h('p', { text: message })], [
      btn(t('cancel'), '', function () { m.close(); resolve(false); }),
      btn(t('apply'), 'pri', function () { m.close(); resolve(true); })
    ]);
  });
}

function copyText(text) {
  function fallback() {
    try {
      var ta = h('textarea', { class: 'hid' });
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      var ok = document.execCommand('copy');
      document.body.removeChild(ta);
      toast(t(ok ? 'copied' : 'copyFailed'), ok ? 'ok' : 'bad');
    } catch (e) {
      toast(t('copyFailed'), 'bad');
    }
  }
  try {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { toast(t('copied'), 'ok'); }, fallback);
      return;
    }
  } catch (e) { /* fall through */ }
  fallback();
}

function showQR(text, title) {
  var q = qrEncode(text);
  if (!q) { toast(t('qrTooLong'), 'bad'); return; }
  var scale = Math.max(2, Math.min(8, Math.floor(300 / (q.size + 8))));
  var px = (q.size + 8) * scale;
  var cv = h('canvas', { width: px, height: px, class: 'qr' });
  var ctx = cv.getContext('2d');
  ctx.fillStyle = '#ffffff';
  ctx.fillRect(0, 0, px, px);
  ctx.fillStyle = '#000000';
  for (var y = 0; y < q.size; y++) {
    for (var x = 0; x < q.size; x++) {
      if (q.get(x, y)) ctx.fillRect((x + 4) * scale, (y + 4) * scale, scale, scale);
    }
  }
  var m = modal(title || t('qrTitle'), [h('div', { class: 'qrbox' }, [cv])], [
    btn(t('close'), 'pri', function () { m.close(); })
  ]);
}

/* ---------------- API helpers ---------------- */
function api(method, path, body) {
  var opts = { method: method, headers: { 'x-panel': '1' } };
  if (body !== undefined) {
    opts.headers['content-type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  return fetch(path, opts).then(function (r) {
    return r.json().then(
      function (j) { j.status = r.status; return j; },
      function () { return { ok: false, error: 'bad_response', status: r.status }; }
    );
  }, function () {
    return { ok: false, error: 'network', status: 0 };
  });
}

function act(method, path, body, okKey) {
  return api(method, path, body).then(function (r) {
    if (r.status === 401) { boot.authed = false; S = null; render(); return r; }
    if (!r.ok) { toast(errText(r.error), 'bad'); return r; }
    if (r.state) S = r.state;
    if (r.warn) toast(errText(r.warn), 'warn');
    else if (okKey) toast(t(okKey), 'ok');
    return r;
  });
}

function loadState() {
  return api('GET', '/api/state').then(function (r) {
    if (r.ok) { S = r.state; render(); }
    else if (r.status === 401) { boot.authed = false; S = null; render(); }
    else toast(errText(r.error), 'bad');
  });
}

function doLogout() {
  api('POST', '/api/logout', {}).then(function () {
    boot.authed = false;
    S = null;
    EX = null;
    render();
  });
}

/* ---------------- language and theme ---------------- */
function applyLang() {
  document.documentElement.setAttribute('lang', lang);
  document.documentElement.setAttribute('dir', lang === 'fa' ? 'rtl' : 'ltr');
  document.title = t('appName');
}

function setLang(l) {
  lang = l;
  setCookie('lang', l);
  lsSet('lang', l);
  render();
}

function currentTheme() {
  var a = document.documentElement.getAttribute('data-theme');
  if (a === 'dark' || a === 'light') return a;
  try {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  } catch (e) { return 'light'; }
}

function toggleTheme() {
  var next = currentTheme() === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
  setCookie('theme', next);
  lsSet('theme', next);
}

/* ---------------- generic form modal ---------------- */
// fields: [{ k, label, type: text|number|date|checkbox|textarea|uuid, ltr, ph, hint, step, rows }]
// submit(values) returns a Promise: true = close the form, false = keep it open (the user can fix the input).
function formModal(title, fields, vals, submitLabel, submit) {
  var inputs = {};
  var body = h('div', { class: 'form' });
  fields.forEach(function (f) {
    var el;
    var v = vals[f.k] === undefined || vals[f.k] === null ? '' : vals[f.k];
    if (f.type === 'checkbox') {
      el = h('input', { type: 'checkbox', checked: !!vals[f.k] });
      body.appendChild(h('label', { class: 'chk' }, [el, h('span', { text: f.label })]));
    } else if (f.type === 'textarea') {
      el = h('textarea', { rows: f.rows || 6, placeholder: f.ph || null, dir: f.ltr ? 'ltr' : null, value: v });
      body.appendChild(h('label', { class: 'fld' }, [h('span', { class: 'lbl', text: f.label }), el, f.hint ? h('small', { class: 'muted', text: f.hint }) : null]));
    } else {
      el = h('input', {
        type: f.type === 'uuid' ? 'text' : (f.type || 'text'),
        placeholder: f.ph || null,
        dir: f.ltr ? 'ltr' : null,
        step: f.step || null,
        min: f.min || null,
        autocomplete: 'off',
        value: v
      });
      var line = f.type === 'uuid'
        ? h('div', { class: 'row nowrap' }, [el, btn(t('generate'), 'sm', function () { el.value = genUuid(); })])
        : el;
      body.appendChild(h('label', { class: 'fld' }, [h('span', { class: 'lbl', text: f.label }), line, f.hint ? h('small', { class: 'muted', text: f.hint }) : null]));
    }
    inputs[f.k] = el;
  });
  var saveBtn = btn(submitLabel || t('save'), 'pri', function () {
    var out = {};
    fields.forEach(function (f) {
      var el = inputs[f.k];
      out[f.k] = f.type === 'checkbox' ? el.checked : el.value;
    });
    saveBtn.disabled = true;
    submit(out).then(function (done) {
      saveBtn.disabled = false;
      if (done) m.close();
    });
  });
  var m = modal(title, [body], [btn(t('cancel'), '', function () { m.close(); }), saveBtn]);
}

/* ---------------- views ---------------- */
function header() {
  var acts = [
    btn(t('switchLang'), 'sm', function () { setLang(lang === 'fa' ? 'en' : 'fa'); }, t('langToggle')),
    btn('◐', 'sm', toggleTheme, t('themeToggle'))
  ];
  if (boot.authed) acts.push(btn(t('logout'), 'sm', doLogout));
  return h('header', { class: 'top' }, [h('div', { class: 'brand', text: t('appName') }), h('div', { class: 'acts' }, acts)]);
}

function viewNoPass() {
  return h('div', { class: 'card warn' }, [
    h('h2', { text: t('noPassTitle') }),
    h('p', { text: t('noPassBody') }),
    h('ul', { class: 'steps' }, [h('li', { text: t('noPassWorkers') }), h('li', { text: t('noPassPages') })])
  ]);
}

function viewLogin() {
  var pw = h('input', { type: 'password', autocomplete: 'current-password', placeholder: t('password'), dir: 'ltr' });
  function go() {
    api('POST', '/api/login', { password: pw.value }).then(function (r) {
      if (r.ok) { boot.authed = true; loadState(); }
      else toast(errText(r.error), 'bad');
    });
  }
  pw.addEventListener('keydown', function (e) {
    if (e.key === 'Enter') go();
  });
  return h('div', { class: 'card login' }, [
    h('h2', { text: t('loginTitle') }),
    h('p', { class: 'note', text: t('loginHint') }),
    pw,
    h('div', { class: 'row' }, [btn(t('login'), 'pri', go)])
  ]);
}

function stat(label, value) {
  return h('div', { class: 'stat' }, [h('div', { class: 'num ltr', text: String(value) }), h('div', { class: 'muted', text: label })]);
}

function kvCard() {
  if (S.kv === 'ok') {
    return h('div', { class: 'card ok' }, [h('h3', { text: t('kvOkTitle') }), h('p', { text: t('kvOkBody') })]);
  }
  if (S.kv === 'error') {
    return h('div', { class: 'card warn' }, [h('h3', { text: t('kvErrorTitle') }), h('p', { text: t('kvErrorBody') })]);
  }
  return h('div', { class: 'card warn' }, [
    h('h3', { text: t('kvMissingTitle') }),
    h('p', { text: t('kvMissingBody') }),
    h('ul', { class: 'steps' }, [
      h('li', { text: t('kvStepGit') }),
      h('li', { text: t('kvStepWorkers') }),
      h('li', { text: t('kvStepPages') })
    ])
  ]);
}

function viewHome() {
  return h('div', null, [
    kvCard(),
    h('div', { class: 'stats' }, [
      stat(t('statUsers'), S.users.length),
      stat(t('statIps'), S.ips.length),
      stat(t('statProxy'), S.proxyIps.length),
      stat(t('statLinks'), S.linksPerUser)
    ]),
    h('div', { class: 'card' }, [
      h('div', { class: 'kv' }, [h('span', { class: 'muted', text: t('workerHost') + ': ' }), h('span', { class: 'ltr', text: S.host })]),
      h('div', { class: 'kv' }, [h('span', { class: 'muted', text: t('version') + ': ' }), h('span', { class: 'ltr', text: S.version })])
    ]),
    h('div', { class: 'card' }, [
      h('h3', { text: t('qsTitle') }),
      h('p', { text: t('qs1') }),
      h('p', { text: t('qs2') }),
      h('p', { text: t('qs3') })
    ])
  ]);
}

/* ----- users ----- */
function userState(u) {
  if (!u.enabled) return 'disabled';
  if (u.expiry && Date.now() > Date.parse(u.expiry + 'T23:59:59Z')) return 'expired';
  if (u.limitBytes > 0 && u.used >= u.limitBytes) return 'limit';
  return 'ok';
}

function editUser(u) {
  var isNew = !u;
  var vals = isNew
    ? { name: '', uuid: genUuid(), expiry: '', limitGb: '', enabled: true, resetUsage: false }
    : { name: u.name, uuid: u.uuid, expiry: u.expiry, limitGb: u.limitBytes > 0 ? +(u.limitBytes / 1073741824).toFixed(3) : '', enabled: u.enabled, resetUsage: false };
  var fields = [
    { k: 'name', label: t('userName') },
    { k: 'uuid', label: t('uuid'), type: 'uuid', ltr: true },
    { k: 'expiry', label: t('expiryDate'), type: 'date', ltr: true },
    { k: 'limitGb', label: t('limitGb'), type: 'number', step: 'any', min: '0', ltr: true, hint: t('limitHint') },
    { k: 'enabled', label: t('enabled'), type: 'checkbox' }
  ];
  if (!isNew) fields.push({ k: 'resetUsage', label: t('resetUsage'), type: 'checkbox' });
  formModal(isNew ? t('addUser') : t('editUser'), fields, vals, null, function (out) {
    var path = isNew ? '/api/users' : '/api/users/' + u.id;
    return act(isNew ? 'POST' : 'PUT', path, out, 'saved').then(function (r) {
      if (r && r.ok) { EX = null; render(); }
      return !!(r && (r.ok || r.status === 401));
    });
  });
}

function userCard(u) {
  var st = userState(u);
  var badges = [];
  if (st === 'disabled') badges.push(h('span', { class: 'badge bad', text: t('badgeDisabled') }));
  if (st === 'expired') badges.push(h('span', { class: 'badge bad', text: t('badgeExpired') }));
  if (st === 'limit') badges.push(h('span', { class: 'badge bad', text: t('badgeLimit') }));
  if (st === 'ok') badges.push(h('span', { class: 'badge ok', text: t('enabled') }));
  var traffic = u.limitBytes > 0 ? fmtGb(u.used) + ' / ' + fmtGb(u.limitBytes) : t('unlimited');
  return h('div', { class: 'card' }, [
    h('div', { class: 'bar' }, [h('h3', { text: u.name || u.uuid.slice(0, 8) }), h('div', { class: 'row' }, badges)]),
    h('div', { class: 'kv' }, [h('span', { class: 'muted', text: t('uuid') + ': ' }), h('span', { class: 'ltr mono', text: u.uuid })]),
    h('div', { class: 'kv' }, [h('span', { class: 'muted', text: t('expires') + ': ' }), h('span', { class: 'ltr', text: u.expiry || t('unlimited') })]),
    h('div', { class: 'kv' }, [h('span', { class: 'muted', text: t('traffic') + ': ' }), h('span', { class: 'ltr', text: traffic })]),
    h('div', { class: 'row' }, [
      btn(t('copy'), 'sm', function () { copyText(u.uuid); }),
      btn(t('edit'), 'sm', function () { editUser(u); }),
      btn(u.enabled ? t('disabled') : t('enabled'), 'sm', function () {
        act('PUT', '/api/users/' + u.id, { enabled: !u.enabled }, 'saved').then(function () { EX = null; render(); });
      }),
      btn(t('del'), 'bad sm', function () {
        confirmBox(t('userDeleteConfirm')).then(function (yes) {
          if (!yes) return;
          act('DELETE', '/api/users/' + u.id, undefined, 'deleted').then(function () { EX = null; render(); });
        });
      })
    ])
  ]);
}

function viewUsers() {
  var box = h('div');
  box.appendChild(h('div', { class: 'bar' }, [h('h2', { text: t('usersTitle') }), btn(t('addUser'), 'pri sm', function () { editUser(null); })]));
  box.appendChild(h('p', { class: 'note', text: t('userNote') }));
  if (!S.users.length) box.appendChild(h('div', { class: 'card muted', text: t('noUsers') }));
  S.users.forEach(function (u) { box.appendChild(userCard(u)); });
  return box;
}

/* ----- clean IPs and proxy IPs (same item shape) ----- */
function listPath(kind) {
  return kind === 'ips' ? '/api/ips' : '/api/proxyips';
}

function editAddr(kind, item) {
  var isNew = !item;
  var vals = isNew ? { address: '', port: '', remark: '', enabled: true } : { address: item.address, port: item.port || '', remark: item.remark, enabled: item.enabled };
  var fields = [
    { k: 'address', label: t('ipAddress'), ltr: true },
    { k: 'port', label: t('portOverride'), type: 'number', ltr: true, min: '1' },
    { k: 'remark', label: t('remark') },
    { k: 'enabled', label: t('enabled'), type: 'checkbox' }
  ];
  formModal(isNew ? t(kind === 'ips' ? 'addIp' : 'addProxy') : t('edit'), fields, vals, null, function (out) {
    return act(isNew ? 'POST' : 'PUT', isNew ? listPath(kind) : listPath(kind) + '/' + item.id, out, 'saved').then(function (r) {
      if (r && r.ok) { EX = null; render(); }
      return !!(r && (r.ok || r.status === 401));
    });
  });
}

function bulkAdd() {
  var fields = [{ k: 'bulk', label: t('ipAddress'), type: 'textarea', ltr: true, rows: 9, hint: t('bulkHint'), ph: '104.16.1.1\n104.17.2.2:2053#my-remark' }];
  formModal(t('bulkTitle'), fields, { bulk: '' }, t('add'), function (out) {
    return act('POST', '/api/ips', { bulk: out.bulk }).then(function (r) {
      if (r && r.ok) { toast(tf('bulkResult', r.result || {}), 'ok'); EX = null; render(); }
      return !!(r && (r.ok || r.status === 401));
    });
  });
}

function deleteAll(kind) {
  confirmBox(t('confirmDeleteAll')).then(function (yes) {
    if (!yes) return;
    act('DELETE', listPath(kind), undefined, 'deleted').then(function () { EX = null; render(); });
  });
}

function addrRow(kind, item) {
  var label = item.address + (item.port ? ':' + item.port : '');
  var sw = h('input', {
    type: 'checkbox',
    checked: item.enabled,
    onchange: function (e) {
      act('PUT', listPath(kind) + '/' + item.id, { enabled: e.target.checked }).then(function () { EX = null; render(); });
    }
  });
  return h('div', { class: 'item' }, [
    h('label', { class: 'sw' }, [sw, h('span', { class: 'sl' })]),
    h('div', { class: 'grow' }, [h('div', { class: 'ltr strong clip', text: label }), item.remark ? h('div', { class: 'muted small', text: item.remark }) : null]),
    h('div', { class: 'row nowrap' }, [
      btn(t('edit'), 'sm', function () { editAddr(kind, item); }),
      btn(t('del'), 'bad sm', function () {
        confirmBox(t('confirmDelete')).then(function (yes) {
          if (!yes) return;
          act('DELETE', listPath(kind) + '/' + item.id, undefined, 'deleted').then(function () { EX = null; render(); });
        });
      })
    ])
  ]);
}

function viewIps() {
  var box = h('div');
  box.appendChild(h('div', { class: 'bar' }, [
    h('h2', { text: t('ipsTitle') }),
    h('div', { class: 'row' }, [
      btn(t('add'), 'pri sm', function () { editAddr('ips', null); }),
      btn(t('bulkAdd'), 'sm', bulkAdd),
      btn(t('deleteAll'), 'bad sm', function () { deleteAll('ips'); })
    ])
  ]));
  box.appendChild(h('p', { class: 'note', text: t('ipNote') }));
  if (!S.ips.length) box.appendChild(h('div', { class: 'card muted', text: t('noIps') }));
  S.ips.forEach(function (ip) { box.appendChild(addrRow('ips', ip)); });
  return box;
}

function viewProxy() {
  var box = h('div');
  var sel = h('select', { value: S.settings.proxyMode }, [['fallback', 'modeFallback'], ['always', 'modeAlways'], ['off', 'modeOff']].map(function (m) {
    return h('option', { value: m[0], text: t(m[1]) });
  }));
  box.appendChild(h('div', { class: 'card' }, [
    h('h2', { text: t('proxyTitle') }),
    h('p', { class: 'note', text: t('proxyNote') }),
    h('label', { class: 'fld' }, [h('span', { class: 'lbl', text: t('proxyMode') }), sel]),
    S.envProxy ? h('p', { class: 'note', text: t('proxyEnv') }) : null,
    h('div', { class: 'row' }, [
      btn(t('apply'), 'pri', function () {
        act('POST', '/api/settings', { settings: { proxyMode: sel.value } }, 'saved').then(function () { render(); });
      }),
      btn(t('addProxy'), '', function () { editAddr('proxyIps', null); }),
      S.proxyIps.length ? btn(t('deleteAll'), 'bad', function () { deleteAll('proxyIps'); }) : null
    ])
  ]));
  if (!S.proxyIps.length) box.appendChild(h('div', { class: 'card muted', text: t('noProxy') }));
  S.proxyIps.forEach(function (p) { box.appendChild(addrRow('proxyIps', p)); });
  return box;
}

/* ----- settings ----- */
function portBoxes(list, selected) {
  var boxes = list.map(function (p) {
    return h('input', { type: 'checkbox', checked: selected.indexOf(p) >= 0 });
  });
  var wrap = h('div', { class: 'ports ltr' }, boxes.map(function (el, i) {
    return h('label', { class: 'chk port' }, [el, h('span', { text: String(list[i]) })]);
  }));
  return {
    wrap: wrap,
    get: function () {
      return list.filter(function (_p, i) { return boxes[i].checked; });
    }
  };
}

function viewSettings() {
  var s = S.settings;
  var c = S.consts;
  var f = {};
  function txt(key, val, ltr, ph) {
    var el = h('input', { type: 'text', value: val === undefined || val === null ? '' : String(val), dir: ltr ? 'ltr' : null, placeholder: ph || null, autocomplete: 'off' });
    f[key] = el;
    return el;
  }
  function chk(key, val) {
    var el = h('input', { type: 'checkbox', checked: !!val });
    f[key] = el;
    return el;
  }
  function fld(label, el, hint) {
    return h('label', { class: 'fld' }, [h('span', { class: 'lbl', text: label }), el, hint ? h('small', { class: 'muted', text: hint }) : null]);
  }
  function cb(label, el) {
    return h('label', { class: 'chk' }, [el, h('span', { text: label })]);
  }

  var tlsBox = portBoxes(c.tlsPorts, s.tlsPorts);
  var plainBox = portBoxes(c.plainPorts, s.plainPorts);
  var fpSel = h('select', { value: s.fingerprint }, c.fingerprints.map(function (x) { return h('option', { value: x, text: x }); }));
  f.fingerprint = fpSel;
  var presetSel = h('select', { value: s.fragment.preset }, [['light', 'presetLight'], ['medium', 'presetMedium'], ['strong', 'presetStrong'], ['custom', 'presetCustom']].map(function (p) {
    return h('option', { value: p[0], text: t(p[1]) });
  }));
  f.fragPreset = presetSel;
  var pathInput = txt('wsPath', s.wsPath, true, '/ws');
  var packets = txt('fragPackets', s.fragment.packets, true);
  var length = txt('fragLength', s.fragment.length, true);
  var interval = txt('fragInterval', s.fragment.interval, true);
  presetSel.addEventListener('change', function () {
    var p = c.presets[presetSel.value];
    if (p) { packets.value = p.packets; length.value = p.length; interval.value = p.interval; }
  });
  [packets, length, interval].forEach(function (el) {
    el.addEventListener('input', function () { presetSel.value = 'custom'; });
  });

  function apply() {
    var body = {
      host: f.host.value,
      wsPath: f.wsPath.value,
      earlyData: f.earlyData.value,
      fingerprint: f.fingerprint.value,
      remarkPrefix: f.remarkPrefix.value,
      includeHost: f.includeHost.checked,
      tlsPorts: tlsBox.get(),
      plainPorts: plainBox.get(),
      dns: { remote: f.dnsRemote.value, direct: f.dnsDirect.value },
      fragment: { enabled: f.fragEnabled.checked, preset: f.fragPreset.value, packets: f.fragPackets.value, length: f.fragLength.value, interval: f.fragInterval.value },
      block: { ads: f.ads.checked, porn: f.porn.checked, security: f.security.checked, useDns: f.useDns.checked }
    };
    act('POST', '/api/settings', { settings: body }, 'saved').then(function (r) {
      if (r && r.ok) { EX = null; render(); }
    });
  }

  return h('div', null, [
    h('div', { class: 'card' }, [
      h('h2', { text: t('secConn') }),
      fld(t('host'), txt('host', s.host, true, S.host), t('hostHint')),
      h('div', { class: 'fld' }, [h('span', { class: 'lbl', text: t('wsPath') }), h('div', { class: 'row nowrap' }, [pathInput, btn(t('randomize'), 'sm', function () { pathInput.value = '/' + randId(10); })])]),
      fld(t('earlyData'), txt('earlyData', s.earlyData, true)),
      fld(t('fingerprint'), fpSel),
      fld(t('remarkPrefix'), txt('remarkPrefix', s.remarkPrefix, true)),
      cb(t('includeHost'), chk('includeHost', s.includeHost))
    ]),
    h('div', { class: 'card' }, [
      h('h2', { text: t('secPorts') }),
      h('p', { class: 'note', text: t('portsHint') }),
      h('div', { class: 'lbl', text: t('tlsPorts') }), tlsBox.wrap,
      h('div', { class: 'lbl', text: t('plainPorts') }), plainBox.wrap
    ]),
    h('div', { class: 'card' }, [
      h('h2', { text: t('secDns') }),
      fld(t('dnsRemote'), txt('dnsRemote', s.dns.remote, true)),
      fld(t('dnsDirect'), txt('dnsDirect', s.dns.direct, true)),
      h('div', { class: 'kv' }, [h('span', { class: 'muted', text: t('dnsEffective') + ' ' }), h('span', { class: 'ltr mono', text: S.effectiveDns })]),
      h('p', { class: 'note', text: t('dnsHint') })
    ]),
    h('div', { class: 'card' }, [
      h('h2', { text: t('secFrag') }),
      cb(t('fragEnabled'), chk('fragEnabled', s.fragment.enabled)),
      fld(t('fragPreset'), presetSel),
      fld(t('fragPackets'), packets),
      fld(t('fragLength'), length),
      fld(t('fragInterval'), interval),
      h('p', { class: 'note', text: t('fragHint') })
    ]),
    h('div', { class: 'card' }, [
      h('h2', { text: t('secBlock') }),
      cb(t('blockAds'), chk('ads', s.block.ads)),
      cb(t('blockPorn'), chk('porn', s.block.porn)),
      cb(t('blockSecurity'), chk('security', s.block.security)),
      cb(t('blockDns'), chk('useDns', s.block.useDns)),
      h('p', { class: 'note', text: t('blockHint') })
    ]),
    h('div', { class: 'row sticky' }, [btn(t('applySettings'), 'pri', apply)])
  ]);
}

/* ----- export ----- */
function loadExport() {
  var id = exUser;
  if (exBusy === id) return;
  exBusy = id;
  api('GET', '/api/export?user=' + encodeURIComponent(id)).then(function (r) {
    exBusy = '';
    if (r.status === 401) { boot.authed = false; S = null; render(); return; }
    EX = r.ok ? { user: id, data: r.data } : { user: id, error: r.error || 'generic' };
    if (tab === 'export') render();
  });
}

function linkCard(title, hint, url, extra) {
  var inp = h('input', { type: 'text', readonly: true, value: url, dir: 'ltr', class: 'mono' });
  inp.addEventListener('focus', function () { inp.select(); });
  return h('div', { class: 'card' }, [
    h('h3', { text: title }),
    h('p', { class: 'note', text: hint }),
    inp,
    h('div', { class: 'row' }, [
      btn(t('copy'), 'pri sm', function () { copyText(url); }),
      btn(t('qr'), 'sm', function () { showQR(url, title); })
    ].concat(extra || []))
  ]);
}

function viewExport() {
  var box = h('div');
  box.appendChild(h('h2', { text: t('expTitle') }));
  if (!S.users.length) { box.appendChild(h('div', { class: 'card muted', text: t('noUsers') })); return box; }
  var found = false;
  S.users.forEach(function (u) { if (u.id === exUser) found = true; });
  if (!found) exUser = S.users[0].id;
  var sel = h('select', { value: exUser, onchange: function () { exUser = sel.value; EX = null; render(); } }, S.users.map(function (u) {
    return h('option', { value: u.id, text: u.name || u.uuid.slice(0, 8) });
  }));
  box.appendChild(h('label', { class: 'fld' }, [h('span', { class: 'lbl', text: t('expUser') }), sel]));
  if (!EX || EX.user !== exUser) {
    loadExport();
    box.appendChild(h('div', { class: 'card muted', text: t('loading') }));
    return box;
  }
  if (EX.error) { box.appendChild(h('div', { class: 'card warn', text: errText(EX.error) })); return box; }
  var d = EX.data;
  var regen = btn(t('regen'), 'sm', function () {
    confirmAction(t('regenConfirm')).then(function (yes) {
      if (!yes) return;
      act('POST', '/api/users/' + exUser + '/token', {}, 'regenDone').then(function () { EX = null; render(); });
    });
  });
  box.appendChild(linkCard(t('subTitle'), t('subHint'), d.sub, [regen]));
  box.appendChild(linkCard(t('xrayTitle'), t('xrayHint'), d.xray));
  var raw = d.raw;
  var rawCard = h('div', { class: 'card' }, [
    h('div', { class: 'bar' }, [h('h3', { text: t('rawTitle') }), h('span', { class: 'muted', text: tf('linksCount', { n: raw.length }) })]),
    h('p', { class: 'note', text: raw.length ? t('rawHint') : t('noLinks') }),
    raw.length ? btn(t('copyAll'), 'pri sm', function () { copyText(raw.map(function (x) { return x.uri; }).join('\n')); }) : null
  ]);
  raw.forEach(function (x) {
    rawCard.appendChild(h('div', { class: 'item' }, [
      h('div', { class: 'grow' }, [h('div', { class: 'ltr strong clip', text: x.remark }), h('div', { class: 'ltr mono small clip', text: x.uri })]),
      h('div', { class: 'row nowrap' }, [
        btn(t('copy'), 'sm', function () { copyText(x.uri); }),
        btn(t('qr'), 'sm', function () { showQR(x.uri, x.remark); })
      ])
    ]));
  });
  box.appendChild(rawCard);
  return box;
}

function viewHelp() {
  var box = h('div');
  box.appendChild(h('h2', { text: t('helpTitle') }));
  [['h1t', 'h1'], ['h2t', 'h2'], ['h3t', 'h3'], ['h4t', 'h4'], ['h5t', 'h5']].forEach(function (p) {
    box.appendChild(h('div', { class: 'card' }, [h('h3', { text: t(p[0]) }), h('p', { text: t(p[1]) })]));
  });
  return box;
}

/* ---------------- shell ---------------- */
var TABS = [
  ['home', 'tabHome', '🏠'],
  ['users', 'tabUsers', '👥'],
  ['ips', 'tabIps', '🌐'],
  ['proxy', 'tabProxy', '🛡️'],
  ['settings', 'tabSettings', '⚙️'],
  ['export', 'tabExport', '📤'],
  ['help', 'tabHelp', '❓']
];

function tabsNav() {
  return h('nav', { class: 'tabs' }, TABS.map(function (x) {
    return h('button', {
      type: 'button',
      class: 'tab' + (tab === x[0] ? ' on' : ''),
      onclick: function () { tab = x[0]; render(); window.scrollTo(0, 0); },
      text: x[2] + ' ' + t(x[1])
    });
  }));
}

function viewTab() {
  if (tab === 'users') return viewUsers();
  if (tab === 'ips') return viewIps();
  if (tab === 'proxy') return viewProxy();
  if (tab === 'settings') return viewSettings();
  if (tab === 'export') return viewExport();
  if (tab === 'help') return viewHelp();
  return viewHome();
}

function render() {
  applyLang();
  root.textContent = '';
  root.appendChild(header());
  var main = h('main', { class: 'wrap' });
  if (!boot.hasPass) main.appendChild(viewNoPass());
  else if (!boot.authed) main.appendChild(viewLogin());
  else if (!S) main.appendChild(h('div', { class: 'card muted', text: t('loading') }));
  else {
    main.appendChild(tabsNav());
    main.appendChild(viewTab());
  }
  root.appendChild(main);
}

(function init() {
  var saved = lsGet('lang');
  if (saved === 'fa' || saved === 'en') {
    if (saved !== lang) { lang = saved; setCookie('lang', lang); }
  }
  var th = lsGet('theme');
  if (th === 'dark' || th === 'light') document.documentElement.setAttribute('data-theme', th);
  render();
  if (boot.hasPass && boot.authed) loadState();
})();
`;

/* ------------------------------------------------------------------------------------------------
 * Pages. The panel is a small single page app rendered in the browser (QR_JS and CLIENT_JS below are
 * browser code kept as strings). All user data is inserted with textContent, never as HTML.
 * ---------------------------------------------------------------------------------------------- */
const CSS = `
:root{--bg:#f3f5fa;--card:#fff;--fg:#17203a;--mut:#667394;--bd:#dde3f0;--pri:#2563eb;--inp:#fff;--ok:#15803d;--warn:#b45309;--bad:#dc2626;color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0b1020;--card:#141b2f;--fg:#e8ecf7;--mut:#9aa7c7;--bd:#26304d;--pri:#3b82f6;--inp:#0e1427;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;color-scheme:dark}}
:root[data-theme=dark]{--bg:#0b1020;--card:#141b2f;--fg:#e8ecf7;--mut:#9aa7c7;--bd:#26304d;--pri:#3b82f6;--inp:#0e1427;--ok:#4ade80;--warn:#fbbf24;--bad:#f87171;color-scheme:dark}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font:15px/1.65 system-ui,-apple-system,"Segoe UI","Noto Sans Arabic","Noto Naskh Arabic",Vazirmatn,Tahoma,sans-serif;-webkit-text-size-adjust:100%;min-height:100vh}
button,input,select,textarea{font:inherit;color:inherit}
a{color:var(--pri)}
h1{font-size:24px;margin:8px 0}
h2{font-size:19px;margin:4px 0 8px}
h3{font-size:16px;margin:4px 0 6px}
p{margin:6px 0}
.top{position:sticky;top:0;z-index:20;display:flex;align-items:center;justify-content:space-between;gap:8px;padding:10px 14px;background:var(--card);border-bottom:1px solid var(--bd)}
.brand{font-weight:700;font-size:17px}
.acts{display:flex;gap:6px;align-items:center}
.wrap{max-width:760px;margin:0 auto;padding:12px 12px 90px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:14px;margin:10px 0}
.card.ok{border-inline-start:4px solid var(--ok)}
.card.warn{border-inline-start:4px solid var(--warn)}
.btn{border:1px solid var(--bd);background:var(--card);border-radius:10px;padding:9px 14px;cursor:pointer;min-height:40px}
.btn.pri{background:var(--pri);border-color:var(--pri);color:#fff}
.btn.bad{color:var(--bad);border-color:var(--bad)}
.btn.sm{padding:6px 10px;min-height:34px;font-size:14px}
input[type=text],input[type=number],input[type=date],input[type=password],select,textarea{width:100%;background:var(--inp);border:1px solid var(--bd);border-radius:10px;padding:9px 11px}
input[type=checkbox]{width:20px;height:20px;accent-color:var(--pri);flex:0 0 auto}
.fld{display:block;margin:10px 0}
.lbl{display:block;font-size:13px;color:var(--mut);margin:6px 0 4px}
.chk{display:flex;align-items:center;gap:8px;margin:8px 0}
.ports{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0 12px}
.port{margin:0;padding:6px 10px;border:1px solid var(--bd);border-radius:10px}
.row{display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin:8px 0}
.nowrap{flex-wrap:nowrap}
.bar{display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap}
.item{display:flex;align-items:center;gap:10px;background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:10px 12px;margin:8px 0}
.grow{flex:1;min-width:0}
.clip{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.badge{font-size:12px;padding:2px 8px;border-radius:999px;border:1px solid currentColor}
.badge.ok{color:var(--ok)}
.badge.bad{color:var(--bad)}
.stats{display:grid;grid-template-columns:repeat(2,1fr);gap:10px;margin:10px 0}
.stat{background:var(--card);border:1px solid var(--bd);border-radius:14px;padding:12px;text-align:center}
.num{font-size:26px;font-weight:700}
.tabs{display:flex;gap:6px;overflow-x:auto;padding:4px 0 10px;scrollbar-width:none}
.tab{flex:0 0 auto;border:1px solid var(--bd);background:var(--card);border-radius:999px;padding:7px 14px;cursor:pointer;white-space:nowrap}
.tab.on{background:var(--pri);color:#fff;border-color:var(--pri)}
.ltr{direction:ltr;unicode-bidi:isolate;text-align:left}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
.small{font-size:12px}
.strong{font-weight:600}
.muted{color:var(--mut)}
.note{color:var(--mut);font-size:13px;margin:6px 0}
.steps{margin:8px 0;padding-inline-start:20px}
.steps li{margin:6px 0}
.kv{margin:4px 0;word-break:break-all}
.sw{position:relative;display:inline-block;width:44px;height:26px;flex:0 0 auto}
.sw input{opacity:0;width:0;height:0;position:absolute}
.sl{position:absolute;inset:0;background:var(--bd);border-radius:999px;transition:.2s;cursor:pointer}
.sl:before{content:"";position:absolute;height:20px;width:20px;inset-inline-start:3px;top:3px;background:#fff;border-radius:50%;transition:.2s}
.sw input:checked+.sl{background:var(--ok)}
.sw input:checked+.sl:before{inset-inline-start:21px}
.ov{position:fixed;inset:0;background:rgba(0,0,0,.5);display:flex;align-items:flex-end;justify-content:center;z-index:50}
@media (min-width:600px){.ov{align-items:center}}
.dlg{background:var(--card);width:100%;max-width:520px;max-height:90vh;overflow:auto;border-radius:18px 18px 0 0;padding:16px}
@media (min-width:600px){.dlg{border-radius:18px}}
.drow{display:flex;gap:8px;justify-content:flex-end;margin-top:12px}
.toast{position:fixed;left:50%;bottom:22px;transform:translateX(-50%);background:#111827;color:#fff;padding:10px 16px;border-radius:12px;opacity:0;pointer-events:none;transition:opacity .25s;z-index:60;max-width:90vw;text-align:center}
.toast.show{opacity:1}
.toast.ok{background:#166534}
.toast.bad{background:#991b1b}
.toast.warn{background:#92400e}
.qrbox{display:flex;justify-content:center;padding:8px}
.qr{max-width:100%;height:auto;image-rendering:pixelated;background:#fff}
.hid{position:fixed;opacity:0;pointer-events:none;left:-999px}
.login{max-width:420px;margin:30px auto}
.sticky{position:sticky;bottom:10px;background:var(--bg);padding:8px 0;justify-content:center}
.root{max-width:520px;margin:18vh auto 0;padding:0 18px;text-align:center}
`;

function pageHead(lang, theme, title, viewport) {
  return (
    '<!doctype html><html lang="' + lang + '" dir="' + (lang === 'fa' ? 'rtl' : 'ltr') + '"' +
    (theme ? ' data-theme="' + theme + '"' : '') +
    '><head><meta charset="utf-8"><meta name="viewport" content="' + viewport + '">' +
    '<meta name="robots" content="noindex,nofollow"><meta name="color-scheme" content="light dark">' +
    '<title>' + esc(title) + '</title><style>' + CSS + '</style></head>'
  );
}

const STATIC_CSP = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'";

// Harmless public page (translated). The language link sets the "lang" cookie.
function rootPage(lang, theme) {
  const other = lang === 'fa' ? 'en' : 'fa';
  return (
    pageHead(lang, theme, tr(lang, 'rootTitle'), 'width=device-width,initial-scale=1') +
    '<body><main class="root"><h1>' + esc(tr(lang, 'rootTitle')) + '</h1><p class="muted">' + esc(tr(lang, 'rootText')) +
    '</p><p><a href="/?lang=' + other + '">' + esc(tr(lang, 'switchLang')) + '</a></p></main></body></html>'
  );
}

function messagePage(lang, theme, text, status) {
  const body =
    pageHead(lang, theme, text, 'width=device-width,initial-scale=1') +
    '<body><main class="root"><h1>' + esc(text) + '</h1><p><a href="/">' + esc(tr(lang, 'rootTitle')) + '</a></p></main></body></html>';
  return htmlResponse(body, status, { 'content-security-policy': STATIC_CSP });
}

const notFoundPage = (lang, theme) => messagePage(lang, theme || '', tr(lang, 'notFound'), 404);
const errorPage = (lang, theme) => messagePage(lang, theme || '', tr(lang, 'serverError'), 500);

const panelCsp = (nonce) =>
  "default-src 'none'; script-src 'nonce-" + nonce + "'; style-src 'unsafe-inline'; img-src data:; connect-src 'self'; " +
  "base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

function shellPage(lang, theme, boot, nonce) {
  return (
    pageHead(lang, theme, tr(lang, 'appName'), 'width=device-width,initial-scale=1,viewport-fit=cover') +
    '<body><div id="app"></div><noscript><p style="padding:16px">' + esc(I18N.en.noscript) + '<br>' + esc(I18N.fa.noscript) +
    '</p></noscript><script id="boot" type="application/json">' + safeJson(boot) + '</script>' +
    '<script nonce="' + nonce + '">(function(){\'use strict\';' + QR_JS + CLIENT_JS + '})();</script></body></html>'
  );
}

/* ------------------------------------------------------------------------------------------------
 * Panel API (JSON). Every route except /api/login needs the signed session cookie and, for writes, the
 * "x-panel: 1" header (a simple CSRF guard). All errors are returned as { ok:false, error:<code> };
 * the browser translates the code, so no hard-coded message leaves the server.
 * ---------------------------------------------------------------------------------------------- */
async function readJson(request) {
  const txt = await request.text();
  if (txt.length > 300000) throw new VErr('bad_json');
  if (txt.trim() === '') return {};
  try {
    const v = JSON.parse(txt);
    return v && typeof v === 'object' && !Array.isArray(v) ? v : {};
  } catch {
    throw new VErr('bad_json');
  }
}

async function buildState(env, request, db) {
  const usage = await loadUsage(env);
  const host = new URL(request.url).hostname;
  return {
    settings: db.settings,
    ips: db.ips,
    proxyIps: db.proxyIps,
    users: db.users.map((u) => Object.assign({}, u, { used: Number(usage[u.id]) || 0 })),
    kv: kvStatus(env),
    host,
    envProxy: envProxies(env).length > 0,
    version: VERSION,
    effectiveDns: effectiveDoh(db.settings),
    linksPerUser: targetsOf(db, hostOf(db.settings, host)).length,
    consts: { tlsPorts: TLS_PORTS, plainPorts: PLAIN_PORTS, fingerprints: FINGERPRINTS, presets: FRAG_PRESETS },
  };
}

// kv = result of saveDB(): 'error' adds a warning, the data is still kept in memory.
async function stateReply(env, request, db, extra, kv) {
  const body = Object.assign({ ok: true, state: await buildState(env, request, db) }, extra || {});
  if (kv === 'error') body.warn = 'kv_write';
  return jsonResponse(body);
}

async function apiLogin(request, env) {
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  if (!loginAllowed(ip)) return jsonResponse({ ok: false, error: 'too_many' }, 429);
  const body = await readJson(request);
  if (!(await passwordOk(env, body.password))) {
    loginFailed(ip);
    return jsonResponse({ ok: false, error: 'wrong_password' }, 401);
  }
  LOGIN_FAILS.delete(ip);
  const token = await signSession(env, Math.floor(Date.now() / 1000) + SESSION_TTL);
  return jsonResponse({ ok: true }, 200, { 'set-cookie': cookieStr(request, 'sid', token, SESSION_TTL, true) });
}

// Works on a copy, so a failure half way never leaves a partly changed list behind.
function bulkAddItems(list, text, max) {
  const tokens = String(text || '').split(/[\s,;]+/).filter(Boolean);
  if (!tokens.length) throw new VErr('no_bulk');
  const out = list.slice();
  const seen = new Set(out.map((x) => x.address + '|' + x.port));
  const result = { added: 0, skipped: 0, invalid: 0 };
  for (const tk of tokens) {
    const e = parseEntry(tk);
    if (!e) {
      result.invalid += 1;
      continue;
    }
    const key = e.address + '|' + e.port;
    if (seen.has(key)) {
      result.skipped += 1;
      continue;
    }
    if (out.length >= max) throw new VErr('limit');
    seen.add(key);
    out.push({ id: newId(), address: e.address, port: e.port, remark: e.remark, enabled: true });
    result.added += 1;
  }
  return { list: out, result };
}

async function handleApi(request, env, url) {
  const path = url.pathname;
  const method = request.method;
  if (!env.ADMIN_PASSWORD) return jsonResponse({ ok: false, error: 'no_pass' }, 503);
  if (method !== 'GET' && method !== 'HEAD' && request.headers.get('x-panel') !== '1') {
    return jsonResponse({ ok: false, error: 'forbidden' }, 403);
  }
  if (path === '/api/login') {
    if (method !== 'POST') return jsonResponse({ ok: false, error: 'forbidden' }, 405);
    return apiLogin(request, env);
  }
  if (!(await isAuthed(request, env))) return jsonResponse({ ok: false, error: 'unauthorized' }, 401);
  if (path === '/api/logout' && method === 'POST') {
    return jsonResponse({ ok: true }, 200, { 'set-cookie': cookieStr(request, 'sid', '', 0, true) });
  }

  const db = await loadDB(env);

  if (path === '/api/state' && method === 'GET') {
    // First run with a working KV: create the first user automatically.
    if (!db.users.length && kvStatus(env) === 'ok') {
      db.users.push(newUser(cleanUserInput({ name: 'user1' }, db.users, null)));
      await saveDB(env, db);
    }
    return stateReply(env, request, db);
  }

  if (path === '/api/export' && method === 'GET') {
    const id = url.searchParams.get('user') || '';
    const user = db.users.find((u) => u.id === id) || db.users[0];
    if (!user) throw new VErr('not_found');
    const host = hostOf(db.settings, url.hostname);
    const base = url.origin + '/sub/' + user.token;
    return jsonResponse({
      ok: true,
      data: { user: user.id, sub: base, xray: base + '?format=xray', raw: buildLinks(db, user, host) },
    });
  }

  if (path === '/api/settings' && method === 'POST') {
    const body = await readJson(request);
    db.settings = cleanSettings(body.settings, db.settings, true);
    return stateReply(env, request, db, null, await saveDB(env, db));
  }

  const mu = path.match(/^\/api\/users(?:\/([\w-]{1,32})(\/token)?)?$/);
  if (mu) {
    const id = mu[1] || '';
    if (!id && method === 'POST') {
      if (db.users.length >= MAX_ITEMS.users) throw new VErr('limit');
      db.users.push(newUser(cleanUserInput(await readJson(request), db.users, null)));
      return stateReply(env, request, db, null, await saveDB(env, db));
    }
    const self = id ? db.users.find((u) => u.id === id) : null;
    if (!self) throw new VErr('not_found');
    if (mu[2] && method === 'POST') {
      self.token = newToken();
      return stateReply(env, request, db, null, await saveDB(env, db));
    }
    if (method === 'PUT') {
      const body = await readJson(request);
      const merged = Object.assign(
        {
          name: self.name,
          uuid: self.uuid,
          expiry: self.expiry,
          limitGb: self.limitBytes > 0 ? self.limitBytes / 1073741824 : '',
          enabled: self.enabled,
        },
        body
      );
      Object.assign(self, cleanUserInput(merged, db.users, self));
      if (body.resetUsage === true) await resetUsage(env, self.id);
      return stateReply(env, request, db, null, await saveDB(env, db));
    }
    if (method === 'DELETE') {
      db.users = db.users.filter((u) => u.id !== id);
      await dropUsage(env, id);
      return stateReply(env, request, db, null, await saveDB(env, db));
    }
  }

  const ml = path.match(/^\/api\/(ips|proxyips)(?:\/([\w-]{1,32}))?$/);
  if (ml) {
    const key = ml[1] === 'ips' ? 'ips' : 'proxyIps';
    const max = MAX_ITEMS[key];
    const id = ml[2] || '';
    if (!id && method === 'POST') {
      const body = await readJson(request);
      let extra = null;
      if (key === 'ips' && typeof body.bulk === 'string') {
        const r = bulkAddItems(db[key], body.bulk, max);
        db[key] = r.list;
        extra = { result: r.result };
      } else {
        if (db[key].length >= max) throw new VErr('limit');
        db[key] = db[key].concat([Object.assign({ id: newId() }, cleanAddrItem(body))]);
      }
      return stateReply(env, request, db, extra, await saveDB(env, db));
    }
    if (!id && method === 'DELETE') {
      db[key] = [];
      return stateReply(env, request, db, null, await saveDB(env, db));
    }
    if (id) {
      const self = db[key].find((x) => x.id === id);
      if (!self) throw new VErr('not_found');
      if (method === 'PUT') {
        const body = await readJson(request);
        const merged = Object.assign(
          { address: self.address, port: self.port || '', remark: self.remark, enabled: self.enabled },
          body
        );
        Object.assign(self, cleanAddrItem(merged));
        return stateReply(env, request, db, null, await saveDB(env, db));
      }
      if (method === 'DELETE') {
        db[key] = db[key].filter((x) => x.id !== id);
        return stateReply(env, request, db, null, await saveDB(env, db));
      }
    }
  }

  throw new VErr('not_found');
}

async function apiEntry(request, env, url) {
  try {
    return await handleApi(request, env, url);
  } catch (e) {
    if (e instanceof VErr) return jsonResponse({ ok: false, error: e.code }, e.code === 'not_found' ? 404 : 400);
    return jsonResponse({ ok: false, error: 'generic' }, 500);
  }
}

/* ------------------------------ subscription ------------------------------ */
async function handleSub(env, url, token, lang) {
  const db = await loadDB(env);
  const user = db.users.find((u) => u.token === token);
  if (!user) return textResponse(tr(lang, 'notFound'), 404);
  const used = user.limitBytes > 0 ? Number((await loadUsage(env))[user.id]) || 0 : 0;
  const headers = { 'profile-update-interval': '6' };
  const info = userinfoHeader(user, used);
  if (info) headers['subscription-userinfo'] = info;
  // A disabled, expired or over-limit user gets an empty subscription.
  if (userStatus(user, used) !== 'ok') return textResponse('', 200, headers);
  const out = subscriptionBody(url.searchParams.get('format'), db, user, hostOf(db.settings, url.hostname));
  return new Response(out.body, {
    status: 200,
    headers: Object.assign({ 'content-type': out.type, 'cache-control': 'no-store' }, headers),
  });
}

/* ------------------------------ router ------------------------------ */
async function route(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const lang = pickLang(request, url);
  const theme = pickTheme(request);

  // WebSocket upgrade: the VLESS endpoint (only on the configured path).
  if ((request.headers.get('upgrade') || '').toLowerCase() === 'websocket') {
    const res = await wsEntry(request, env, url);
    return res || notFoundPage(lang, theme);
  }

  if (path === '/') {
    const extra = { 'content-security-policy': STATIC_CSP };
    const q = url.searchParams.get('lang');
    if (q === 'fa' || q === 'en') extra['set-cookie'] = cookieStr(request, 'lang', q, 31536000, false);
    return htmlResponse(rootPage(lang, theme), 200, extra);
  }

  if (path === '/panel' || path === '/panel/') {
    const hasPass = !!env.ADMIN_PASSWORD;
    const authed = hasPass && (await isAuthed(request, env));
    const nonce = b64url(rndBytes(16));
    const html = shellPage(lang, theme, { lang, hasPass, authed, i18n: I18N }, nonce);
    return htmlResponse(html, 200, { 'content-security-policy': panelCsp(nonce) });
  }

  if (path.startsWith('/api/')) return apiEntry(request, env, url);

  const ms = path.match(/^\/sub\/([A-Za-z0-9_-]{8,128})\/?$/);
  if (ms) return handleSub(env, url, ms[1], lang);

  return notFoundPage(lang, theme);
}

// Nothing in here may throw: an uncaught exception would show Cloudflare Error 1101.
export default {
  async fetch(request, env) {
    try {
      return await route(request, env || {});
    } catch {
      try {
        return errorPage(pickLang(request, null), '');
      } catch {
        return new Response('Error', { status: 500 });
      }
    }
  },
};
