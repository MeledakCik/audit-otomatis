/**
 * Permukaan RCE, Shell-Escalation (wp2shell, php2shell, node2shell, go2shell, py2shell)
 * & Node Out-of-Bounds / Memory Surface PASIF:
 * Endpoint diagnostik/debug/runtime yang membuka jalur eksekusi kode atau kebocoran memori bila terekspos.
 * 100% GET-only, tanpa payload eksploitasi. Temuan hanya dibuat jika ISI respons cocok dengan penanda spesifik (true-positive validated).
 */
import type { Finding, FindingCategory, Severity } from "@/lib/types";
import { chromeHeaders, detectCloudflareChallenge } from "@/lib/crawler";
import type { RequestBudget } from "@/lib/rate-limit";
import type { RceSurfaceEvidence } from "@/lib/sentinel/dossier";

export type ShellVector =
  | "wp2shell"
  | "php2shell"
  | "node2shell"
  | "go2shell"
  | "py2shell"
  | "node-oob"
  | "rce-surface";

export interface Spec {
  path: string;
  vector: ShellVector;
  title: string;
  cwe: string[];
  cve?: string[];
  rce: boolean;
  /** return severity bila cocok, null jika bukan true positive */
  validate: (body: string, ct: string, status?: number) => Severity | null;
  marker: string;
  impact: string;
  fix: string;
}

const html = (ct: string) => ct.includes("html");
const json = (ct: string, b: string) => ct.includes("json") || /^\s*[{[]/.test(b);
const notHtml = (ct: string, b: string) =>
  !ct.includes("html") && !/<(!doctype|html|head|body)\b/i.test(b.slice(0, 600));

export const RCE_SPECS: Spec[] = [
  // ==================== 1. wp2shell (WordPress Shell-Escalation & Debug Surface) ====================
  {
    path: "/wp-content/debug.log",
    vector: "wp2shell",
    title: "[wp2shell] WordPress debug.log terbuka di publik",
    cwe: ["CWE-532", "CWE-209"],
    rce: false,
    marker: "PHP Notice/Warning/Fatal in /wp-",
    validate: (b, ct) =>
      notHtml(ct, b) &&
      /\[\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\s+UTC\]\s+PHP\s+(?:Notice|Warning|Fatal error|Deprecated|Parse error)/i.test(b)
        ? "HIGH"
        : null,
    impact:
      "Log debug WordPress membocorkan path absolut server, query database, nonce/token, dan celah plugin/theme yang dapat dirangkai menjadi eskalasi wp2shell.",
    fix: "Nonaktifkan WP_DEBUG_LOG di production, hapus /wp-content/debug.log, dan blokir akses *.log di konfigurasi web server.",
  },
  {
    path: "/wp-json/wp/v2/users",
    vector: "wp2shell",
    title: "[wp2shell] WordPress REST API User Enumeration terbuka",
    cwe: ["CWE-200", "CWE-284"],
    rce: false,
    marker: "wp/v2/users slug & id",
    validate: (b, ct) =>
      json(ct, b) && /"slug"\s*:\s*"[^"]+"/.test(b) && /"avatar_urls"\s*:/.test(b) ? "MEDIUM" : null,
    impact:
      "Daftar akun administrator/author WordPress terekspos tanpa autentikasi, memudahkan credential stuffing menuju pengambilalihan wp-admin & injeksi plugin/theme (wp2shell).",
    fix: "Batasi endpoint /wp-json/wp/v2/users hanya untuk pengguna terautentikasi dan aktifkan 2FA pada seluruh akun administrator.",
  },
  {
    path: "/xmlrpc.php",
    vector: "wp2shell",
    title: "[wp2shell] WordPress XML-RPC interface aktif",
    cwe: ["CWE-307", "CWE-918"],
    rce: false,
    marker: "XML-RPC server accepts POST requests only",
    validate: (b, _ct, st) =>
      (st === 200 || st === 405) && /XML-RPC server accepts POST requests only/i.test(b) ? "MEDIUM" : null,
    impact:
      "Antarmuka xmlrpc.php aktif dapat disalahgunakan untuk brute-force terdistribusi (system.multicall) dan pingback SSRF sebagai batu loncatan kompromi wp2shell.",
    fix: "Blokir akses ke /xmlrpc.php di level WAF/Nginx atau matikan melalui filter xmlrpc_enabled jika tidak diperlukan.",
  },
  {
    path: "/wp-admin/install.php",
    vector: "wp2shell",
    title: "[wp2shell] WordPress Installer / Setup terbuka",
    cwe: ["CWE-306", "CWE-434"],
    rce: true,
    marker: "WordPress installation form",
    validate: (b, ct) =>
      html(ct) &&
      /<title>[^<]*WordPress\s*&rsaquo;\s*Installation/i.test(b) &&
      /weblog_title|admin_password/i.test(b)
        ? "CRITICAL"
        : null,
    impact:
      "Halaman instalasi WordPress yang belum terkunci memungkinkan pihak luar mengambil alih akun admin utama dan mengunggah plugin/theme untuk mengeksekusi kode (wp2shell).",
    fix: "Selesaikan instalasi segera atau blokir akses publik ke /wp-admin/install.php dan /wp-admin/setup-config.php.",
  },
  {
    path: "/wp-content/uploads/",
    vector: "wp2shell",
    title: "[wp2shell] Directory listing terbuka pada /wp-content/uploads/",
    cwe: ["CWE-548", "CWE-434"],
    rce: false,
    marker: "Index of /wp-content/uploads",
    validate: (b, ct) =>
      html(ct) && /<(?:title|h1)>\s*Index of \/wp-content\/uploads/i.test(b) ? "HIGH" : null,
    impact:
      "Indeks direktori uploads terbuka memudahkan penyerang memetakan file sensitif, backup plugin, atau memicu webshell yang terunggah.",
    fix: "Matikan autoindex (Options -Indexes) dan larang eksekusi script PHP di dalam direktori /wp-content/uploads/.",
  },

  // ==================== 2. php2shell (PHP Eval, Ignition, Profiler & Runtime Surface) ====================
  {
    path: "/_ignition/health-check",
    vector: "php2shell",
    title: "[php2shell] Laravel Ignition debug endpoint terbuka",
    cwe: ["CWE-94", "CWE-489"],
    cve: ["CVE-2021-3129"],
    rce: true,
    marker: "can_execute_commands",
    validate: (b, ct) =>
      json(ct, b) && /"can_execute_commands"\s*:\s*true/.test(b)
        ? "CRITICAL"
        : json(ct, b) && /"can_execute_commands"\s*:\s*false/.test(b)
        ? "HIGH"
        : null,
    impact:
      "Laravel Ignition aktif di mode debug. Versi Ignition <= 2.5.1 dapat dieksploitasi untuk Remote Code Execution / php2shell (CVE-2021-3129).",
    fix: "Set APP_DEBUG=false di production, upgrade facade/ignition >= 2.5.2, dan blokir /_ignition/*.",
  },
  {
    path: "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
    vector: "php2shell",
    title: "[php2shell] PHPUnit eval-stdin.php terekspos di webroot",
    cwe: ["CWE-94", "CWE-95"],
    cve: ["CVE-2017-9841"],
    rce: true,
    marker: "phpunit eval-stdin endpoint",
    validate: (b, ct) =>
<<<<<<< HEAD
      !html(ct) && /(?:PHPUnit|eval-stdin\.php|Fatal error.*eval-stdin\.php)/i.test(b)
=======
      !html(ct) &&
      (b.trim() === "" || /eval\(\).*php:\/\/input|PHPUnit|Call Stack/i.test(b)) &&
      ct.includes("text/html") === false
        ? null // hindari false positive jika body kosong tanpa penanda PHPUnit
        : /(?:PHPUnit|eval-stdin\.php|Fatal error.*eval-stdin\.php)/i.test(b)
>>>>>>> bbaddad103ee180657df44c34d5a8762c65b0076
        ? "CRITICAL"
        : null,
    impact:
      "File eval-stdin.php milik PHPUnit di dalam folder vendor yang dapat diakses publik memungkinkan eksekusi kode PHP langsung (CVE-2017-9841 / php2shell).",
    fix: "Hapus dev-dependencies di production (`composer install --no-dev`) dan blokir akses publik ke direktori /vendor/.",
  },
  {
    path: "/_profiler/",
    vector: "php2shell",
    title: "[php2shell] Symfony Web Profiler terbuka",
    cwe: ["CWE-489", "CWE-200"],
    rce: false,
    marker: "Symfony Profiler",
    validate: (b, ct) => (html(ct) && /<title>[^<]*Symfony Profiler[^<]*<\/title>/i.test(b) ? "HIGH" : null),
    impact:
      "Symfony Profiler membocorkan APP_SECRET, environment variables, dan parameter internal yang dapat dipakai menandatangani payload RCE (php2shell).",
    fix: "Nonaktifkan profiler dan pastikan APP_ENV=prod di production.",
  },
  {
    path: "/phpinfo.php",
    vector: "php2shell",
    title: "[php2shell] Diagnostik phpinfo() terbuka di publik",
    cwe: ["CWE-200", "CWE-215"],
    rce: false,
    marker: "PHP Version & Configuration",
    validate: (b, ct) =>
      html(ct) && /<title>[^<]*phpinfo\(\)[^<]*<\/title>/i.test(b) && /PHP Version/i.test(b) ? "HIGH" : null,
    impact:
      "Membocorkan variabel $_ENV/$_SERVER, path dokumen, disable_functions, dan konfigurasi ekstensi PHP yang mempermudah konstruksi rantai php2shell (mis. LFI + phpinfo).",
    fix: "Hapus file phpinfo.php dari server produksi dan batasi fungsi phpinfo() di dalam disable_functions.",
  },
  {
    path: "/fpm-status",
    vector: "php2shell",
    title: "[php2shell] Halaman PHP-FPM Status terbuka",
    cwe: ["CWE-200", "CWE-489"],
    rce: false,
    marker: "pool / process manager / accepted conn",
    validate: (b, ct) =>
      notHtml(ct, b) && /^pool:\s+\S+/m.test(b) && /^process manager:\s+\S+/m.test(b) ? "HIGH" : null,
    impact:
      "Mengekspos status pool PHP-FPM; jika FastCGI port/socket ikut terbuka atau salah dikonfigurasi di Nginx, berisiko dimodifikasi via PHP_VALUE auto_prepend_file (php2shell).",
    fix: "Batasi akses /fpm-status hanya untuk IP internal/localhost di konfigurasi Nginx/Apache.",
  },
  {
    path: "/composer.json",
    vector: "php2shell",
    title: "[php2shell] Manifest dependency composer.json terbuka di webroot",
    cwe: ["CWE-200", "CWE-502"],
    rce: false,
    marker: "composer require packages",
    validate: (b, ct) =>
      json(ct, b) && /"require"\s*:\s*\{/.test(b) && /"(?:php|laravel\/framework|symfony\/|monolog\/|guzzlehttp\/)"/i.test(b)
        ? "MEDIUM"
        : null,
    impact:
      "Mengungkap daftar pustaka PHP beserta versi untuk pemetaan gadget chain deserialization (PHPGGC / php2shell).",
    fix: "Tempatkan composer.json di luar public webroot atau blokir akses ke composer.json dan composer.lock di web server.",
  },

  // ==================== 3. node2shell (Node.js V8 Inspector, PM2 & SSR Debug Surface) ====================
  {
    path: "/json/version",
    vector: "node2shell",
    title: "[node2shell] Node.js V8 Inspector Debug Endpoint terbuka (/json/version)",
    cwe: ["CWE-489", "CWE-94", "CWE-306"],
    rce: true,
    marker: "webSocketDebuggerUrl / V8-Version",
    validate: (b, ct) =>
      json(ct, b) &&
      (/"webSocketDebuggerUrl"\s*:\s*"ws/i.test(b) || (/"Browser"\s*:\s*"node\.js/i.test(b) && /"V8-Version"/i.test(b)))
        ? "CRITICAL"
        : null,
    impact:
      "Port debug V8 Inspector Node.js terekspos ke publik; penyerang dapat terhubung ke WebSocket debugger dan mengeksekusi child_process.exec secara langsung (node2shell RCE penuh).",
    fix: "Jangan jalankan Node.js dengan flag --inspect / --inspect-brk di produksi dan blokir rute /json/* di reverse proxy.",
  },
  {
    path: "/ecosystem.config.js",
    vector: "node2shell",
    title: "[node2shell] Konfigurasi PM2 ecosystem.config.js terbuka",
    cwe: ["CWE-538", "CWE-798"],
    rce: false,
    marker: "module.exports apps PM2",
    validate: (b, ct) =>
      notHtml(ct, b) && /module\.exports\s*=/.test(b) && /\bapps\s*:\s*\[/.test(b) ? "CRITICAL" : null,
    impact:
      "Membocorkan konfigurasi proses PM2 Node.js, argumen eksekusi, path internal, serta variabel rahasia di dalam blok env_production.",
    fix: "Pindahkan ecosystem.config.js ke luar direktori statis/publik dan rotasi seluruh secret yang tercantum.",
  },
  {
    path: "/__nextjs_original-stack-frame",
    vector: "node2shell",
    title: "[node2shell] Next.js Dev Server Stack-Frame Endpoint aktif di produksi",
    cwe: ["CWE-489", "CWE-215"],
    rce: false,
    marker: "Next.js original stack frame",
    validate: (b, ct) =>
<<<<<<< HEAD
      json(ct, b) && /"originalStackFrame"|"originalCodeFrame"/i.test(b) ? "HIGH" : null,
=======
      (json(ct, b) && /"originalStackFrame"|"originalCodeFrame"/i.test(b)) ? "HIGH" : null,
>>>>>>> bbaddad103ee180657df44c34d5a8762c65b0076
    impact:
      "Endpoint pengembangan Next.js aktif dan dapat membocorkan struktur kode sumber server-side serta konfigurasi runtime Node.js.",
    fix: "Pastikan aplikasi dijalankan menggunakan `next build && next start` (NODE_ENV=production), bukan `next dev`.",
  },

  // ==================== 4. go2shell (Go pprof, Cmdline & Expvar Runtime Surface) ====================
  {
    path: "/debug/pprof/",
    vector: "go2shell",
    title: "[go2shell] Go net/http/pprof Runtime Profiler terbuka",
    cwe: ["CWE-215", "CWE-200", "CWE-489"],
    rce: false,
    marker: "Types of profiles available (goroutine/heap)",
    validate: (b, ct) =>
      html(ct) && /Types of profiles available/i.test(b) && /\bgoroutine\b[\s\S]*\bheap\b/i.test(b)
        ? "HIGH"
        : null,
    impact:
      "Endpoint pprof Go terbuka tanpa autentikasi, membocorkan jejak tumpukan goroutine, alokasi heap memori, simbol binary, dan path kode sumber server (go2shell recon).",
    fix: "Daftarkan pprof hanya pada listener loopback internal (127.0.0.1) dan blokir /debug/pprof/* di reverse proxy publik.",
  },
  {
    path: "/debug/pprof/cmdline",
    vector: "go2shell",
    title: "[go2shell] Go pprof/cmdline Command-Line Arguments terbuka",
    cwe: ["CWE-200", "CWE-215"],
    rce: false,
    marker: "Go binary command line",
    validate: (b, ct) =>
      notHtml(ct, b) &&
      b.length > 3 &&
      b.length < 4096 &&
<<<<<<< HEAD
      /(\/usr\/|\/bin\/|\/app\/|\/opt\/|--config|--port|-env)/i.test(b) &&
      b.includes("\u0000")
=======
      (/(\/usr\/|\/bin\/|\/app\/|\/opt\/|--config|--port|-env)/i.test(b) && b.includes("\u0000"))
>>>>>>> bbaddad103ee180657df44c34d5a8762c65b0076
        ? "HIGH"
        : null,
    impact:
      "Membocorkan argumen eksekusi binary Go di server beserta flag konfigurasi, token argumen, dan struktur direktori sistem.",
    fix: "Nonaktifkan net/http/pprof di production atau batasi rute /debug/* dengan autentikasi ketat.",
  },
  {
    path: "/debug/vars",
    vector: "go2shell",
    title: "[go2shell] Go expvar Runtime Variables & Memstats terbuka",
    cwe: ["CWE-200", "CWE-215"],
    rce: false,
    marker: "cmdline & memstats JSON",
    validate: (b, ct) =>
      json(ct, b) && /"cmdline"\s*:\s*\[/.test(b) && /"memstats"\s*:\s*\{/.test(b) ? "HIGH" : null,
    impact:
      "Paket expvar Go mengekspose argumen command-line, metrik memori internal (memstats), dan variabel state aplikasi secara publik.",
    fix: "Blokir rute /debug/vars di reverse proxy dan hanya izinkan akses dari jaringan monitoring internal.",
  },

  // ==================== 5. py2shell (Python Werkzeug, Jupyter, Celery & Django Debug Surface) ====================
  {
    path: "/console",
    vector: "py2shell",
    title: "[py2shell] Werkzeug / Flask Interactive Debug Console terbuka",
    cwe: ["CWE-94", "CWE-489"],
    rce: true,
    marker: "Werkzeug interactive console",
    validate: (b, ct) =>
      html(ct) &&
      /<title>[^<]*Werkzeug[^<]*<\/title>/i.test(b) &&
      /(Interactive Console|console locked|__debugger__)/i.test(b)
        ? "CRITICAL"
        : null,
    impact:
      "Console debugger interaktif Werkzeug memungkinkan eksekusi perintah Python secara langsung di server (py2shell RCE) apabila PIN berhasil dihitung via LFI atau tidak dikunci.",
    fix: "Jalankan aplikasi Flask/Werkzeug menggunakan WSGI server produksi (gunicorn/uvicorn) dengan debug=False.",
  },
  {
    path: "/api/kernels",
    vector: "py2shell",
    title: "[py2shell] Jupyter / IPython Kernel API terbuka tanpa autentikasi",
    cwe: ["CWE-306", "CWE-94"],
    rce: true,
    marker: "Jupyter kernel execution API",
    validate: (b, ct) =>
      json(ct, b) && /"execution_state"\s*:\s*"(?:idle|busy|starting)"/i.test(b) && /"name"\s*:\s*"python/i.test(b)
        ? "CRITICAL"
        : null,
    impact:
      "Endpoint kernel Jupyter terbuka tanpa token autentikasi, memungkinkan eksekusi kode Python jarak jauh secara penuh di atas server (py2shell).",
    fix: "Aktifkan token/password wajib pada Jupyter Server dan jangan pernah mengekspos port Jupyter langsung ke internet publik.",
  },
  {
    path: "/api/workers",
    vector: "py2shell",
    title: "[py2shell] Celery Flower Worker Monitor API terbuka",
    cwe: ["CWE-306", "CWE-200"],
    rce: true,
    marker: "celery@ worker pool configuration",
    validate: (b, ct) =>
      json(ct, b) && /"celery@[^"]+"\s*:\s*\{/i.test(b) && /"active_queues"|"stats"|"conf"/i.test(b)
        ? "HIGH"
        : null,
    impact:
      "Dashboard/API Celery Flower terbuka tanpa autentikasi, membocorkan kredensial broker (Redis/RabbitMQ) dan berisiko memungkinkan injeksi task Python (py2shell).",
    fix: "Aktifkan basic-auth / OAuth2 pada Celery Flower dan tempatkan di jaringan privat internal.",
  },
  {
    path: "/__debug__/",
    vector: "py2shell",
    title: "[py2shell] Django Debug Toolbar aktif di produksi",
    cwe: ["CWE-489", "CWE-215"],
    rce: false,
    marker: "djDebug / Django Debug Toolbar",
    validate: (b, ct) =>
      (html(ct) || json(ct, b)) && /(?:djDebug|djdt|Django Debug Toolbar)/i.test(b) ? "HIGH" : null,
    impact:
      "Django berjalan dengan DEBUG=True atau Debug Toolbar terbuka, berisiko membocorkan SECRET_KEY untuk pemalsuan session pickle/cookie (py2shell).",
    fix: "Set DEBUG = False pada settings.py produksi dan hapus django-debug-toolbar dari INSTALLED_APPS produksi.",
  },

  // ==================== 6. node-oob (Node Out-of-Bounds, Memory Heapdump & GraphQL Surface) ====================
  {
    path: "/heapdump",
    vector: "node-oob",
    title: "[Node Out-of-Bounds / Memory] Endpoint V8 / Server Heapdump terbuka",
    cwe: ["CWE-119", "CWE-125", "CWE-200"],
    rce: false,
    marker: "V8 heap snapshot / nodes & edges",
    validate: (b, ct) =>
      (json(ct, b) && /"snapshot"\s*:\s*\{/.test(b) && /"nodes"\s*:\s*\[/.test(b)) ||
<<<<<<< HEAD
      (ct.includes("octet-stream") && b.startsWith("JAVA PROFILE"))
=======
      ct.includes("octet-stream") && b.startsWith("JAVA PROFILE")
>>>>>>> bbaddad103ee180657df44c34d5a8762c65b0076
        ? "CRITICAL"
        : null,
    impact:
      "Snapshot memori (V8 Heapdump / Buffer dump) dapat diunduh publik, mengekspos isi memori out-of-bounds, Buffer yang belum dibersihkan, JWT secret, dan sesi pengguna aktif.",
    fix: "Hapus rute /heapdump dari aplikasi produksi dan hindari penggunaan Buffer.allocUnsafe tanpa inisialisasi nol.",
  },
  {
    path: "/actuator/heapdump",
    vector: "node-oob",
    title: "[Memory / Out-of-Bounds] Actuator Heapdump terbuka",
    cwe: ["CWE-200", "CWE-119"],
    rce: false,
    marker: "JVM HPROF / GZIP heapdump header",
    validate: (b, ct) =>
      (ct.includes("octet-stream") || ct.includes("gzip")) &&
      (b.startsWith("JAVA PROFILE") || (b.charCodeAt(0) === 0x1f && b.charCodeAt(1) === 0x8b))
        ? "CRITICAL"
        : null,
    impact:
      "Dump memori mentah server dapat diunduh tanpa autentikasi, membocorkan kredensial database, kunci enkripsi, dan state memori internal.",
    fix: "Matikan endpoint heapdump pada konfigurasi Actuator dan lindungi seluruh endpoint manajemen dengan autentikasi.",
  },
  {
    path: "/graphql",
    vector: "node-oob",
    title: "[Node Out-of-Bounds / GraphQL] GraphiQL / Apollo Playground terbuka",
    cwe: ["CWE-200", "CWE-400"],
    rce: false,
    marker: "GraphiQL / Apollo Sandbox IDE",
    validate: (b, ct) =>
      html(ct) && /(?:GraphiQL|Apollo Sandbox|graphql-playground)/i.test(b) ? "MEDIUM" : null,
    impact:
      "IDE GraphQL interaktif terbuka di produksi; memudahkan introspeksi skema penuh serta berisiko terhadap serangan nested query out-of-bounds / alokasi memori berlebih.",
    fix: "Nonaktifkan GraphiQL/Playground dan introspection di production serta terapkan query depth & complexity limiting.",
  },

  // ==================== 7. Enterprise & Server Diagnostics (Actuator, Jolokia, ELMAH, Server-Status) ====================
  {
    path: "/actuator/env",
    vector: "rce-surface",
    title: "Spring Boot Actuator /env terbuka",
    cwe: ["CWE-200", "CWE-215"],
    rce: true,
    marker: "propertySources",
    validate: (b, ct) => (json(ct, b) && /"propertySources"\s*:/.test(b) && /"activeProfiles"\s*:/.test(b) ? "HIGH" : null),
    impact:
      "Konfigurasi dan environment aplikasi terbaca publik; sering menjadi batu loncatan menuju Remote Code Execution via Spring Cloud / SnakeYAML.",
    fix: "Batasi endpoint actuator (management.endpoints.web.exposure.include) dan lindungi dengan autentikasi.",
  },
  {
    path: "/actuator/gateway/routes",
    vector: "rce-surface",
    title: "Spring Cloud Gateway Actuator routes terbuka",
    cwe: ["CWE-917", "CWE-94"],
    cve: ["CVE-2022-22947"],
    rce: true,
    marker: "route_id & predicates",
    validate: (b, ct) =>
      json(ct, b) && /"route_id"\s*:/.test(b) && /"predicates"\s*:/.test(b) ? "CRITICAL" : null,
    impact:
      "Endpoint Actuator Spring Cloud Gateway terbuka tanpa autentikasi; rentan terhadap SpEL Code Injection / RCE (CVE-2022-22947).",
    fix: "Upgrade Spring Cloud Gateway ke versi ter-patch dan nonaktifkan eksposur endpoint gateway di Actuator.",
  },
  {
    path: "/actuator",
    vector: "rce-surface",
    title: "Spring Boot Actuator index terbuka",
    cwe: ["CWE-200"],
    rce: false,
    marker: "_links",
    validate: (b, ct) =>
      json(ct, b) && /"_links"\s*:/.test(b) && /"(env|heapdump|beans|mappings|gateway)"\s*:/.test(b)
        ? "MEDIUM"
        : null,
    impact: "Daftar endpoint manajemen terbuka, memudahkan reconnaissance permukaan serangan server.",
    fix: "Batasi eksposur actuator ke jaringan internal atau tambahkan autentikasi.",
  },
  {
    path: "/elmah.axd",
    vector: "rce-surface",
    title: "ELMAH .NET error log terbuka",
    cwe: ["CWE-209", "CWE-532"],
    rce: false,
    marker: "ELMAH",
    validate: (b, ct) => (html(ct) && /<title>\s*Error Log for/i.test(b) && /ELMAH/i.test(b) ? "HIGH" : null),
    impact: "Log error berisi stack trace, parameter request, dan session/cookie autentikasi pengguna.",
    fix: "Batasi elmah.axd dengan autentikasi atau nonaktifkan remote access (`allowRemoteAccess=false`).",
  },
  {
    path: "/jolokia/version",
    vector: "rce-surface",
    title: "Jolokia JMX-over-HTTP terbuka",
    cwe: ["CWE-306", "CWE-94"],
    rce: true,
    marker: "jolokia agent",
    validate: (b, ct) =>
      json(ct, b) && /jolokia/i.test(b) && /"agent"\s*:/.test(b) && /"protocol"\s*:/.test(b) ? "CRITICAL" : null,
    impact:
      "Akses JMX tanpa autentikasi dapat dipakai memanggil MBean berbahaya (Logback/DiagnosticCommand) sehingga berpotensi RCE.",
    fix: "Matikan Jolokia di production atau lindungi dengan autentikasi dan pembatasan jaringan.",
  },
  {
    path: "/server-status",
    vector: "rce-surface",
    title: "Apache mod_status terbuka",
    cwe: ["CWE-200"],
    rce: false,
    marker: "Apache Server Status",
    validate: (b, ct) =>
      html(ct) && /<(?:h1|title)>\s*Apache (?:Server )?Status(?: for)?/i.test(b) ? "MEDIUM" : null,
    impact: "Menampilkan request HTTP aktif, IP klien, dan URL endpoint internal secara real-time.",
    fix: "Batasi /server-status hanya ke localhost atau jaringan administrator.",
  },
];

export const RCE_SURFACE_PATH_COUNT = RCE_SPECS.length;

export interface RceSurfaceResult {
  findings: Finding[];
  evidence: RceSurfaceEvidence[];
}

const newId = () => Math.random().toString(36).slice(2) + Date.now().toString(36);

export function evaluateRceSpec(spec: Spec, status: number, ct: string, body: string): Severity | null {
  if (status !== 200 && !(spec.path === "/xmlrpc.php" && status === 405)) return null;
  return spec.validate(body, ct.toLowerCase(), status);
}

export async function checkRceSurface(
  origin: string,
  budget: RequestBudget,
  cfClearance?: string
): Promise<RceSurfaceResult> {
  const out: RceSurfaceResult = { findings: [], evidence: [] };
  for (const spec of RCE_SPECS) {
    const url = new URL(spec.path, origin).toString();
    const r = await budget.spend(async () => {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), 8000);
      try {
        const res = await fetch(url, {
          method: "GET",
<<<<<<< HEAD
          headers: chromeHeaders(origin, cfClearance),
=======
          headers: chromeHeaders(),
>>>>>>> bbaddad103ee180657df44c34d5a8762c65b0076
          redirect: "manual",
          signal: ctl.signal,
        });
        const text = (await res.text()).slice(0, 64 * 1024);
        return {
          status: res.status,
          headers: res.headers,
          text,
          ct: res.headers.get("content-type") ?? "",
        };
      } catch {
        return null;
      } finally {
        clearTimeout(t);
      }
    });
    if (!r) continue;
    if (detectCloudflareChallenge(r.status, r.headers, r.text.slice(0, 2000))) continue;

    const sev = evaluateRceSpec(spec, r.status, r.ct, r.text);
    if (!sev) continue;

    const category: FindingCategory = spec.vector;

    out.findings.push({
      id: newId(),
      severity: sev,
      title: `${spec.title}${spec.rce ? " — potensi RCE" : ""}`,
      endpoint: url,
      evidence: `HTTP ${r.status} — isi respons cocok penanda "${spec.marker}" (detail diamankan di Sentinel Vault)`,
      impact: spec.impact,
      fix: spec.fix,
      cwe: spec.cwe.join(", "),
      cve: spec.cve,
      rce: spec.rce || undefined,
      confidence: "verified",
      category,
    });
    out.evidence.push({
      path: spec.path,
      title: spec.title,
      severity: sev,
      cwe: spec.cwe,
      cve: spec.cve ?? [],
      status: r.status,
      marker: spec.marker,
      snippet: r.text.replace(/\s+/g, " ").slice(0, 300),
    });
  }
  return out;
}
