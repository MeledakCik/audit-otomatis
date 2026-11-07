/**
 * Permukaan RCE, Shell-Escalation (wp2shell, php2shell, node2shell, go2shell, py2shell),
 * Node Out-of-Bounds / Memory Surface & Deep WebShell / FileManager Detector PASIF:
 * Endpoint diagnostik/debug/runtime serta artefak WebShell & FileManager (WSO, b374k, Alfa,
 * MariJUANA, Gel4y, Mini Shell, TinyFileManager, FileRun, elFinder, Responsive FileManager,
 * KCFFinder, Roxy Fileman, KodExplorer) yang membuka jalur kompromi penuh bila terekspos.
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
  | "webshell"
  | "filemanager-shell"
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

/**
 * Detektor tanda tangan (signature) multi-indikator untuk WebShell aktif (WSO, b374k, Alfa, c99, r57,
 * MariJUANA, Gel4y, IndoXploit, Sadrazam, FoxWSO, dsb.) dan halaman login backdoor (single-input password gate).
 * Mencegah false-positive pada halaman website biasa atau artikel blog keamanan.
 */
export function matchWebshellSignature(body: string): { family: string; marker: string; severity: Severity } | null {
  const head = body.slice(0, 48 * 1024);

  // 1. Named WebShell Families (Title / Banner + Functional UI markers)
  if (
    /(?:WSO\s+\d+\.\d+|Web\s*Shell\s*by\s*oRb|wso_version|FilesMan)/i.test(head) &&
    /(?:uname\s*-a|safe_mode|Server\s+security|Php\s+eval|chmod|Self\s+remove)/i.test(head)
  ) {
    return { family: "WSO / FilesMan WebShell", marker: "WSO / FilesMan UI + system uname banner", severity: "CRITICAL" };
  }

  if (
    /(?:b374k\s+\d+\.\d+|b374k\s+shell|b374k\s+mini)/i.test(head) &&
    /(?:terminal|processes|eval|database|file\s*manager|c99|r57)/i.test(head)
  ) {
    return { family: "b374k PHP WebShell", marker: "b374k WebShell UI + terminal/eval tabs", severity: "CRITICAL" };
  }

  if (
    /(?:Alfa\s+Team|ALFA\s+TEaM\s+Shell|Alfa-Shell|alfacgiapi|Alfa\s+V\d)/i.test(head) &&
    /(?:solevisible|Alfa|filemanager|cgi\s+shell|eval|perl|python)/i.test(head)
  ) {
    return { family: "ALFA Team WebShell", marker: "ALFA Team Shell signature + command console", severity: "CRITICAL" };
  }

  if (
    /(?:MARIJUANA|MariJUANA\s+Shell|0x5a455553|Gel4y\s+Mini\s+Shell|IndoXploit\s+Shell|IDX\s+Shell|Mini\s+Shell\s+By| FoxWSO|AnonSec\s+Shell|0byt3m1n1)/i.test(
      head
    ) &&
    /(?:uname|uid=\d+|gid=\d+|safe_mode|disable_functions|Upload\s+File|Current\s+Directory|chmod| Mass\s+Deface)/i.test(head)
  ) {
    return {
      family: "Underground PHP Mini/Stealth WebShell (MariJUANA / Gel4y / IndoXploit / 0byt3m1n1)",
      marker: "Mini/Stealth WebShell banner + OS uid/gid/disable_functions telemetry",
      severity: "CRITICAL",
    };
  }

  if (
    /(?:c99shell|c99madshell|r57shell|PhpSpy|MyShell|Ani-Shell|p0wny@shell|p0wny-shell)/i.test(head) &&
    /(?:safe_mode|uname|uid=|Encoder|Bind\s+port|Back-connect|terminal|cmd)/i.test(head)
  ) {
    return {
      family: "Classic Interactive WebShell (c99 / r57 / p0wny-shell)",
      marker: "Classic WebShell signature (c99/r57/p0wny) + interactive shell prompt",
      severity: "CRITICAL",
    };
  }

  // 2. Generic Active WebShell Telemetry Combo:
  // Membutuhkan minimal 3 indikator kuat yang muncul bersamaan (mis. output uname + uid/gid + disable_functions + upload/chmod)
  let score = 0;
  const hitMarkers: string[] = [];
  if (/\buid=\d+\([a-z0-9_-]+\)\s+gid=\d+\([a-z0-9_-]+\)/i.test(head)) {
    score += 2;
    hitMarkers.push("uid/gid unix id output");
  }
  if (/\bLinux\s+[^\s<>]{2,50}\s+\d+\.\d+\.\d+[-\w.]*\s+#\d+\s+SMP\b/i.test(head)) {
    score += 2;
    hitMarkers.push("Linux kernel uname -a banner");
  }
  if (/\b(?:disable_functions|safe_mode|open_basedir)\s*[:=]\s*(?:<[^>]+>)?\s*(?:NONE|OFF|ON|exec|system|passthru|shell_exec)/i.test(head)) {
    score += 2;
    hitMarkers.push("PHP disable_functions/safe_mode status bar");
  }
  if (/\b(?:drwxr-xr-x|-rw-r--r--|drwxrwxrwx)\b/.test(head) && /(?:chmod|Rename|Touch|Delete|Edit)/i.test(head)) {
    score += 1;
    hitMarkers.push("POSIX permission table + file actions");
  }
  if (/<input[^>]+type=["']file["'][^>]*>[\s\S]{0,400}(?:Upload|Summon|upfile)/i.test(head)) {
    score += 1;
    hitMarkers.push("direct file upload widget");
  }

  if (score >= 4) {
    return {
      family: "Active Generic WebShell & System Command Console",
      marker: hitMarkers.join(" + "),
      severity: "CRITICAL",
    };
  }

  // 3. Stealth Password-Protected WebShell Gate (Minimalist single-input password form without standard HTML layout)
  if (
    head.length > 40 &&
    head.length < 2200 &&
    /<form[^>]*method=["']?post["']?[^>]*>[\s\S]{0,600}<input[^>]*type=["']?password["']?[^>]*>/i.test(head) &&
    !/<(?:nav|footer|header|aside|article|main)\b/i.test(head) &&
    (head.split(/\r?\n/).length <= 35 || /(?:md5|pass|auth_pass|shell|b374k|wso|alfa)/i.test(head))
  ) {
    return {
      family: "Stealth Password-Gated WebShell Backdoor",
      marker: "Minimalist password-only POST gate (<2.2KB, no nav/footer layout)",
      severity: "HIGH",
    };
  }

  // 4. Unexecuted / Raw Obfuscated PHP WebShell Source Code Leak
  if (
    /<\?php/i.test(head) &&
    /(?:eval|assert|system|shell_exec|passthru|proc_open|popen)\s*\(\s*(?:gzinflate|gzuncompress|str_rot13|base64_decode|rawurldecode)\s*\(/i.test(
      head
    )
  ) {
    return {
      family: "Obfuscated PHP WebShell Source Code",
      marker: "<?php eval/system(gzinflate/base64_decode/str_rot13(...))",
      severity: "CRITICAL",
    };
  }

  return null;
}

/**
 * Detektor khusus Web-based File Manager (TinyFileManager, elFinder, FileRun, Responsive FileManager,
 * KCFFinder, Roxy Fileman, KodExplorer, FileGator, MonstaFTP, Net2FTP) yang sering dipasang penyerang
 * atau tertinggal tanpa autentikasi di webroot.
 */
export function matchFileManagerSignature(body: string, ct: string): { name: string; marker: string; severity: Severity; cve?: string[] } | null {
  const head = body.slice(0, 48 * 1024);

  // 1. TinyFileManager (H3K / CCPProgrammers)
  if (
    html(ct) &&
    (/(?:Tiny\s*File\s*Manager|tinyfilemanager\.github\.io|fm_usr|fm_pwd|ccpprogrammers)/i.test(head) ||
      (/<title>[^<]*File\s*Manager[^<]*<\/title>/i.test(head) && /translation\.json|fm_current_root|fa-folder/i.test(head)))
  ) {
    const isUnauthListing = /(?:New\s+Item|Upload|Direct\s+Link|Change\s+Permissions|Root\s+path)/i.test(head) && !/fm_pwd/i.test(head);
    return {
      name: isUnauthListing ? "TinyFileManager (Unauthenticated File System Access)" : "TinyFileManager Login / Console",
      marker: isUnauthListing ? "TinyFileManager workspace terbuka tanpa password" : "TinyFileManager (fm_usr/fm_pwd) aktif di webroot",
      severity: "CRITICAL",
      cve: ["CVE-2021-45010", "CVE-2022-45474"],
    };
  }

  // 2. Studio-42 elFinder (UI & Connector API)
  if (
    (html(ct) && /elFinder|elfinder\.min\.js|elfinder\.full\.js/i.test(head) && /\$\(['"]#elfinder['"]\)\.elfinder/i.test(head)) ||
    (json(ct, head) && /"cwd"\s*:\s*\{[\s\S]*"phash"\s*:/i.test(head) && /"files"\s*:\s*\[/i.test(head))
  ) {
    return {
      name: "Studio-42 elFinder Web File Manager / Connector",
      marker: json(ct, head) ? "elFinder Connector JSON (cwd/phash/files)" : "elFinder UI (#elfinder instance)",
      severity: "CRITICAL",
      cve: ["CVE-2021-32682", "CVE-2019-9194"],
    };
  }

  // 3. Responsive FileManager (Trippo)
  if (
    html(ct) &&
    /(?:Responsive\s+FileManager|responsivefilemanager\.com|rfm_subfolder| dialog\.php\?type=)/i.test(head)
  ) {
    return {
      name: "Responsive FileManager (dialog.php / upload.php)",
      marker: "Responsive FileManager UI terbuka di publik",
      severity: "CRITICAL",
      cve: ["CVE-2020-26045"],
    };
  }

  // 4. KCFinder Web File Manager
  if (html(ct) && /(?:KCFinder|kcfinder\/browse\.php|kc_CKEditor|browser\.init)/i.test(head)) {
    return {
      name: "KCFinder Web File Manager (browse.php)",
      marker: "KCFinder file browser UI terbuka",
      severity: "HIGH",
      cve: ["CVE-2019-14315"],
    };
  }

  // 5. Roxy Fileman (.NET / PHP File Manager)
  if (
    (html(ct) || json(ct, head)) &&
    /(?:Roxy\s+Fileman|roxyfileman|DIRLIST|FILESLIST|pnlDirList)/i.test(head)
  ) {
    return {
      name: "Roxy Fileman Web File Manager",
      marker: "Roxy Fileman interface / DIRLIST endpoint",
      severity: "CRITICAL",
      cve: ["CVE-2018-20526"],
    };
  }

  // 6. KodExplorer / KodBox / FileGator / FileRun
  if (
    html(ct) &&
    /(?:KodExplorer|kalcaddle|KodBox|FileGator|filegator\.io|FileRun|filerun\.com)/i.test(head) &&
    /(?:file|explorer|login|upload|webdav)/i.test(head)
  ) {
    return {
      name: "Standalone Cloud/Web File Manager (KodExplorer / FileGator / FileRun)",
      marker: "KodExplorer / FileGator / FileRun web interface",
      severity: "HIGH",
    };
  }

  // 7. WP File Manager (wp-file-manager plugin connector / Zero-Day CVE-2020-25213)
  if (
    (json(ct, head) || html(ct)) &&
    /(?:errUnknownCmd|elFinderConnector|wp-file-manager)/i.test(head)
  ) {
    return {
      name: "WordPress File Manager elFinder Connector (CVE-2020-25213)",
      marker: "elFinder connector response (errUnknownCmd / cwd)",
      severity: "CRITICAL",
      cve: ["CVE-2020-25213"],
    };
  }

  return null;
}

const FIX_WEBSHELL =
  "ISOLASI SERVER SEGERA: Hapus file webshell dari server, cabut izin tulis (chmod) pada direktori webroot, periksa access log & crontab untuk mencari backdoor persistensi, lalu rotasi seluruh kredensial database, APP_KEY, dan SSH/API key.";

const FIX_FILEMANAGER =
  "Hapus File Manager standalone dari server produksi, atau pindahkan ke jaringan internal dengan autentikasi berlapis (Basic Auth + IP Allowlist + 2FA) dan nonaktifkan eksekusi script (.php/.sh) di direktori upload.";

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
      !html(ct) && /(?:PHPUnit|eval-stdin\.php|Fatal error.*eval-stdin\.php)/i.test(b)
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
      json(ct, b) && /"originalStackFrame"|"originalCodeFrame"/i.test(b) ? "HIGH" : null,
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
      /(\/usr\/|\/bin\/|\/app\/|\/opt\/|--config|--port|-env)/i.test(b) &&
      b.includes("\u0000")
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
      (ct.includes("octet-stream") && b.startsWith("JAVA PROFILE"))
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

  // ==================== 7. webshell (Active WebShell Backdoors: WSO, b374k, Alfa, MariJUANA, Gel4y, Mini Shell, c99/r57) ====================
  ...[
    "/shell.php",
    "/wso.php",
    "/alfa.php",
    "/b374k.php",
    "/mini.php",
    "/marijuana.php",
    "/gel4y.php",
    "/indoxploit.php",
    "/c99.php",
    "/r57.php",
    "/cmd.php",
    "/up.php",
    "/uploader.php",
    "/wp-content/uploads/shell.php",
    "/wp-content/uploads/alfa.php",
    "/wp-content/uploads/wso.php",
    "/wp-includes/wp-class.php",
    "/uploads/shell.php",
  ].map(
    (p): Spec => ({
      path: p,
      vector: "webshell",
      title: `[WebShell Backdoor] Artefak WebShell aktif terdeteksi pada ${p}`,
      cwe: ["CWE-434", "CWE-94", "CWE-506"],
      rce: true,
      marker: "WebShell UI / System Command Telemetry (WSO/b374k/Alfa/Mini/Stealth)",
      validate: (b) => matchWebshellSignature(b)?.severity ?? null,
      impact:
        "File WebShell / Backdoor aktif terdeteksi di server! Penyerang memiliki kendali Remote Code Execution (RCE), pembacaan/modifikasi seluruh filesystem, akses database, dan pivot ke jaringan internal.",
      fix: FIX_WEBSHELL,
    })
  ),

  // ==================== 8. filemanager-shell (Exposed Web File Managers: TinyFileManager, elFinder, ResponsiveFM, Roxy, KCFinder) ====================
  ...[
    "/tinyfilemanager.php",
    "/filemanager.php",
    "/fm.php",
    "/files.php",
    "/manager.php",
    "/filemanager/dialog.php",
    "/assets/filemanager/dialog.php",
    "/elfinder/elfinder.html",
    "/elfinder/php/connector.minimal.php",
    "/wp-content/plugins/wp-file-manager/lib/php/connector.minimal.php",
    "/kcfinder/browse.php",
    "/fileman/index.html",
    "/roxyfileman/index.html",
  ].map(
    (p): Spec => ({
      path: p,
      vector: "filemanager-shell",
      title: `[FileManager WebShell] Panel Web File Manager terekspos pada ${p}`,
      cwe: ["CWE-434", "CWE-306", "CWE-284"],
      cve: p.includes("wp-file-manager")
        ? ["CVE-2020-25213"]
        : p.includes("elfinder")
        ? ["CVE-2021-32682"]
        : p.includes("tinyfilemanager") || p === "/fm.php"
        ? ["CVE-2021-45010"]
        : undefined,
      rce: true,
      marker: "Web File Manager UI / Connector (TinyFileManager / elFinder / ResponsiveFM / KCFinder / Roxy)",
      validate: (b, ct) => matchFileManagerSignature(b, ct)?.severity ?? null,
      impact:
        "Panel Web File Manager terbuka di webroot publik. Sering digunakan sebagai WebShell FileManager untuk mengunggah backdoor PHP, mengedit source code produksi, atau mengunduh file konfigurasi rahasia (.env / wp-config.php).",
      fix: FIX_FILEMANAGER,
    })
  ),

  // ==================== 9. Enterprise & Server Diagnostics (Actuator, Jolokia, ELMAH, Server-Status) ====================
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
          headers: chromeHeaders(origin, cfClearance),
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

    // Enrich marker & title with exact WebShell / FileManager family if matched
    let exactMarker = spec.marker;
    let exactTitle = spec.title;
    if (spec.vector === "webshell") {
      const ws = matchWebshellSignature(r.text);
      if (ws) {
        exactMarker = `${ws.family} — ${ws.marker}`;
        exactTitle = `[WebShell Backdoor] ${ws.family} aktif pada ${spec.path}`;
      }
    } else if (spec.vector === "filemanager-shell") {
      const fm = matchFileManagerSignature(r.text, r.ct.toLowerCase());
      if (fm) {
        exactMarker = `${fm.name} — ${fm.marker}`;
        exactTitle = `[FileManager WebShell] ${fm.name} terekspos pada ${spec.path}`;
      }
    }

    const category: FindingCategory = spec.vector;

    out.findings.push({
      id: newId(),
      severity: sev,
      title: `${exactTitle}${spec.rce ? " — potensi RCE" : ""}`,
      endpoint: url,
      evidence: `HTTP ${r.status} — isi respons cocok penanda "${exactMarker}" (detail diamankan di Sentinel Vault)`,
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
      title: exactTitle,
      severity: sev,
      cwe: spec.cwe,
      cve: spec.cve ?? [],
      status: r.status,
      marker: exactMarker,
      snippet: r.text.replace(/\s+/g, " ").slice(0, 300),
    });
  }
  return out;
}
