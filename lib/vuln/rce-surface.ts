/**
 * Permukaan RCE, Shell-Escalation (wp2shell, php2shell, node2shell, go2shell, py2shell),
 * Node Out-of-Bounds / Memory Surface & Deep Structural WebShell / FileManager Detector PASIF:
 * Endpoint diagnostik/debug/runtime serta artefak WebShell & FileManager (WSO, b374k, Alfa,
 * MariJUANA, Gel4y, Mini Shell, TinyFileManager, FileRun, elFinder, Responsive FileManager,
 * KCFFinder, Roxy Fileman, KodExplorer) yang membuka jalur kompromi penuh bila terekspos.
 *
 * PRINSIP ANTI-FALSE-POSITIVE (STRUCTURAL DOM / JSON / HEADER VALIDATION):
 * - TIDAK PERNAH mendeteksi WebShell / FileManager hanya dari kemunculan teks nama di halaman biasa,
 *   dokumentasi, artikel, atau bundle JS React/Next.js (`__NEXT_DATA__`, `_next/static`, `self.__next_f`).
 * - Wajib memverifikasi STRUKTUR DOM / FORM / INPUT / JSON API CONNECTOR / COOKIE nyata dari aplikasi
 *   WebShell atau FileManager yang sedang berjalan di endpoint tersebut.
 */
import * as cheerio from "cheerio";
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
  validate: (body: string, ct: string, status?: number, headers?: Headers) => Severity | null;
  marker: string;
  impact: string;
  fix: string;
}

const html = (ct: string) => ct.includes("html");
const json = (ct: string, b: string) => ct.includes("json") || /^\s*[{[]/.test(b);
const notHtml = (ct: string, b: string) =>
  !ct.includes("html") && !/<(!doctype|html|head|body)\b/i.test(b.slice(0, 600));

/**
 * Guard untuk menolak halaman SPA modern (Next.js / Nuxt / Vite / artikel dokumentasi)
 * agar halaman web biasa yang menulis kata "WSO" / "TinyFileManager" / "b374k" TIDAK PERNAH
 * dianggap sebagai WebShell / FileManager.
 */
function isModernSpaOrArticleShell(body: string): boolean {
  const head = body.slice(0, 32 * 1024);
  if (
    head.includes("/_next/static/") ||
    head.includes("__NEXT_DATA__") ||
    head.includes("self.__next_f") ||
    head.includes("sentinel-id.net") ||
    /<meta[^>]+name=["']generator["'][^>]+content=["'](?:Next\.js|Gatsby|Astro|Hugo|Hexo)/i.test(head)
  ) {
    return true;
  }
  return false;
}

/**
 * Detektor STRUKTURAL untuk WebShell aktif (WSO, b374k, Alfa, c99, r57, MariJUANA, Gel4y, IndoXploit, Mini Shell).
 * Wajib memverifikasi elemen interaktif DOM (`<form>`, `<input>`, `<textarea>`, `<table>` file listing)
 * atau header/cookie autentikasi khas WebShell — BUKAN sekadar kecocokan string teks!
 */
export function matchWebshellSignature(
  body: string,
  headers?: Headers
): { family: string; marker: string; severity: Severity } | null {
  if (!body || isModernSpaOrArticleShell(body)) return null;
  const head = body.slice(0, 48 * 1024);

  // 0. Cek Cookie / Header khas WebShell (WSO / Alfa / b374k kadang menaruh cookie md5 atau header khusus)
  const setCookie = headers?.get("set-cookie") ?? "";
  if (/(?:wso_version|b374k|alfacgi|c99sh)/i.test(setCookie)) {
    return {
      family: "Active WebShell Session Cookie",
      marker: `Set-Cookie header mengandung signature WebShell (${setCookie.slice(0, 60)})`,
      severity: "CRITICAL",
    };
  }

  // 1. Raw / Unexecuted Obfuscated PHP WebShell Source Code Leak (bukan HTML)
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

  // Parse struktur DOM dengan Cheerio untuk verifikasi elemen nyata
  const $ = cheerio.load(head);
  const titleText = $("title").first().text().trim();
  const hasFileInput = $('input[type="file"]').length > 0;
  const hasPasswordInput = $('input[type="password"]').length > 0;
  const hasWsoHiddenAct = $('input[name="a"], input[name="c"], input[name="p1"], select[name="a"]').length > 0;
  const hasCmdInput =
    $('input[name="cmd"], input[name="command"], input[name="exec"], textarea[name="p1"], textarea[name="code"], textarea[name="php_eval"]').length > 0;

  // 2. WSO / FilesMan WebShell (Verifikasi DOM: hidden input a/c/p1 atau FilesMan table + uname banner)
  if (
    (hasWsoHiddenAct || hasFileInput || hasCmdInput) &&
    /(?:WSO\s+\d+\.\d+|Web\s*Shell\s*by\s*oRb|FilesMan)/i.test(head) &&
    /(?:Uname|Safe\s*mode|Php\s*eval|Server\s*security|Self\s*remove)/i.test(head)
  ) {
    return {
      family: "WSO / FilesMan Interactive WebShell",
      marker: `DOM terverifikasi: form WSO (input[name=a/c/p1]) + sistem telemetri pada <title>${titleText.slice(0, 40)}</title>`,
      severity: "CRITICAL",
    };
  }

  // 3. b374k PHP WebShell (Verifikasi DOM: elemen #terminal / #eval / b374k title + form/script interaktif)
  if (
    (/b374k\s+\d+\.\d+|b374k\s+shell/i.test(titleText) || $("#terminal, #processes, #eval, .b374k").length > 0) &&
    (hasFileInput || hasCmdInput || $("form").length > 0)
  ) {
    return {
      family: "b374k Interactive PHP WebShell",
      marker: `DOM terverifikasi: antarmuka b374k (<title>${titleText.slice(0, 40)}</title>) + modul terminal/eval`,
      severity: "CRITICAL",
    };
  }

  // 4. ALFA Team WebShell (Verifikasi DOM: form/script alfacgiapi / solevisible + elemen kontrol shell)
  if (
    (/(?:Alfa\s+Team|ALFA\s+TEaM\s+Shell|Alfa-Shell|Solevisible)/i.test(titleText) || /alfacgiapi|alfa_data/i.test(head)) &&
    (hasFileInput || hasCmdInput || $("form").length > 0) &&
    /(?:safe_mode|disable_functions|uname|uid=\d+|cgi\s+shell)/i.test(head)
  ) {
    return {
      family: "ALFA Team Interactive WebShell",
      marker: "DOM terverifikasi: struktur ALFA Team Shell + OS command/upload form",
      severity: "CRITICAL",
    };
  }

  // 5. Underground Mini / Stealth WebShells (MariJUANA, Gel4y, IndoXploit, 0byt3m1n1, FoxWSO, AnonSec, c99, r57, p0wny)
  if (
    /(?:MARIJUANA|0x5a455553|Gel4y\s+Mini\s+Shell|IndoXploit|0byt3m1n1|c99shell|r57shell|p0wny@shell)/i.test(head) &&
    (hasFileInput || hasCmdInput || $('input[name="up"], input[name="upload"]').length > 0) &&
    /(?:uid=\d+\(|gid=\d+\(|disable_functions|drwxr-xr-x|-rw-r--r--)/i.test(head)
  ) {
    return {
      family: "Interactive PHP Mini/Stealth WebShell",
      marker: "DOM terverifikasi: form upload/command + tabel permission POSIX & uid/gid",
      severity: "CRITICAL",
    };
  }

  // 6. Generic Active WebShell Telemetry + Interactive File/Command Form
  // Wajib memiliki form interaktif (upload file atau eksekusi command) SEKALIGUS output sistem nyata (uid/gid + kernel uname + permission rwx)
  const hasUnixIdOutput = /\buid=\d+\([a-z0-9_-]+\)\s+gid=\d+\([a-z0-9_-]+\)/i.test(head);
  const hasKernelUname = /\bLinux\s+[^\s<>]{2,50}\s+\d+\.\d+\.\d+[-\w.]*\s+#\d+\s+SMP\b/i.test(head);
  const hasPosixPermTable = /\b(?:drwxr-xr-x|-rw-r--r--|drwxrwxrwx)\b/.test(head);
  const hasDisableFuncBar = /\b(?:disable_functions|safe_mode)\s*[:=]\s*(?:<[^>]+>)?\s*(?:NONE|OFF|ON|exec|system|passthru|shell_exec)/i.test(head);

  if (
    (hasFileInput || hasCmdInput) &&
    ((hasUnixIdOutput && hasPosixPermTable) || (hasKernelUname && hasDisableFuncBar && hasPosixPermTable))
  ) {
    return {
      family: "Active Generic WebShell & File System Console",
      marker: "DOM terverifikasi: form interaktif (<input type=file/cmd>) + output kernel uname/uid/gid & tabel rwx",
      severity: "CRITICAL",
    };
  }

  // 7. Stealth Password-Protected WebShell Gate
  // Halaman sangat kecil (<1.8 KB), HANYA punya 1 form POST dengan 1 input password, TANPA elemen navigasi/header/footer/script framework
  const forms = $("form");
  const scriptsCount = $("script[src]").length;
  if (
    head.length > 40 &&
    head.length < 1800 &&
    forms.length === 1 &&
    hasPasswordInput &&
    $('input:not([type="hidden"]):not([type="submit"])').length === 1 &&
    scriptsCount === 0 &&
    $("nav, footer, header, aside, article, main").length === 0 &&
    (head.split(/\r?\n/).length <= 25 || /(?:auth_pass|b374k|wso|alfa|shell_pass)/i.test(head))
  ) {
    return {
      family: "Stealth Password-Gated WebShell Backdoor",
      marker: "DOM terverifikasi: single-input password POST gate murni (<1.8KB, tanpa layout web standar)",
      severity: "HIGH",
    };
  }

  return null;
}

/**
 * Detektor STRUKTURAL khusus Web-based File Manager (TinyFileManager, elFinder, Responsive FileManager,
 * KCFFinder, Roxy Fileman, KodExplorer, FileGator, WP File Manager).
 * Wajib memverifikasi elemen DOM nyata (`input[name="fm_usr"]`, `#elfinder`, JSON API response `cwd/phash/errUnknownCmd`, dsb.),
 * BUKAN sekadar teks nama file manager!
 */
export function matchFileManagerSignature(
  body: string,
  ct: string
): { name: string; marker: string; severity: Severity; cve?: string[] } | null {
  if (!body || isModernSpaOrArticleShell(body)) return null;
  const head = body.slice(0, 48 * 1024);

  // 1. JSON Connector Response (elFinder / WP File Manager / Roxy Fileman API)
  // Benar-benar memvalidasi struktur JSON objek yang dikembalikan oleh konektor PHP/backend
  if (json(ct, head)) {
    try {
      const parsed = JSON.parse(head) as Record<string, unknown>;
      // elFinder connector.minimal.php terbuka penuh (mengembalikan objek cwd + files/options/api)
      if (
        parsed &&
        typeof parsed === "object" &&
        parsed.cwd &&
        typeof parsed.cwd === "object" &&
        "phash" in (parsed.cwd as Record<string, unknown>) &&
        Array.isArray(parsed.files)
      ) {
        return {
          name: "Studio-42 elFinder Connector API (Unauthenticated Directory Access)",
          marker: 'JSON struktur konektor elFinder valid ({"cwd":{"phash":...},"files":[...]})',
          severity: "CRITICAL",
          cve: ["CVE-2021-32682", "CVE-2020-25213"],
        };
      }
      // elFinder connector aktif merespons perintah kosong dengan {"error":["errUnknownCmd"]}
      if (
        parsed &&
        typeof parsed === "object" &&
        Array.isArray(parsed.error) &&
        parsed.error.includes("errUnknownCmd")
      ) {
        return {
          name: "Studio-42 elFinder / WP File Manager Connector Endpoint",
          marker: 'JSON respons konektor elFinder aktif ({"error":["errUnknownCmd"]})',
          severity: "CRITICAL",
          cve: ["CVE-2020-25213", "CVE-2021-32682"],
        };
      }
    } catch {
      // bukan JSON valid
    }
  }

  if (!html(ct)) return null;

  const $ = cheerio.load(head);
  const titleText = $("title").first().text().trim();

  // 2. TinyFileManager (Verifikasi Struktur DOM: input[name="fm_usr"] & input[name="fm_pwd"] atau tabel #main-table dengan form token)
  const hasTinyLoginInputs = $('input[name="fm_usr"]').length > 0 && $('input[name="fm_pwd"]').length > 0;
  const hasTinyWorkspaceDom =
    $("table#main-table, form#newitemform, div#createNewItem").length > 0 &&
    $('input[name="token"], a[href*="?p="]').length > 0;

  if (hasTinyLoginInputs || hasTinyWorkspaceDom) {
    return {
      name: hasTinyWorkspaceDom
        ? "TinyFileManager (Unauthenticated File System Workspace)"
        : "TinyFileManager Login Console",
      marker: hasTinyWorkspaceDom
        ? "DOM terverifikasi: tabel workspace #main-table & navigasi direktori ?p= terbuka tanpa login"
        : "DOM terverifikasi: form login TinyFileManager (input[name=fm_usr] + input[name=fm_pwd])",
      severity: "CRITICAL",
      cve: ["CVE-2021-45010", "CVE-2022-45474"],
    };
  }

  // 3. Studio-42 elFinder Web UI (Verifikasi Struktur DOM: container #elfinder + script elfinder.min.js/elfinder.full.js + inisialisasi .elfinder({url:...}))
  const hasElfinderContainer = $("#elfinder, .elfinder").length > 0;
  const hasElfinderScript = $('script[src*="elfinder"]').length > 0;
  if (hasElfinderContainer && (hasElfinderScript || /\.elfinder\s*\(\s*\{[\s\S]{0,300}url\s*:/i.test(head))) {
    return {
      name: "Studio-42 elFinder Web File Manager UI",
      marker: "DOM terverifikasi: container #elfinder + script elfinder.js & konfigurasi connector URL",
      severity: "CRITICAL",
      cve: ["CVE-2021-32682", "CVE-2019-9194"],
    };
  }

  // 4. Responsive FileManager (Verifikasi Struktur DOM: input#rfm_subfolder / #ff-item-type-all / script include.min.js)
  if (
    $("input#rfm_subfolder, input#sub_folder, div.uploader, ul.grid.cs-style-2").length >= 2 &&
    /Responsive\s+FileManager/i.test(titleText)
  ) {
    return {
      name: "Responsive FileManager (dialog.php Workspace)",
      marker: "DOM terverifikasi: struktur input#rfm_subfolder + grid file explorer Responsive FileManager",
      severity: "CRITICAL",
      cve: ["CVE-2020-26045"],
    };
  }

  // 5. KCFinder Web File Manager (Verifikasi Struktur DOM: #folders + #files + script kcfinder)
  if ($("#folders").length > 0 && $("#files").length > 0 && /KCFinder/i.test(titleText)) {
    return {
      name: "KCFinder Web File Manager (browse.php)",
      marker: "DOM terverifikasi: panel #folders + #files pada KCFinder browse.php",
      severity: "HIGH",
      cve: ["CVE-2019-14315"],
    };
  }

  // 6. Roxy Fileman (Verifikasi Struktur DOM: #pnlDirList + #pnlFileList + conf.json)
  if ($("#pnlDirList").length > 0 && $("#pnlFileList").length > 0) {
    return {
      name: "Roxy Fileman Web File Manager",
      marker: "DOM terverifikasi: elemen #pnlDirList & #pnlFileList Roxy Fileman",
      severity: "CRITICAL",
      cve: ["CVE-2018-20526"],
    };
  }

  // 7. KodExplorer / FileGator / FileRun (Verifikasi Struktur DOM spesifik aplikasi)
  if (
    ($('meta[name="generator"][content*="KodExplorer"]').length > 0 ||
      $("div.frame-main, div#filegator, body.kod-login").length > 0) &&
    /(?:KodExplorer|KodBox|FileGator|FileRun)/i.test(titleText)
  ) {
    return {
      name: "Standalone Web File Manager (KodExplorer / FileGator / FileRun)",
      marker: `DOM terverifikasi: container aplikasi pada <title>${titleText.slice(0, 40)}</title>`,
      severity: "HIGH",
    };
  }

  return null;
}

/**
 * Inspeksi pasif terhadap setiap halaman yang sudah di-crawl (`CrawledPage`) untuk mendeteksi
 * apabila halaman tersebut ternyata adalah WebShell atau FileManager WebShell aktif (tanpa peduli apa nama filenya).
 */
export function inspectCrawledPageForShellOrFileManager(page: {
  url: string;
  status: number;
  contentType?: string;
  html?: string;
}): Finding | null {
  if (page.status !== 200 || !page.html) return null;
  const ct = (page.contentType ?? "text/html").toLowerCase();

  const ws = matchWebshellSignature(page.html);
  if (ws) {
    return {
      id: `ws_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
      severity: ws.severity,
      title: `[WebShell Backdoor] ${ws.family} aktif terverifikasi secara struktural`,
      endpoint: page.url,
      evidence: `HTTP ${page.status} — ${ws.marker}`,
      impact:
        "Halaman ini terverifikasi secara struktural (DOM/form/telemetri sistem) sebagai WebShell backdoor aktif yang memberikan akses Remote Code Execution (RCE) dan kontrol sistem file penuh.",
      fix: FIX_WEBSHELL,
      cwe: "CWE-434, CWE-94, CWE-506",
      rce: true,
      confidence: "verified",
      category: "webshell",
    };
  }

  const fm = matchFileManagerSignature(page.html, ct);
  if (fm) {
    return {
      id: `fm_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
      severity: fm.severity,
      title: `[FileManager WebShell] ${fm.name} terverifikasi secara struktural`,
      endpoint: page.url,
      evidence: `HTTP ${page.status} — ${fm.marker}`,
      impact:
        "Panel Web File Manager atau konektor API file manager terverifikasi aktif di URL ini. Penyerang dapat memanfaatkannya untuk mengunggah backdoor, memodifikasi source code, atau mengunduh konfigurasi sensitif.",
      fix: FIX_FILEMANAGER,
      cwe: "CWE-434, CWE-306, CWE-284",
      cve: fm.cve,
      rce: true,
      confidence: "verified",
      category: "filemanager-shell",
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

  // ==================== 7. webshell (Active WebShell Backdoors — Structural DOM & Telemetry Validated) ====================
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
      marker: "Structural WebShell DOM / System Command Telemetry",
      validate: (b, _ct, _st, headers) => matchWebshellSignature(b, headers)?.severity ?? null,
      impact:
        "File WebShell / Backdoor aktif terdeteksi secara struktural di server! Penyerang memiliki kendali Remote Code Execution (RCE), pembacaan/modifikasi seluruh filesystem, akses database, dan pivot ke jaringan internal.",
      fix: FIX_WEBSHELL,
    })
  ),

  // ==================== 8. filemanager-shell (Exposed Web File Managers — Structural DOM & JSON Connector Validated) ====================
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
      marker: "Structural Web File Manager DOM / JSON Connector",
      validate: (b, ct) => matchFileManagerSignature(b, ct)?.severity ?? null,
      impact:
        "Panel Web File Manager atau konektor JSON-nya terverifikasi terbuka di webroot publik. Sering digunakan sebagai FileManager WebShell untuk mengunggah backdoor PHP, mengedit source code produksi, atau mengunduh file konfigurasi rahasia (.env / wp-config.php).",
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

export function evaluateRceSpec(
  spec: Spec,
  status: number,
  ct: string,
  body: string,
  headers?: Headers
): Severity | null {
  if (status !== 200 && !(spec.path === "/xmlrpc.php" && status === 405)) return null;
  return spec.validate(body, ct.toLowerCase(), status, headers);
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

    const sev = evaluateRceSpec(spec, r.status, r.ct, r.text, r.headers);
    if (!sev) continue;

    let exactMarker = spec.marker;
    let exactTitle = spec.title;
    if (spec.vector === "webshell") {
      const ws = matchWebshellSignature(r.text, r.headers);
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
