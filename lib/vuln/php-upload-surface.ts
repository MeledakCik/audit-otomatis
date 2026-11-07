/**
 * PHP Upload Surface & Upload-Directory Backdoor Audit — PASIF (GET only).
 *
 * Yang dicek:
 *  1. Form upload file pada halaman hasil crawl (hanya membaca atribut HTML; TIDAK ada upload).
 *  2. Direktori upload umum (+ yang terlihat dari link/src/action di halaman): directory listing
 *     terbuka, dan apakah di dalamnya ada file script (.php/.phtml/.phar/...) atau nama ganda
 *     (shell.php.jpg, x.jpg.php) atau nama mencurigakan.
 *  3. File script yang TERLIHAT di direktori upload: diambil dengan GET dan diklasifikasi:
 *       - dieksekusi server (tidak ada `<?php` di respons)  → PHP bisa jalan di dir upload
 *       - source terbaca (`<?php` di respons)               → handler PHP tidak aktif, tapi source bocor
 *       - struktur WebShell cocok (reuse matchWebshellSignature) → backdoor aktif terverifikasi
 *  3b. Static signature pada source PHP yang bocor (eval(base64_decode(...)), system($_GET[..]), dst).
 *  4. File konfigurasi persistensi di direktori upload yang terbaca publik:
 *     .htaccess (AddType/AddHandler/SetHandler ke PHP) dan .user.ini (auto_prepend_file).
 *
 * BATAS PASIF (sengaja):
 *  - Modul ini TIDAK mengunggah file apa pun, jadi TIDAK bisa membuktikan "upload .php lalu kebuka".
 *    Ia mendeteksi (a) permukaan upload, (b) bukti bahwa file script sudah ada & dilayani di dir upload,
 *    (c) konfigurasi yang memungkinkannya. Uji upload sungguhan = aktif → butuh izin tertulis & manual.
 *  - Hanya URL yang (i) ada di daftar direktori tetap, (ii) muncul di halaman crawl, atau
 *    (iii) muncul di directory listing yang dipakai. Tidak ada tebak-nama brute force.
 *  - Evidence TIDAK pernah memuat isi respons penuh; hanya status, content-type, label sinyal.
 */
import * as cheerio from "cheerio";
import type { Finding, FormInfo, Severity } from "@/lib/types";
import { chromeHeaders, detectCloudflareChallenge } from "@/lib/crawler";
import type { RequestBudget } from "@/lib/rate-limit";
import type { RceSurfaceEvidence } from "@/lib/sentinel/dossier";
import { matchWebshellSignature } from "@/lib/vuln/rce-surface";

// ---------- Konstanta ----------

/** Direktori upload umum yang di-GET (maks sebagian dipakai sesuai budget). */
export const UPLOAD_DIRS = [
  "/uploads/",
  "/upload/",
  "/wp-content/uploads/",
  "/files/",
  "/userfiles/",
  "/user_files/",
  "/storage/",
  "/media/",
  "/attachments/",
  "/assets/uploads/",
  "/public/uploads/",
  "/static/uploads/",
  "/images/uploads/",
  "/content/uploads/",
  "/tmp/",
] as const;

const SCRIPT_EXT = "(?:php[0-9]?|phtml|pht|phar|phps)";
/** File dengan ekstensi script PHP (termasuk query/fragment setelahnya). */
const SCRIPT_FILE_RE = new RegExp(`\\.${SCRIPT_EXT}(?=$|[?#;/])`, "i");
/** Double extension: x.php.jpg  atau  x.jpg.php  atau  x.php;.jpg  */
const DOUBLE_EXT_RE = new RegExp(
  `\\.${SCRIPT_EXT}\\.(?:jpe?g|png|gif|webp|bmp|ico|txt|pdf|zip)$|\\.(?:jpe?g|png|gif|webp|bmp|ico|txt|pdf|zip)\\.${SCRIPT_EXT}$|\\.${SCRIPT_EXT};\\.`,
  "i"
);
/** Nama berkas yang khas dipakai backdoor/uploader (heuristik, confidence rendah). */
const SUSPICIOUS_NAME_RE =
  /(?:^|[\/_.-])(?:shell|cmd|c99|r57|wso|b374k|alfa|indoxploit|mini|uploader?|up|x|xx|1|0|a|bak|backdoor|bd|hack(?:ed)?|gel4y|marijuana|filesman|404|wp-?(?:feed|tmp|vcd))\.(?:php[0-9]?|phtml|pht|phar)$/i;

const MAX_BODY = 64 * 1024;
const UPLOAD_SEGMENT_RE =
  /\/(?:wp-content\/uploads|uploads?|files?|userfiles|user_files|storage|media|attachments?|tmp|temp)\//i;

// ---------- Util ----------

const newId = () => `pu_${Math.random().toString(36).slice(2)}${Date.now().toString(36)}`;

function sameOrigin(origin: string, u: string): URL | null {
  try {
    const url = new URL(u, origin);
    return url.origin === new URL(origin).origin ? url : null;
  } catch {
    return null;
  }
}

function trunc(s: string, n = 100): string {
  const c = s.replace(/\s+/g, " ").trim();
  return c.length > n ? c.slice(0, n) + "…" : c;
}

interface Fetched {
  status: number;
  ct: string;
  headers: Headers;
  text: string;
}

async function getText(
  url: string,
  budget: RequestBudget,
  origin: string,
  cfClearance?: string
): Promise<Fetched | null> {
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
      const text = (await res.text()).slice(0, MAX_BODY);
      return { status: res.status, headers: res.headers, text, ct: (res.headers.get("content-type") ?? "").toLowerCase() };
    } catch {
      return null;
    } finally {
      clearTimeout(t);
    }
  });
  if (!r) return null;
  if (detectCloudflareChallenge(r.status, r.headers, r.text.slice(0, 2000))) return null;
  return r;
}

// ---------- 1. Form upload (tanpa request) ----------

export function analyzeUploadForms(forms: FormInfo[], origin: string): Finding[] {
  const out: Finding[] = [];
  const seen = new Set<string>();

  for (const f of forms) {
    if (!f.fileInputs?.length) continue;
    const page = f.pageUrl ?? f.action;
    const key = `${f.action}|${f.fileInputs.map((i) => i.name).join(",")}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const actionUrl = sameOrigin(origin, f.action);
    const actionIsScript = !!actionUrl && SCRIPT_FILE_RE.test(actionUrl.pathname);
    const acceptAll = f.fileInputs.some((i) => !i.accept);
    const acceptPhp = f.fileInputs.some((i) => i.accept && /php|x-httpd|\*\/\*|application\/octet-stream/i.test(i.accept));
    const noCsrf = !f.hasCsrfToken;

    let severity: Severity = "LOW";
    const notes: string[] = [];
    if (acceptPhp) {
      severity = "HIGH";
      notes.push("atribut accept mengizinkan tipe script/semua tipe");
    }
    if (actionIsScript) {
      if (severity === "LOW") severity = "MEDIUM";
      notes.push(`action langsung ke file script (${actionUrl!.pathname})`);
    }
    if (noCsrf && severity === "LOW") {
      notes.push("tidak ada hidden token CSRF/nonce terdeteksi");
    }
    if (acceptAll) notes.push("tidak ada atribut accept (catatan: accept hanya client-side, bukan kontrol keamanan)");
    if (f.method.toUpperCase() !== "POST") notes.push(`method ${f.method}`);

    out.push({
      id: newId(),
      severity,
      title: `[PHP Upload Surface] Form upload file ditemukan (${f.fileInputs.length} input file)`,
      endpoint: page,
      evidence: trunc(
        `form action=${f.action} method=${f.method} enctype=${f.enctype ?? "-"} ; ${notes.join("; ") || "form upload standar"}`,
        100
      ),
      impact:
        "Titik unggah file terdeteksi secara pasif. Jika validasi sisi server lemah (ekstensi/MIME/isi file) dan folder tujuan mengeksekusi PHP, file .php/.phtml/.phar bisa diunggah dan dijalankan (CWE-434 → RCE). Modul ini TIDAK menguji upload; ini hanya menandai permukaan serangan.",
      fix: "Validasi di server: allowlist ekstensi + deteksi MIME dari isi file, rename file acak tanpa ekstensi asli, simpan di luar webroot atau di storage terpisah, nonaktifkan eksekusi PHP di folder upload (nginx: `location ~* ^/uploads/.*\\.(php|phtml|phar)$ { deny all; }`; Apache: `php_admin_flag engine off` atau `RemoveHandler .php .phtml .phar`), tambahkan CSRF token & autentikasi, batasi ukuran.",
      cwe: "CWE-434, CWE-646",
      confidence: "verified",
      category: "php-upload",
      poc: `# Verifikasi manual (butuh izin tertulis): upload file uji non-eksekusi lalu cek apakah ekstensi .php ditolak\n# Pasif: tidak ada request upload yang dijalankan oleh auditor ini.`,
    });
  }
  return out;
}

// ---------- 2. Referensi script di dir upload dari halaman crawl ----------

export function extractUploadScriptRefs(
  pages: { url: string; html?: string }[],
  origin: string
): { script: string[]; dirs: string[] } {
  const scripts = new Set<string>();
  const dirs = new Set<string>();
  const urlRe = /(?:href|src|action|data-[a-z-]+|content)\s*=\s*["']([^"'<>\s]+)["']|["'](\/[^"'<>\s]*(?:uploads?|files?|media|storage)\/[^"'<>\s]*)["']/gi;

  for (const p of pages) {
    if (!p.html) continue;
    for (const m of p.html.matchAll(urlRe)) {
      const raw = m[1] ?? m[2];
      if (!raw) continue;
      const u = sameOrigin(p.url || origin, raw);
      if (!u) continue;
      if (!UPLOAD_SEGMENT_RE.test(u.pathname)) continue;
      u.hash = "";
      if (SCRIPT_FILE_RE.test(u.pathname) || DOUBLE_EXT_RE.test(u.pathname)) {
        scripts.add(u.origin + u.pathname + u.search);
      }
      const dir = u.pathname.replace(/[^/]*$/, "");
      if (UPLOAD_SEGMENT_RE.test(dir)) dirs.add(u.origin + dir);
    }
  }
  return { script: Array.from(scripts), dirs: Array.from(dirs) };
}

// ---------- 3. Directory listing ----------

export function parseDirectoryListing(body: string): string[] | null {
  if (!/<title>\s*Index of\s|<h1>\s*Index of\s|<title>\s*Directory listing for/i.test(body)) return null;
  const $ = cheerio.load(body);
  const names: string[] = [];
  $("a[href]").each((_, el) => {
    const href = ($(el).attr("href") || "").trim();
    if (!href || href.startsWith("?") || href.startsWith("#") || href.startsWith("/") || href.includes("://")) return;
    if (href === "../" || href === "./") return;
    try {
      names.push(decodeURIComponent(href));
    } catch {
      names.push(href);
    }
  });
  return Array.from(new Set(names)).slice(0, 500);
}

export interface ListingClass {
  scripts: string[];
  doubleExt: string[];
  suspicious: string[];
}

export function classifyListing(names: string[]): ListingClass {
  const scripts: string[] = [];
  const doubleExt: string[] = [];
  const suspicious: string[] = [];
  for (const n of names) {
    if (n.endsWith("/")) continue;
    if (DOUBLE_EXT_RE.test(n)) doubleExt.push(n);
    else if (SCRIPT_FILE_RE.test(n)) scripts.push(n);
    if (SUSPICIOUS_NAME_RE.test(n) && !scripts.includes(n)) suspicious.push(n);
  }
  return { scripts, doubleExt, suspicious };
}

// ---------- 3b. Static signature pada source PHP yang bocor ----------

const PHP_BACKDOOR_SIGNS: { label: string; re: RegExp }[] = [
  { label: "eval(base64_decode/gzinflate/str_rot13)", re: /\beval\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|str_rot13|rawurldecode)\s*\(/i },
  { label: "eval/assert dari input HTTP", re: /\b(?:eval|assert)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i },
  { label: "system/exec/passthru dari input HTTP", re: /\b(?:system|shell_exec|passthru|exec|popen|proc_open)\s*\(\s*\$_(?:GET|POST|REQUEST|COOKIE)\b/i },
  { label: "variable function dari input HTTP ($_X[..](..))", re: /\$_(?:GET|POST|REQUEST|COOKIE)\s*\[[^\]]+\]\s*\(/ },
  { label: "preg_replace modifier /e", re: /preg_replace\s*\(\s*["'][^"']*\/[a-z]*e[a-z]*["']/i },
  { label: "create_function dengan input", re: /\bcreate_function\s*\([^)]*\$_(?:GET|POST|REQUEST)/i },
  { label: "move_uploaded_file tanpa pengecekan terlihat", re: /\bmove_uploaded_file\s*\(\s*\$_FILES\s*\[[^\]]+\]\s*\[\s*["']tmp_name["']\s*\]\s*,\s*[^;]*\$_FILES\s*\[[^\]]+\]\s*\[\s*["']name["']\s*\]/i },
  { label: "string penanda webshell (FilesMan/c99/r57/WSO)", re: /\b(?:FilesMan|c99shell|r57shell|WSO\s*[0-9.]*|b374k)\b/i },
  { label: "auto_prepend_file / auto_append_file", re: /auto_(?:prepend|append)_file/i },
];

export function analyzePhpSource(text: string): string[] {
  const hits: string[] = [];
  for (const s of PHP_BACKDOOR_SIGNS) if (s.re.test(text)) hits.push(s.label);
  return hits;
}

// ---------- 4. Persistensi: .htaccess & .user.ini ----------

export function analyzeHtaccess(text: string): { risky: string[]; safe: boolean } {
  const risky: string[] = [];
  if (/^\s*(?:AddType|AddHandler|SetHandler)\b[^\n]*(?:php|application\/x-httpd)/im.test(text)) {
    const m = text.match(/^\s*(?:AddType|AddHandler|SetHandler)\b[^\n]*(?:php|application\/x-httpd)[^\n]*/im);
    const mapsNonPhp = m ? /\.(?:jpe?g|png|gif|txt|jpg|ico|pdf|html?|css|js)\b/i.test(m[0]) : false;
    risky.push(mapsNonPhp ? "AddType/AddHandler memetakan ekstensi non-PHP ke PHP" : "AddType/AddHandler/SetHandler ke PHP");
  }
  if (/php_flag\s+engine\s+on/i.test(text)) risky.push("php_flag engine on");
  if (/auto_(?:prepend|append)_file/i.test(text)) risky.push("auto_prepend/append_file");
  const safe = /php_(?:admin_)?flag\s+engine\s+off|RemoveHandler\s+\.php|RemoveType\s+\.php/i.test(text);
  return { risky, safe };
}

// ---------- Orkestrasi ----------

export interface PhpUploadResult {
  findings: Finding[];
  evidence: RceSurfaceEvidence[];
  requests: number;
}

function rce(sev: Severity, title: string, endpoint: string, evidenceLine: string, impact: string, fix: string, extra: Partial<Finding> = {}): Finding {
  return {
    id: newId(),
    severity: sev,
    title,
    endpoint,
    evidence: trunc(evidenceLine, 100),
    impact,
    fix,
    cwe: "CWE-434, CWE-94",
    confidence: "verified",
    category: "php-upload",
    ...extra,
  };
}

const FIX_UPLOAD_DIR =
  "Nonaktifkan eksekusi script di folder upload (nginx: `location ~* ^/(uploads|wp-content/uploads|files)/.*\\.(php[0-9]?|phtml|phar)$ { deny all; }`; Apache: `php_admin_flag engine off` + `RemoveHandler .php .phtml .phar`), matikan autoindex (`Options -Indexes` / `autoindex off`), hapus file script yang tidak dikenal, lalu telusuri akar masuknya (log upload, plugin/CMS rentan) dan rotasi kredensial.";

export async function checkPhpUploadSurface(
  origin: string,
  pages: { url: string; html?: string }[],
  forms: FormInfo[],
  budget: RequestBudget,
  cfClearance?: string,
  onLog?: (m: string) => void | Promise<void>
): Promise<PhpUploadResult> {
  const out: PhpUploadResult = { findings: [], evidence: [], requests: 0 };
  const before = budget.count;
  const note = async (m: string) => {
    if (onLog) await onLog(m);
  };

  // 1) Form upload — tanpa request.
  out.findings.push(...analyzeUploadForms(forms, origin));

  // 2) Referensi dari halaman crawl.
  const refs = extractUploadScriptRefs(pages, origin);

  // 3) Direktori kandidat: daftar tetap + yang terlihat di halaman (dedupe, batasi).
  const dirSet = new Map<string, string>();
  for (const d of UPLOAD_DIRS) dirSet.set(new URL(d, origin).toString(), d);
  for (const d of refs.dirs.slice(0, 8)) dirSet.set(d, new URL(d).pathname);

  const scriptCandidates = new Map<string, { source: string; inListing: boolean; name: string }>();
  for (const s of refs.script.slice(0, 8)) {
    scriptCandidates.set(s, { source: "referensi di halaman", inListing: false, name: s.split("/").pop() ?? s });
  }
  const dirsWithEvidence: string[] = [];

  for (const [dirUrl, dirPath] of dirSet) {
    if (!budget.canSpend(1)) break;
    const r = await getText(dirUrl, budget, origin, cfClearance);
    if (!r || r.status !== 200) continue;
    const names = parseDirectoryListing(r.text);
    if (!names) continue;

    dirsWithEvidence.push(dirUrl);
    const cls = classifyListing(names);
    const flagged = cls.scripts.length + cls.doubleExt.length;
    const sev: Severity = flagged > 0 ? "HIGH" : "MEDIUM";

    out.findings.push(
      rce(
        sev,
        flagged > 0
          ? `[PHP Upload Dir] Directory listing terbuka dan memuat ${flagged} file script/nama ganda di ${dirPath}`
          : `[PHP Upload Dir] Directory listing terbuka pada ${dirPath}`,
        dirUrl,
        `HTTP 200 Index of — ${names.length} entri; script=${cls.scripts.slice(0, 3).join(",") || "-"}; dobel=${cls.doubleExt.slice(0, 3).join(",") || "-"}`,
        flagged > 0
          ? "Folder upload terbuka dan berisi file berekstensi script (.php/.phtml/.phar) atau nama ganda (mis. shell.php.jpg). Ini indikator kuat webshell/backdoor hasil unggahan atau konfigurasi upload yang lolos validasi ekstensi."
          : "Indeks folder upload terbuka memudahkan pemetaan file pengguna, backup, dan file sensitif; juga membantu penyerang menemukan file yang sudah diunggah.",
        FIX_UPLOAD_DIR,
        { cwe: "CWE-548, CWE-434" }
      )
    );
    out.evidence.push({
      path: dirPath,
      title: "Directory listing upload",
      severity: sev,
      cwe: ["CWE-548", "CWE-434"],
      cve: [],
      status: 200,
      marker: "Index of",
      snippet: names.slice(0, 20).join(", ").slice(0, 300),
    });

    for (const n of [...cls.scripts, ...cls.doubleExt, ...cls.suspicious].slice(0, 6)) {
      const u = new URL(n, dirUrl).toString();
      if (!scriptCandidates.has(u)) scriptCandidates.set(u, { source: `listing ${dirPath}`, inListing: true, name: n });
    }
  }

  // 4) Ambil tiap file script kandidat (maks 10) dan klasifikasi.
  let fetchedScripts = 0;
  for (const [url, meta] of scriptCandidates) {
    if (fetchedScripts >= 10 || !budget.canSpend(1)) break;
    fetchedScripts++;
    const r = await getText(url, budget, origin, cfClearance);
    if (!r || r.status !== 200) continue;

    const isPhpSource = /<\?(?:php|=)/i.test(r.text.slice(0, MAX_BODY));
    const phpCt = /x-httpd-php|x-php|application\/php/i.test(r.ct);
    const path = new URL(url).pathname;

    // Struktur webshell aktif → verifikasi paling kuat (reuse detektor struktural yang sudah ada).
    const ws = !isPhpSource ? matchWebshellSignature(r.text, r.headers) : null;
    if (ws) {
      out.findings.push(
        rce(
          "CRITICAL",
          `[WebShell Backdoor] ${ws.family} aktif di folder upload (${path})`,
          url,
          `HTTP 200 — ${ws.marker}; asal: ${meta.source}`,
          "File PHP di folder upload dilayani dan dieksekusi, dan strukturnya cocok dengan WebShell aktif → akses RCE & file system penuh bagi siapa pun yang tahu URL ini.",
          FIX_UPLOAD_DIR,
          { severity: "CRITICAL", rce: true, category: "webshell" }
        )
      );
      out.evidence.push({ path, title: `WebShell ${ws.family} di upload dir`, severity: "CRITICAL", cwe: ["CWE-434", "CWE-506"], cve: [], status: 200, marker: ws.marker, snippet: trunc(r.text, 300) });
      continue;
    }

    if (isPhpSource) {
      const hits = analyzePhpSource(r.text);
      const sev: Severity = hits.length ? "HIGH" : "MEDIUM";
      out.findings.push(
        rce(
          sev,
          hits.length
            ? `[PHP Backdoor Indicator] Source PHP terbaca di folder upload dengan pola berbahaya (${path})`
            : `[PHP Upload Dir] Source PHP terbaca di folder upload (${path})`,
          url,
          `HTTP 200 source "<?php" terbaca; sinyal: ${hits.slice(0, 3).join("; ") || "tidak ada pola backdoor yang cocok"}; asal: ${meta.source}`,
          hits.length
            ? "Source PHP yang bocor di folder upload mengandung pola khas backdoor (eval/base64, system dari input HTTP, dll). Handler PHP pada folder ini tampak tidak aktif, tapi file berbahaya sudah ada di server dan bisa menjadi aktif bila konfigurasi berubah atau dipindah."
            : "File script berada di folder upload dan source-nya dapat dibaca publik (kebocoran kode/konfigurasi), serta menandakan folder ini menerima file berekstensi script.",
          FIX_UPLOAD_DIR,
          { cwe: "CWE-540, CWE-434" }
        )
      );
      out.evidence.push({ path, title: "Source PHP terbaca di upload dir", severity: sev, cwe: ["CWE-540", "CWE-434"], cve: [], status: 200, marker: hits[0] ?? "<?php", snippet: hits.join("; ").slice(0, 300) });
      continue;
    }

    // Respons 200 tanpa `<?php` pada URL berekstensi script = dijalankan oleh handler PHP.
    const empty = r.text.trim().length === 0;
    // index.php kosong = placeholder "Silence is golden" bawaan WordPress/Joomla; bukan temuan.
    if (empty && /^index\.php$/i.test(path.split("/").pop() ?? "")) continue;
    const executedLike = SCRIPT_FILE_RE.test(path) && !phpCt;
    if (executedLike) {
      const suspicious = SUSPICIOUS_NAME_RE.test(meta.name);
      const sev: Severity = "HIGH";
      out.findings.push(
        rce(
          sev,
          `[PHP Upload Dir] File PHP dilayani/dieksekusi dari folder upload (${path})`,
          url,
          `HTTP 200 ct=${r.ct || "-"} len=${r.text.length}${empty ? " (kosong)" : ""}; nama ${suspicious ? "mencurigakan" : "biasa"}; asal: ${meta.source}`,
          "Server mengembalikan 200 untuk file berekstensi script di folder upload tanpa menampilkan source — artinya handler PHP aktif di folder ini. Jika folder ini menerima unggahan pengguna, siapa pun yang berhasil menaruh file .php dapat menjalankan kode. Respons kosong 200 juga khas loader/backdoor yang menunggu parameter tersembunyi (indikator, bukan bukti).",
          FIX_UPLOAD_DIR,
          { rce: true }
        )
      );
      out.evidence.push({ path, title: "PHP dieksekusi di upload dir", severity: sev, cwe: ["CWE-434", "CWE-94"], cve: [], status: 200, marker: `ct=${r.ct || "-"} len=${r.text.length}`, snippet: trunc(r.text, 300) });
    } else if (phpCt) {
      out.findings.push(
        rce(
          "MEDIUM",
          `[PHP Upload Dir] File script dilayani dengan Content-Type PHP (${path})`,
          url,
          `HTTP 200 Content-Type: ${r.ct}; asal: ${meta.source}`,
          "Content-Type PHP pada folder upload menandakan mapping handler PHP aktif atau file diunduh sebagai source.",
          FIX_UPLOAD_DIR
        )
      );
    }
  }

  // 5) Persistensi: .htaccess / .user.ini pada folder upload yang terbukti relevan (listing terbuka / ada referensi).
  const persistDirs = Array.from(new Set([...dirsWithEvidence, ...refs.dirs])).slice(0, 4);
  for (const d of persistDirs) {
    for (const f of [".htaccess", ".user.ini"]) {
      if (!budget.canSpend(1)) break;
      const url = new URL(f, d).toString();
      const r = await getText(url, budget, origin, cfClearance);
      if (!r || r.status !== 200 || /<html/i.test(r.text.slice(0, 200))) continue;
      const path = new URL(url).pathname;

      if (f === ".htaccess") {
        const a = analyzeHtaccess(r.text);
        if (a.risky.length) {
          out.findings.push(
            rce(
              "HIGH",
              `[PHP Backdoor Indicator] .htaccess di folder upload memetakan eksekusi PHP (${path})`,
              url,
              `HTTP 200 .htaccess terbaca; sinyal: ${a.risky.join("; ")}`,
              "Aturan handler PHP di folder upload (terutama yang memetakan ekstensi non-PHP seperti .jpg ke PHP) adalah teknik umum persistensi: file 'gambar' dapat dieksekusi sebagai PHP.",
              FIX_UPLOAD_DIR,
              { rce: true }
            )
          );
        } else if (!a.safe) {
          out.findings.push(
            rce("LOW", `[PHP Upload Dir] .htaccess folder upload dapat dibaca publik (${path})`, url, "HTTP 200 .htaccess terbaca; tanpa sinyal handler PHP", "File konfigurasi server terbaca publik membocorkan aturan akses/rewrite.", "Blokir akses ke dotfile (`<FilesMatch \"^\\.\">Require all denied</FilesMatch>` atau `location ~ /\\. { deny all; }`).", { cwe: "CWE-538" })
          );
        }
      } else {
        if (/auto_(?:prepend|append)_file\s*=/i.test(r.text)) {
          out.findings.push(
            rce(
              "HIGH",
              `[PHP Backdoor Indicator] .user.ini di folder upload memakai auto_prepend_file (${path})`,
              url,
              "HTTP 200 .user.ini terbaca; auto_prepend/append_file terdeteksi",
              "auto_prepend_file pada folder upload memaksa PHP menjalankan file lain di setiap request — teknik persistensi backdoor yang sering luput dari pengecekan file .php biasa.",
              FIX_UPLOAD_DIR,
              { rce: true, cwe: "CWE-506, CWE-94" }
            )
          );
        }
      }
    }
  }

  out.requests = budget.count - before;
  await note(
    `[PHP-UPLOAD] ${out.findings.length} temuan; ${dirsWithEvidence.length} direktori upload terbuka; ${fetchedScripts} file script diperiksa (${out.requests} request GET).`
  );
  return out;
}
