/**
 * Audit File Sensitif — mesin analisis & katalog (PASIF, GET-only).
 *
 * Prinsip:
 *  - TRUE POSITIVE: status 200 + isi cocok penanda nyata (bukan SPA/soft-404/artikel).
 *  - Nilai rahasia TIDAK pernah keluar ke publik. Publik hanya menerima jenis + jumlah.
 *  - Kredensial TIDAK PERNAH diuji/dipakai (tidak ada panggilan ke AWS/GitHub/DB). Semua offline.
 */
import { createHash } from "node:crypto";
import type { Component } from "./dossier";
import {
  BACKUP_REMEDIATION,
  COMMON_REMEDIATION,
  REMEDIATION,
  SECRET_LABELS,
  type ComposerSummary,
  type SecretFinding,
  type SecretType,
  type SensitiveAnalysis,
  type SensitiveCategory,
} from "./sensitive-types";

// ======================= util dasar =======================

export interface SensitiveResponse {
  status: number;
  contentType: string;
  text: string;
  head: Uint8Array; // ≤512 byte pertama
  size?: number;
  lastModified?: string;
  etag?: string;
}
export interface Baseline { status: number; length: number }
export interface ValidateCtx { baseline?: Baseline }

const sha12 = (s: string) => createHash("sha256").update(s).digest("hex").slice(0, 12);

export function shannon(s: string): number {
  if (!s) return 0;
  const f = new Map<string, number>();
  for (const c of s) f.set(c, (f.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of f.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}

export const looksLikeHtml = (s: string) => /<(!doctype|html|head|body)\b/i.test(s.slice(0, 600));

export function humanSize(n?: number): string {
  if (!n || n < 0) return "";
  const u = ["B", "KB", "MB", "GB", "TB"];
  let i = 0, v = n;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return `${v.toFixed(v >= 10 || i === 0 ? 0 : 1)} ${u[i]}`;
}

/** ID akun AWS dari access key ID — murni offline (base32), tanpa menghubungi AWS. */
export function awsAccountFromKeyId(id: string): string | undefined {
  const body = id.slice(4);
  if (!/^[A-Z2-7]{16}$/.test(body)) return undefined;
  const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const FIVE = BigInt(5);
  const THIRTYTWO = BigInt(32);
  const SEVEN = BigInt(7);
  const MASK = BigInt("0x7fffffffff80");
  let bits = BigInt(0);
  for (const ch of body) bits = (bits << FIVE) | BigInt(B32.indexOf(ch));
  const first48 = bits >> THIRTYTWO;
  return String((first48 & MASK) >> SEVEN).padStart(12, "0");
}

// ======================= placeholder / redaksi =======================

const PREFIX_PLACEHOLDER = /^(?:your[-_ ]|change[-_ ]?me|replace[-_ ]?me|enter[-_ ]|insert[-_ ]|example|sample|dummy|placeholder|todo|fixme|<|\$\{|\{\{|%[A-Za-z_]+%|\$[A-Za-z_]|process\.env)/i;
const WHOLE_PLACEHOLDER = /^(?:test(?:ing)?|null|none|nil|undefined|false|true|secret|password|passwd|admin|root|default|homestead|laravel|1234(?:5678?)?|123456|x{3,}|\*{3,}|\.{3,})$/i;

/** return alasan bila TIDAK tampak nilai nyata; null bila tampak nyata. */
export function placeholderReason(v: string): string | null {
  const s = v.trim();
  if (s.length < 3) return "kosong/terlalu pendek";
  if (/^(.)\1+$/.test(s)) return "karakter berulang";
  if (PREFIX_PLACEHOLDER.test(s) || WHOLE_PLACEHOLDER.test(s)) return "placeholder/default";
  if (/EXAMPLE/.test(s)) return "contoh dokumentasi";
  if (/^\d{1,7}$/.test(s)) return "angka pendek (bukan secret)";
  if (s.length >= 20 && shannon(s) < 2.2) return "entropi rendah";
  return null;
}

export function redact(v: string): string {
  return v.length >= 12 ? `${v.slice(0, 4)}…${v.slice(-2)} (${v.length} char)` : `${v.slice(0, 1)}… (${v.length} char)`;
}

// ======================= ekstraksi pasangan key/value =======================

export interface Pair { key: string; value: string }

const LINE_KV = /^[ \t]*(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_.\-]{1,80})[ \t]*[=:][ \t]*(.*?)[ \t]*$/;
const JSON_KV = /"([A-Za-z0-9_.\-]{2,80})"\s*:\s*"([^"\\]{1,400})"/g;
const PHP_DEFINE = /define\(\s*['"]([A-Za-z0-9_]+)['"]\s*,\s*['"]([^'"]*)['"]\s*\)/g;
const PHP_ARROW = /['"]([A-Za-z0-9_]+)['"]\s*=>\s*['"]([^'"]*)['"]/g;
const PHP_VAR = /\$[A-Za-z_][A-Za-z0-9_]*(?:\[\s*['"]([A-Za-z0-9_]+)['"]\s*\])?\s*=\s*['"]([^'"]*)['"]\s*;/g;
const PHP_VAR_NAMED = /\$([A-Za-z_][A-Za-z0-9_]*)\s*=\s*['"]([^'"]*)['"]\s*;/g;

function unquote(v: string): string {
  let s = v.trim();
  const q = /^(["'])(.*)\1/.exec(s);
  if (q) return q[2];
  s = s.replace(/\s+#.*$/, "").replace(/,$/, "");
  return s.replace(/^["']|["']$/g, "");
}

export function extractPairs(text: string, cap = 400): Pair[] {
  const out: Pair[] = [];
  const push = (key: string, value: string) => { if (out.length < cap) out.push({ key, value }); };
  for (const line of text.split(/\r?\n/).slice(0, 2000)) {
    const t = line.trim();
    if (!t || t.startsWith("#") || t.startsWith("//") || t.startsWith(";") || t.startsWith("*") || t.startsWith("<?")) continue;
    const m = LINE_KV.exec(line);
    if (m && m[2] !== "") push(m[1], unquote(m[2]));
    else if (m) push(m[1], "");
  }
  for (const m of text.matchAll(JSON_KV)) push(m[1], m[2]);
  for (const m of text.matchAll(PHP_DEFINE)) push(m[1], m[2]);
  for (const m of text.matchAll(PHP_ARROW)) push(m[1], m[2]);
  for (const m of text.matchAll(PHP_VAR)) if (m[1]) push(m[1], m[2]);
  for (const m of text.matchAll(PHP_VAR_NAMED)) push(m[1], m[2]);
  return out;
}

export const SECRET_KEY_RE = /(PASS(?:WORD|WD)?|PWD|SECRET|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|AUTH[_-]?KEY|APP[_-]?KEY|ENCRYPTION[_-]?KEY|SIGNING[_-]?KEY|MASTER[_-]?KEY|SALT|DSN|CREDENTIALS?)/i;

// ======================= detektor spesifik =======================

interface Detector { type: SecretType; re: RegExp; group: number }
const DETECTORS: Detector[] = [
  { type: "aws-access-key", re: /\b((?:AKIA|ASIA)[A-Z2-7]{16})\b/g, group: 1 },
  { type: "aws-secret-key", re: /aws_?secret_?(?:access_?)?key["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])/gi, group: 1 },
  { type: "google-api-key", re: /\b(AIza[0-9A-Za-z_\-]{35})\b/g, group: 1 },
  { type: "github-token", re: /\b(gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})\b/g, group: 1 },
  { type: "slack-token", re: /\b(xox[baprs]-[A-Za-z0-9-]{10,})\b/g, group: 1 },
  { type: "stripe-key", re: /\b((?:sk|rk)_live_[0-9A-Za-z]{16,})\b/g, group: 1 },
  { type: "sendgrid-key", re: /\b(SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,})\b/g, group: 1 },
  { type: "npm-token", re: /_authToken\s*=\s*([^\s]+)/g, group: 1 },
  { type: "npm-token", re: /\b(npm_[A-Za-z0-9]{36})\b/g, group: 1 },
  { type: "app-key", re: /\bAPP_KEY[ \t]*=[ \t]*["']?(base64:[A-Za-z0-9+/=]{40,})/g, group: 1 },
];

function jwtLive(token: string): { live: boolean; reason?: string } {
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1], "base64url").toString("utf8")) as { exp?: number };
    if (typeof payload.exp === "number" && payload.exp * 1000 < Date.now()) return { live: false, reason: "kedaluwarsa" };
  } catch { /* abaikan */ }
  return { live: true };
}

export function analyzeText(text: string, category: SensitiveCategory, fileKind: string): SensitiveAnalysis {
  const secrets: SecretFinding[] = [];
  const seen = new Set<string>();
  const add = (type: SecretType, value: string, extra: Partial<SecretFinding> = {}) => {
    const hash12 = sha12(value);
    if (seen.has(hash12)) return;
    seen.add(hash12);
    let live: boolean; let reason: string | undefined;
    if (extra.live !== undefined) { live = extra.live; reason = extra.reason; }
    else { reason = placeholderReason(value) ?? undefined; live = !reason; }
    secrets.push({ type, label: SECRET_LABELS[type], preview: redact(value), hash12, live, reason, ...extra, ...(extra.live === undefined ? {} : { live: extra.live }) });
  };

  for (const d of DETECTORS) {
    for (const m of text.matchAll(d.re)) {
      const v = unquote(m[d.group]);
      if (d.type === "aws-access-key") {
        const acct = awsAccountFromKeyId(v);
        add("aws-access-key", v, { awsAccountId: acct, note: acct ? `Akun AWS ${acct} (diturunkan offline dari key ID)` : undefined });
      } else add(d.type, v);
    }
  }

  for (const m of text.matchAll(/\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g)) {
    const j = jwtLive(m[0]);
    add("jwt", m[0], { live: j.live, reason: j.reason });
  }

  for (const m of text.matchAll(/\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver):\/\/)([^\s:@/'"<>]+):([^\s@/'"<>]{3,})@([^\s/'"<>?]+)/gi))
    add("db-url-credentials", m[3], { note: `${m[2]}@${m[4]}` });

  for (const m of text.matchAll(/-----BEGIN ((?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?)-----([\s\S]{0,4000}?)(?:-----END|$)/g)) {
    const body = m[2].replace(/[^A-Za-z0-9+/=]/g, "");
    const enc = /ENCRYPTED/.test(m[1]) || /Proc-Type:\s*4,ENCRYPTED/.test(m[2]);
    add("private-key", m[1] + body.slice(0, 40), {
      live: body.length >= 60, reason: body.length >= 60 ? undefined : "kosong/terpotong",
      note: `${m[1]}${enc ? " · terproteksi passphrase (tetap bisa dibrute-force)" : ""}`,
    });
  }

  if (/"type"\s*:\s*"service_account"/.test(text) && /"private_key"\s*:/.test(text)) {
    const id = /"private_key_id"\s*:\s*"([^"]+)"/.exec(text)?.[1] ?? "service_account";
    const email = /"client_email"\s*:\s*"([^"]+)"/.exec(text)?.[1];
    add("gcp-service-account", id, { live: true, note: email ? `client_email: ${email}` : undefined });
  }

  const pairs = extractPairs(text);
  for (const p of pairs) {
    if (!SECRET_KEY_RE.test(p.key)) continue;
    if (p.value === "") { // nilai kosong = bukan kebocoran, tetapi dicatat sebagai placeholder
      add(/PASS|PWD/i.test(p.key) ? "password" : "generic-secret", `${p.key}=∅`, { keyName: p.key, live: false, reason: "kosong" });
      continue;
    }
    add(/PASS|PWD/i.test(p.key) ? "password" : "generic-secret", p.value, { keyName: p.key });
  }

  const showKeys = category === "env" || category === "config" || category === "credentials";
  const keyNames = showKeys ? [...new Set(pairs.map((p) => p.key))].slice(0, 80) : [];
  const live = secrets.filter((s) => s.live);
  const remediation = [...new Set([...live.flatMap((s) => REMEDIATION[s.type]), ...COMMON_REMEDIATION])];

  return {
    category, fileKind, secrets,
    liveCount: live.length,
    placeholderCount: secrets.length - live.length,
    keyNames, remediation,
    summaryPublic: summarizePublic(secrets),
  };
}

export function summarizePublic(secrets: SecretFinding[]): string {
  const counts = new Map<string, number>();
  for (const s of secrets.filter((x) => x.live)) counts.set(s.label, (counts.get(s.label) ?? 0) + 1);
  const live = [...counts.entries()].map(([l, n]) => `${n} ${l}`).join(", ");
  const ph = secrets.filter((s) => !s.live).length;
  return [live && `terdeteksi: ${live}`, ph && `${ph} nilai tampak placeholder/default`].filter(Boolean).join("; ");
}

// ======================= magic bytes =======================

export function detectArchive(h: Uint8Array): string | null {
  const b = (i: number) => h[i];
  if (b(0) === 0x50 && b(1) === 0x4b && (b(2) === 3 || b(2) === 5) && (b(3) === 4 || b(3) === 6)) return "zip";
  if (b(0) === 0x1f && b(1) === 0x8b) return "gzip";
  if (b(0) === 0x37 && b(1) === 0x7a && b(2) === 0xbc && b(3) === 0xaf) return "7z";
  if (b(0) === 0x52 && b(1) === 0x61 && b(2) === 0x72 && b(3) === 0x21) return "rar";
  if (b(0) === 0x42 && b(1) === 0x5a && b(2) === 0x68) return "bzip2";
  if (b(0) === 0xfd && b(1) === 0x37 && b(2) === 0x7a && b(3) === 0x58) return "xz";
  if (b(0) === 0x28 && b(1) === 0xb5 && b(2) === 0x2f && b(3) === 0xfd) return "zstd";
  if (h.length >= 262 && Buffer.from(h.slice(257, 262)).toString("latin1") === "ustar") return "tar";
  return null;
}
const isSqlite = (h: Uint8Array) => Buffer.from(h.slice(0, 15)).toString("latin1") === "SQLite format 3";
const isDsStore = (h: Uint8Array) => h[0] === 0 && h[1] === 0 && h[2] === 0 && h[3] === 1 && h[4] === 0x42 && h[5] === 0x75 && h[6] === 0x64 && h[7] === 0x31;
const hex8 = (h: Uint8Array) => Buffer.from(h.slice(0, 8)).toString("hex");

// ======================= composer =======================

const NOTABLE = new Set([
  "laravel/framework", "symfony/symfony", "symfony/http-kernel", "symfony/http-foundation", "phpunit/phpunit",
  "facade/ignition", "spatie/laravel-ignition", "guzzlehttp/guzzle", "monolog/monolog", "twig/twig",
  "yiisoft/yii2", "cakephp/cakephp", "codeigniter4/framework", "drupal/core", "livewire/livewire",
  "league/flysystem", "doctrine/orm", "doctrine/dbal", "phpmailer/phpmailer", "dompdf/dompdf", "laravel/passport", "laravel/sanctum",
]);

const PAIR_RE = /"name"\s*:\s*"([a-z0-9_.-]+\/[a-z0-9_.-]+)"\s*,\s*"version"\s*:\s*"([^"]+)"/g;

export function parseComposerPackages(text: string, source: string, evidence: string): { components: Component[]; summary: ComposerSummary } {
  const devIdx = text.indexOf('"packages-dev"');
  const comps = new Map<string, Component>();
  let prod = 0, dev = 0;
  let phpunitInProd = false;
  const notable: string[] = [];
  for (const m of text.matchAll(PAIR_RE)) {
    const version = m[2].replace(/^v/i, "");
    if (!/^\d+\.\d+/.test(version)) continue; // lewati dev-master / branch alias
    const isDev = devIdx >= 0 && m.index! > devIdx;
    isDev ? dev++ : prod++;
    if (m[1] === "phpunit/phpunit" && !isDev) phpunitInProd = true;
    if (NOTABLE.has(m[1])) notable.push(`${m[1]}@${version}`);
    comps.set(`${m[1]}@${version}`, { name: m[1], version, kind: "packagist", source, evidence });
  }
  return {
    components: [...comps.values()].slice(0, 400),
    summary: { total: comps.size, prod, dev, notable: notable.slice(0, 20), phpunitInProd },
  };
}

// ======================= katalog =======================

type V = (r: SensitiveResponse, ctx: ValidateCtx) => { marker: string; fileKind: string } | null;

export interface SensitiveSpec {
  path: string;
  title: string;
  category: SensitiveCategory;
  tier: 1 | 2;
  severity: "CRITICAL" | "HIGH";
  validate: V;
  binary?: boolean;
  bytes?: number;
  needsBaseline?: boolean;
  downgradeWhenNoLive?: boolean;
  analyze?: boolean;
  parse?: "composer";
  fix: string;
  cwe: string[];
  cve?: string[];
  rce?: boolean;
  confidence?: "verified" | "existence-only";
}

const okText = (r: SensitiveResponse, allowHtmlCt = false) =>
  r.status === 200 && r.text.length > 0 && !looksLikeHtml(r.text) && (allowHtmlCt || !r.contentType.includes("html"));

const when = (re: RegExp, marker: string, fileKind: string, allowHtmlCt = false): V => (r) =>
  okText(r, allowHtmlCt) && re.test(r.text) ? { marker, fileKind } : null;

const kvCount = (t: string) => (t.match(/^[ \t]*(?:export[ \t]+)?[A-Za-z_][A-Za-z0-9_.]*[ \t]*=[ \t]*\S/gm) ?? []).length;

const envLike: V = (r) => {
  if (!okText(r)) return null;
  const n = kvCount(r.text);
  if (n < 2) return null;
  const hasTyped = /^[ \t]*(?:export[ \t]+)?(?:APP|DB|MAIL|AWS|REDIS|SECRET|AUTH|JWT|DATABASE|API|STRIPE|SMTP|S3|CACHE|QUEUE|SESSION|NODE|NEXT|NUXT|VITE|FIREBASE|SENTRY)[A-Z0-9_]*[ \t]*=/im.test(r.text);
  return hasTyped || SECRET_KEY_RE.test(r.text) ? { marker: `KEY=VALUE (${n} variabel)`, fileKind: "env" } : null;
};

const phpSource: V = (r) => {
  if (!okText(r, true) || !/<\?php/.test(r.text.slice(0, 4096))) return null;
  return extractPairs(r.text).some((p) => SECRET_KEY_RE.test(p.key))
    ? { marker: "source PHP terbaca sebagai teks (PHP tidak dieksekusi) berisi konfigurasi kredensial", fileKind: "php-source" }
    : null;
};

const kvSecrets = (extra: RegExp, marker: string, fileKind: string): V => (r) =>
  okText(r, false) && extra.test(r.text) && extractPairs(r.text).some((p) => SECRET_KEY_RE.test(p.key)) ? { marker, fileKind } : null;

const archive: V = (r) => {
  if (r.status !== 200 && r.status !== 206) return null;
  if (r.contentType.includes("html")) return null;
  const k = detectArchive(r.head);
  return k ? { marker: `magic bytes arsip (${k})`, fileKind: `arsip ${k}` } : null;
};

const SQL_RE = /^(?:--\s*(?:MySQL dump|MariaDB dump|PostgreSQL database dump|phpMyAdmin SQL Dump|Host:)|\/\*!\d{5}\s|CREATE TABLE|INSERT INTO|DROP TABLE IF EXISTS|COPY\s+\S+\s+\()/im;
const sqlDump: V = (r) => (okText(r) && SQL_RE.test(r.text.slice(0, 4096)) ? { marker: "SQL dump (CREATE TABLE/INSERT INTO)", fileKind: "sql dump" } : null);

const privateKey: V = (r) => {
  if (!okText(r)) return null;
  const m = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----([\s\S]{0,4000})/.exec(r.text);
  return m && m[1].replace(/[^A-Za-z0-9+/=]/g, "").length >= 60 ? { marker: "PRIVATE KEY block", fileKind: "private key" } : null;
};

const sqliteMagic: V = (r) => ((r.status === 200 || r.status === 206) && !r.contentType.includes("html") && isSqlite(r.head) ? { marker: "SQLite database (magic bytes)", fileKind: "sqlite db" } : null);

const composerLock: V = (r) => {
  if (!okText(r)) return null;
  const n = [...r.text.matchAll(PAIR_RE)].length;
  return n > 0 && /"content-hash"|"_readme"|"packages"/.test(r.text) ? { marker: `composer.lock (${n} paket terbaca)`, fileKind: "composer.lock" } : null;
};
const installedJson: V = (r) => {
  if (!okText(r)) return null;
  const n = [...r.text.matchAll(PAIR_RE)].length;
  return n > 0 && (/"packages"\s*:/.test(r.text) || /^\s*\[/.test(r.text)) ? { marker: `installed.json (${n} paket terbaca)`, fileKind: "vendor/composer/installed.json" } : null;
};

const dirListing = (dir: string): V => (r) =>
  r.status === 200 && new RegExp(`(<title>|<h1>)\\s*Index of ${dir.replace(/[/.]/g, "\\$&")}`, "i").test(r.text) ? { marker: `direktori ${dir} dapat dilihat (autoindex)`, fileKind: "directory-listing" } : null;

const evalStdinExists: V = (r, ctx) => {
  const b = ctx.baseline;
  if (!b || b.status === 200) return null; // catch-all → tidak bisa dibedakan
  if (r.status !== 200 || r.contentType.includes("html") || looksLikeHtml(r.text)) return null;
  return r.text.trim().length < 64 ? { marker: `respons 200 (isi ${r.text.trim().length === 0 ? "kosong" : "pendek"}) sementara path acak sejenis menghasilkan ${b.status}`, fileKind: "php endpoint (indikasi)" } : null;
};

const FIX_VENDOR = "Hapus dev-dependencies di production (`composer install --no-dev`), letakkan /vendor di luar webroot, dan blokir akses publik ke /vendor/, composer.json dan composer.lock.";
const FIX_PHPSRC = "Pastikan server meng-eksekusi PHP untuk file ini (bukan menyajikannya sebagai teks), hapus salinan backup/.txt/.phps dari webroot, lalu rotasi kredensial di dalamnya.";
const FIX_LOG = "Hapus log dari webroot, blokir akses ke *.log, dan matikan display_errors di production.";

const T = (
  path: string, title: string, category: SensitiveCategory, tier: 1 | 2, severity: "CRITICAL" | "HIGH",
  validate: V, fix: string, cwe: string[], extra: Partial<SensitiveSpec> = {}
): SensitiveSpec => ({ path, title, category, tier, severity, validate, fix, cwe, ...extra });

const ENV_FIX = "Hapus file dari webroot, blokir dotfile di web server, dan rotasi semua kredensial di dalamnya.";

function staticCatalog(): SensitiveSpec[] {
  const out: SensitiveSpec[] = [];
  // --- env varian ---
  for (const [p, tier] of [["/.env.development", 1], ["/.env.dev", 2], ["/.env.prod", 2], ["/.env.save", 2], ["/.env.old", 2], ["/.env.backup", 2], ["/.env~", 2], ["/api/.env", 2], ["/app/.env", 2], ["/public/.env", 2], ["/backend/.env", 2]] as const)
    out.push(T(p, `${p.slice(p.lastIndexOf("/") + 1)} exposed`, "env", tier, "CRITICAL", envLike, ENV_FIX, ["CWE-538", "CWE-200"], { downgradeWhenNoLive: true }));

  // --- config PHP / CMS (source terbaca) ---
  for (const [p, tier] of [
    ["/config.php", 1], ["/config.php.bak", 1], ["/config.php.old", 2], ["/config.php~", 2], ["/config.php.save", 2], ["/config.php.orig", 2], ["/config.php.txt", 2], ["/config.phps", 2],
    ["/config.inc.php", 2], ["/config.inc.php.bak", 2], ["/config/config.php", 2], ["/includes/config.php", 2], ["/inc/config.php", 2],
    ["/wp-config.php", 1], ["/wp-config.php.old", 1], ["/wp-config.php.orig", 2], ["/wp-config.php.txt", 2], ["/wp-config.bak", 2],
    ["/configuration.php.bak", 2], ["/LocalSettings.php.bak", 2], ["/includes/configure.php.bak", 2], ["/app/etc/env.php.bak", 2], ["/application/config/database.php.bak", 2],
  ] as const)
    out.push(T(p, `Source konfigurasi PHP terbaca (${p.slice(p.lastIndexOf("/") + 1)})`, "config", tier, "CRITICAL", phpSource, FIX_PHPSRC, ["CWE-540", "CWE-538", "CWE-798"], { downgradeWhenNoLive: true }));
  out.push(T("/app/config/parameters.yml", "Symfony parameters.yml terbuka", "config", 2, "CRITICAL",
    kvSecrets(/^\s*parameters\s*:/m, "parameters.yml berisi kunci rahasia", "symfony parameters"), ENV_FIX, ["CWE-538", "CWE-798"], { downgradeWhenNoLive: true }));

  // --- composer / vendor ---
  out.push(T("/composer.lock", "composer.lock terbuka (daftar paket + versi PHP)", "php-deps", 1, "HIGH", composerLock, FIX_VENDOR, ["CWE-538", "CWE-1395"], { bytes: 2 * 1024 * 1024, parse: "composer", analyze: false }));
  out.push(T("/vendor/composer/installed.json", "vendor/composer/installed.json terbuka (daftar paket terpasang)", "php-deps", 1, "HIGH", installedJson, FIX_VENDOR, ["CWE-538", "CWE-1395"], { bytes: 2 * 1024 * 1024, parse: "composer", analyze: false }));
  out.push(T("/vendor/composer/LICENSE", "Direktori /vendor/ dapat diakses publik", "php-deps", 1, "HIGH",
    when(/Nils Adermann/i, "file LICENSE Composer di /vendor terbaca", "vendor", false), FIX_VENDOR, ["CWE-538", "CWE-1395"], { analyze: false }));
  out.push(T("/vendor/phpunit/phpunit/LICENSE", "PHPUnit (dev-dependency) terpasang di webroot — potensi RCE CVE-2017-9841 pada versi lama", "php-deps", 1, "HIGH",
    when(/Sebastian Bergmann/i, "file LICENSE PHPUnit di /vendor terbaca", "vendor/phpunit", false), FIX_VENDOR, ["CWE-94", "CWE-538"], { cve: ["CVE-2017-9841"], rce: true, analyze: false }));
  out.push(T("/vendor/", "Directory listing /vendor/ aktif", "php-deps", 1, "HIGH", dirListing("/vendor"), FIX_VENDOR, ["CWE-548", "CWE-538"], { analyze: false }));
  for (const [p, tier] of [["/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", 1], ["/vendor/phpunit/phpunit/Util/PHP/eval-stdin.php", 2], ["/phpunit/phpunit/src/Util/PHP/eval-stdin.php", 2]] as const)
    out.push(T(p, "PHPUnit eval-stdin.php kemungkinan aktif (indikasi, belum dieksploitasi)", "php-deps", tier, "HIGH", evalStdinExists, FIX_VENDOR, ["CWE-94", "CWE-95"],
      { cve: ["CVE-2017-9841"], rce: true, needsBaseline: true, analyze: false, confidence: "existence-only" }));

  // --- diagnostik PHP ---
  for (const p of ["/info.php", "/php.php", "/test.php", "/i.php", "/pi.php"])
    out.push(T(p, "phpinfo() terbuka", "php-diag", 2, "HIGH", (r) => (r.status === 200 && /<title>[^<]*phpinfo\(\)[^<]*<\/title>/i.test(r.text) && /PHP Version/i.test(r.text) ? { marker: "phpinfo() — PHP Version & Configuration", fileKind: "phpinfo" } : null),
      "Hapus file phpinfo dari production.", ["CWE-200", "CWE-215"], { analyze: false }));
  out.push(T("/php.ini", "php.ini terbaca publik", "php-diag", 2, "HIGH", when(/^\s*\[PHP\]/m, "php.ini terbaca", "php.ini"), "Letakkan php.ini di luar webroot dan blokir aksesnya.", ["CWE-538", "CWE-200"], { analyze: false }));
  for (const p of ["/adminer.php", "/adminer/", "/adminer/adminer.php"])
    out.push(T(p, "Panel Adminer (admin database) terbuka", "php-diag", 2, "HIGH", (r) => (r.status === 200 && /<title>[^<]*Adminer[^<]*<\/title>/i.test(r.text) ? { marker: "halaman login Adminer", fileKind: "adminer" } : null),
      "Hapus Adminer dari production atau batasi ke IP internal + autentikasi tambahan.", ["CWE-306", "CWE-284"], { analyze: false }));
  for (const p of ["/phpmyadmin/", "/phpMyAdmin/", "/pma/"])
    out.push(T(p, "Panel phpMyAdmin terbuka", "php-diag", 2, "HIGH", (r) => (r.status === 200 && /<title>phpMyAdmin<\/title>/i.test(r.text) ? { marker: "halaman login phpMyAdmin", fileKind: "phpmyadmin" } : null),
      "Batasi phpMyAdmin ke IP internal/VPN dan ganti path default.", ["CWE-306", "CWE-284"], { analyze: false }));

  // --- log ---
  const phpErr = /\[\d{2}-[A-Za-z]{3}-\d{4} \d{2}:\d{2}:\d{2} [A-Za-z/_]+\] PHP (?:Warning|Notice|Fatal error|Parse error|Deprecated)/;
  for (const p of ["/error_log", "/php_errorlog"]) out.push(T(p, "PHP error log terbuka", "log", 1, "HIGH", when(phpErr, "baris PHP error log dengan path server", "php error log"), FIX_LOG, ["CWE-532", "CWE-209"], { analyze: false }));
  out.push(T("/storage/logs/laravel.log", "Laravel log terbuka", "log", 1, "HIGH",
    (r) => (okText(r) && /\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \w+\.(?:ERROR|WARNING|INFO|DEBUG|CRITICAL)/.test(r.text) && (/Stack trace:|#\d+ \//.test(r.text) || /Illuminate\\/.test(r.text)) ? { marker: "log Laravel dengan stack trace", fileKind: "laravel log" } : null),
    FIX_LOG, ["CWE-532", "CWE-209"], { analyze: false }));

  // --- SQL dump ---
  for (const [p, tier] of [["/db.sql", 1], ["/database.sql", 1], ["/data.sql", 2], ["/db_backup.sql", 2], ["/mysql.sql", 2], ["/backup/backup.sql", 2]] as const)
    out.push(T(p, "SQL dump terbuka", "sql-dump", tier, "CRITICAL", sqlDump, BACKUP_REMEDIATION[0], ["CWE-530", "CWE-200"], { bytes: 4096, analyze: false }));
  for (const p of ["/backup.sql.gz", "/dump.sql.gz", "/db.sql.gz"])
    out.push(T(p, "Dump SQL terkompresi terbuka", "sql-dump", 2, "CRITICAL", archive, BACKUP_REMEDIATION[0], ["CWE-530"], { binary: true, bytes: 4096, analyze: false }));
  for (const p of ["/database/database.sqlite", "/database.sqlite", "/db.sqlite", "/data.db"])
    out.push(T(p, "File database SQLite terbuka", "db-file", 2, "CRITICAL", sqliteMagic, "Pindahkan file database ke luar webroot dan blokir ekstensi .sqlite/.db.", ["CWE-530", "CWE-538"], { binary: true, bytes: 4096, analyze: false }));

  // --- arsip statis ---
  for (const [p, tier] of [["/backup.tar.gz", 1], ["/backup.tgz", 1], ["/www.zip", 1], ["/public_html.zip", 1], ["/html.zip", 2], ["/web.zip", 2], ["/wwwroot.zip", 2], ["/backup.tar", 2], ["/backup.7z", 2], ["/backup.rar", 2], ["/backups.zip", 2], ["/db.zip", 2], ["/database.zip", 2], ["/dump.zip", 2]] as const)
    out.push(T(p, "Arsip backup terbuka", "archive", tier, "CRITICAL", archive, BACKUP_REMEDIATION[0], ["CWE-530", "CWE-200"], { binary: true, bytes: 4096, analyze: false }));

  // --- private key ---
  for (const [p, tier] of [["/id_rsa", 1], ["/id_dsa", 2], ["/id_ecdsa", 2], ["/id_ed25519", 2], ["/.ssh/id_dsa", 2], ["/.ssh/id_ed25519", 2], ["/server.key", 1], ["/private.key", 2], ["/privkey.pem", 2], ["/key.pem", 2], ["/ssl/private.key", 2]] as const)
    out.push(T(p, "Private key terbuka", "private-key", tier, "CRITICAL", privateKey, REMEDIATION["private-key"][0], ["CWE-321", "CWE-538"]));

  // --- kredensial & state ---
  out.push(T("/.npmrc", ".npmrc dengan auth token terbuka", "credentials", 1, "CRITICAL", when(/_authToken\s*=\s*\S+/, "_authToken terdeteksi", "npmrc"), ENV_FIX, ["CWE-798"], { downgradeWhenNoLive: true }));
  out.push(T("/.git-credentials", ".git-credentials terbuka", "credentials", 1, "CRITICAL", when(/^https?:\/\/[^:\s/]+:[^@\s]+@\S+/m, "URL berisi user:password", "git-credentials"), ENV_FIX, ["CWE-798"], { downgradeWhenNoLive: true }));
  out.push(T("/.netrc", ".netrc terbuka", "credentials", 2, "CRITICAL", when(/machine\s+\S+[\s\S]{0,120}?password\s+\S+/i, "machine/password terdeteksi", "netrc"), ENV_FIX, ["CWE-798"], { downgradeWhenNoLive: true }));
  out.push(T("/.pgpass", ".pgpass terbuka", "credentials", 2, "CRITICAL", when(/^[^:\n#]+:\d+:[^:\n]+:[^:\n]+:[^\n]+$/m, "entri host:port:db:user:password", "pgpass"), ENV_FIX, ["CWE-798"], { downgradeWhenNoLive: true }));
  for (const p of ["/.docker/config.json", "/.dockercfg"])
    out.push(T(p, "Docker registry credentials terbuka", "credentials", 2, "CRITICAL", when(/"auths"\s*:\s*\{[\s\S]*"auth"\s*:\s*"[A-Za-z0-9+/=]{8,}"/, "auths/auth terdeteksi", "docker config"), ENV_FIX, ["CWE-798"]));
  out.push(T("/.htpasswd", ".htpasswd terbuka (hash password)", "credentials", 1, "HIGH", when(/^[^:\s]+:(?:\$apr1\$|\$2[aby]\$|\$5\$|\$6\$|\{SHA\})/m, "entri htpasswd", "htpasswd"), "Hapus .htpasswd dari webroot dan ganti password yang tercantum.", ["CWE-538", "CWE-522"], { analyze: false }));
  out.push(T("/.s3cfg", ".s3cfg terbuka", "credentials", 2, "CRITICAL", when(/^\s*(?:access_key|secret_key)\s*=\s*\S+/m, "access_key/secret_key terdeteksi", "s3cfg"), ENV_FIX, ["CWE-798"], { downgradeWhenNoLive: true }));
  for (const p of ["/terraform.tfstate", "/terraform.tfstate.backup", "/.terraform/terraform.tfstate"])
    out.push(T(p, "Terraform state terbuka (berisi secret plaintext)", "cloud-state", p === "/terraform.tfstate" ? 1 : 2, "CRITICAL",
      when(/"terraform_version"\s*:/, "terraform state (terraform_version/resources)", "terraform state"), "Simpan state di backend remote terenkripsi, hapus dari webroot, dan rotasi semua secret di dalamnya.", ["CWE-538", "CWE-312"], { bytes: 256 * 1024 }));
  for (const p of ["/credentials.json", "/service-account.json", "/serviceAccountKey.json"])
    out.push(T(p, "Service account key terbuka", "credentials", 2, "CRITICAL", (r) => (okText(r) && /"type"\s*:\s*"service_account"/.test(r.text) && /"private_key"\s*:/.test(r.text) ? { marker: "service_account + private_key", fileKind: "gcp service account" } : null), ENV_FIX, ["CWE-798", "CWE-538"]));
  for (const p of ["/secrets.json", "/secrets.yml", "/config/secrets.yml"])
    out.push(T(p, `${p.slice(p.lastIndexOf("/") + 1)} terbuka`, "credentials", 2, "CRITICAL", kvSecrets(/./, "berisi kunci rahasia", "secrets file"), ENV_FIX, ["CWE-538", "CWE-798"], { downgradeWhenNoLive: true }));
  for (const p of ["/.vscode/sftp.json", "/.ftpconfig"])
    out.push(T(p, `${p.slice(p.lastIndexOf("/") + 1)} terbuka (kredensial SFTP/FTP)`, "credentials", p === "/.vscode/sftp.json" ? 1 : 2, "CRITICAL",
      (r) => (okText(r) && /"host"\s*:/.test(r.text) && /"(?:password|privateKeyPath|passphrase)"\s*:\s*"[^"]+"/.test(r.text) ? { marker: "host + password/privateKeyPath", fileKind: "sftp config" } : null), ENV_FIX, ["CWE-798", "CWE-538"], { downgradeWhenNoLive: true }));
  for (const p of ["/docker-compose.override.yml"])
    out.push(T(p, "docker-compose override terbuka", "config", 2, "CRITICAL", kvSecrets(/^\s*services\s*:/m, "services + environment berisi kunci rahasia", "docker compose"), ENV_FIX, ["CWE-538", "CWE-798"], { downgradeWhenNoLive: true }));
  for (const p of ["/appsettings.json", "/appsettings.Production.json", "/appsettings.Development.json"])
    out.push(T(p, `${p.slice(1)} terbuka`, "config", p === "/appsettings.json" ? 1 : 2, "CRITICAL",
      (r) => (okText(r) && /"ConnectionStrings"\s*:/.test(r.text) && /(?:Password|Pwd)\s*=\s*[^;"]+/i.test(r.text) ? { marker: "ConnectionStrings + Password", fileKind: "appsettings" } : null), ENV_FIX, ["CWE-538", "CWE-798"], { downgradeWhenNoLive: true }));
  for (const p of ["/application.properties", "/application.yml", "/application-prod.properties"])
    out.push(T(p, `${p.slice(1)} terbuka`, "config", 2, "CRITICAL", kvSecrets(/(?:spring\.|datasource|server\.port)/, "konfigurasi Spring dengan kunci rahasia", "spring config"), ENV_FIX, ["CWE-538", "CWE-798"], { downgradeWhenNoLive: true }));
  out.push(T("/config/database.yml", "database.yml terbuka", "config", 2, "CRITICAL",
    (r) => (okText(r) && (r.text.match(/^\s*(?:adapter|database|username|password)\s*:/gm) ?? []).length >= 2 ? { marker: "adapter/database/username/password", fileKind: "rails database.yml" } : null), ENV_FIX, ["CWE-538", "CWE-798"], { downgradeWhenNoLive: true }));
  out.push(T("/web.config", "web.config terbaca (connectionStrings)", "config", 2, "CRITICAL", when(/<connectionStrings>[\s\S]*(?:password|pwd)\s*=/i, "connectionStrings + password", "web.config", true), ENV_FIX, ["CWE-538", "CWE-798"], { downgradeWhenNoLive: true }));

  // --- VCS/IDE ---
  out.push(T("/.DS_Store", ".DS_Store terbuka (bocor daftar file)", "misc", 1, "HIGH", (r) => ((r.status === 200 || r.status === 206) && isDsStore(r.head) ? { marker: "magic bytes .DS_Store (Bud1)", fileKind: ".DS_Store" } : null), "Hapus .DS_Store dari webroot dan blokir dotfile.", ["CWE-538"], { binary: true, bytes: 4096, analyze: false }));
  out.push(T("/.svn/wc.db", "Subversion wc.db terbuka", "vcs", 2, "HIGH", sqliteMagic, "Blokir /.svn/ dan hapus dari webroot.", ["CWE-527"], { binary: true, bytes: 4096, analyze: false }));
  out.push(T("/.hg/hgrc", "Mercurial hgrc terbuka", "vcs", 2, "HIGH", when(/^\[paths\]/m, "[paths] terdeteksi", "hgrc"), "Blokir /.hg/ dan hapus dari webroot.", ["CWE-527"], { analyze: false }));
  out.push(T("/.idea/workspace.xml", "JetBrains workspace.xml terbuka", "ide", 2, "HIGH", when(/<project version="4">[\s\S]*<component name=/, "workspace.xml JetBrains", "idea workspace", true), "Blokir /.idea/ dan hapus dari webroot.", ["CWE-538"], { analyze: false }));
  return out;
}

// ---- varian nama berbasis domain ----
const SLD_REGISTRIES = new Set(["co", "com", "net", "org", "ac", "go", "or", "sch", "web", "my", "biz", "edu", "gov", "mil", "id"]);

export function domainLabels(domain: string): { apex: string; sld: string } {
  const apex = domain.replace(/^www\./, "");
  const parts = apex.split(".");
  let sld = parts[Math.max(0, parts.length - 2)];
  if (parts.length >= 3 && parts[parts.length - 1].length === 2 && SLD_REGISTRIES.has(parts[parts.length - 2])) sld = parts[parts.length - 3];
  return { apex, sld };
}

function domainCatalog(domain: string): SensitiveSpec[] {
  const { apex, sld } = domainLabels(domain);
  const out: SensitiveSpec[] = [];
  const zip = (name: string, tier: 1 | 2) => out.push(T(`/${name}`, "Arsip backup terbuka (nama dari domain)", "archive", tier, "CRITICAL", archive, BACKUP_REMEDIATION[0], ["CWE-530", "CWE-200"], { binary: true, bytes: 4096, analyze: false }));
  zip(`${apex}.zip`, 1);
  if (sld !== apex) zip(`${sld}.zip`, 1);
  zip(`${sld}.tar.gz`, 2); zip(`${sld}_backup.zip`, 2); zip(`${sld}-backup.zip`, 2);
  for (const [n, tier] of [[`${sld}.sql`, 1], [`${apex}.sql`, 2]] as const)
    out.push(T(`/${n}`, "SQL dump terbuka (nama dari domain)", "sql-dump", tier, "CRITICAL", sqlDump, BACKUP_REMEDIATION[0], ["CWE-530", "CWE-200"], { bytes: 4096, analyze: false }));
  out.push(T(`/${sld}.sql.gz`, "Dump SQL terkompresi terbuka (nama dari domain)", "sql-dump", 2, "CRITICAL", archive, BACKUP_REMEDIATION[0], ["CWE-530"], { binary: true, bytes: 4096, analyze: false }));
  return out;
}

export function buildCatalog(domain: string, opts: { deep: boolean; skipPaths?: Set<string> }): SensitiveSpec[] {
  const seen = new Set<string>(opts.skipPaths ?? []);
  const all = [...staticCatalog(), ...domainCatalog(domain)].filter((s) => (opts.deep || s.tier === 1));
  return all.filter((s) => (seen.has(s.path) ? false : (seen.add(s.path), true)));
}

// ---- spesifikasi dinamis dari directory listing ----
const LISTING_EXT = /\.(?:zip|tar\.gz|tgz|tar|7z|rar|sql|sql\.gz|bak|old|sqlite|env|pem|key)$/i;

export function extractListingFiles(html: string, max = 8): string[] {
  const out: string[] = [];
  for (const m of html.matchAll(/href="([^"?#/][^"?#]*)"/gi)) {
    const f = decodeURIComponent(m[1]);
    if (f.includes("/") || f.startsWith("..") || !LISTING_EXT.test(f)) continue;
    if (!out.includes(f)) out.push(f);
    if (out.length >= max) break;
  }
  return out;
}

export function specForListedFile(dir: string, name: string): SensitiveSpec {
  const path = `${dir.endsWith("/") ? dir : dir + "/"}${name}`;
  const lower = name.toLowerCase();
  if (/\.(?:zip|tar\.gz|tgz|tar|7z|rar|sql\.gz)$/.test(lower))
    return T(path, "Arsip/backup terbuka via directory listing", "archive", 2, "CRITICAL", archive, BACKUP_REMEDIATION[0], ["CWE-548", "CWE-530"], { binary: true, bytes: 4096, analyze: false });
  if (/\.sql$/.test(lower))
    return T(path, "SQL dump terbuka via directory listing", "sql-dump", 2, "CRITICAL", sqlDump, BACKUP_REMEDIATION[0], ["CWE-548", "CWE-530"], { bytes: 4096, analyze: false });
  if (/\.sqlite$/.test(lower))
    return T(path, "File database terbuka via directory listing", "db-file", 2, "CRITICAL", sqliteMagic, BACKUP_REMEDIATION[0], ["CWE-548", "CWE-530"], { binary: true, bytes: 4096, analyze: false });
  if (/\.(?:pem|key)$/.test(lower))
    return T(path, "Private key terbuka via directory listing", "private-key", 2, "CRITICAL", privateKey, ENV_FIX, ["CWE-548", "CWE-321"]);
  return T(path, "File konfigurasi/backup terbuka via directory listing", "env", 2, "CRITICAL", envLike, ENV_FIX, ["CWE-548", "CWE-538"], { downgradeWhenNoLive: true });
}

// ======================= evaluasi =======================

export interface SensitiveHit {
  spec: SensitiveSpec;
  marker: string;
  fileKind: string;
  severity: "CRITICAL" | "HIGH";
  analysis: SensitiveAnalysis;
  snippet: string;
  components?: Component[];
}

export function evaluateSensitive(spec: SensitiveSpec, r: SensitiveResponse, ctx: ValidateCtx = {}, sourceUrl = ""): SensitiveHit | null {
  const statusOk = spec.binary ? r.status === 200 || r.status === 206 : r.status === 200;
  if (!statusOk) return null;
  const v = spec.validate(r, ctx);
  if (!v) return null;

  let analysis: SensitiveAnalysis;
  let components: Component[] | undefined;
  if (spec.analyze !== false && !spec.binary) analysis = analyzeText(r.text, spec.category, v.fileKind);
  else analysis = { category: spec.category, fileKind: v.fileKind, secrets: [], liveCount: 0, placeholderCount: 0, keyNames: [], remediation: [...COMMON_REMEDIATION], summaryPublic: "" };

  analysis.sizeBytes = r.size;
  analysis.lastModified = r.lastModified;
  analysis.etag = r.etag;

  if (spec.category === "sql-dump" && !spec.binary) {
    analysis.sqlTables = [...r.text.matchAll(/CREATE TABLE (?:IF NOT EXISTS )?[`"[]?([A-Za-z0-9_.]+)/gi)].map((m) => m[1]).slice(0, 40);
    analysis.serverVersion = /^--\s*Server version\s+(\S+)/im.exec(r.text)?.[1];
  }
  if (spec.category === "sql-dump" || spec.category === "archive" || spec.category === "db-file") analysis.remediation = [...BACKUP_REMEDIATION];

  if (spec.parse === "composer") {
    const p = parseComposerPackages(r.text, sourceUrl || spec.path, spec.path);
    components = p.components;
    analysis.composer = p.summary;
    analysis.summaryPublic = `${p.summary.total} paket terbaca${p.summary.phpunitInProd ? "; phpunit/phpunit ada di dependency production" : ""}`;
    if (p.summary.total === 0) return null;
  }

  const severity = spec.downgradeWhenNoLive && analysis.liveCount === 0 ? "HIGH" : spec.severity;
  const snippet = spec.binary ? `magic=${hex8(r.head)} kind=${v.fileKind} size=${r.size ?? "?"}` : r.text.slice(0, 2048);
  return { spec, marker: v.marker, fileKind: v.fileKind, severity, analysis, snippet, components };
}

/** Versi aman publik: tanpa nilai, pratinjau, hash, nama key, atau versi paket. */
export function publicSummaryLine(hit: SensitiveHit, status: number): string {
  const parts = [`HTTP ${status}`, hit.marker];
  if (hit.analysis.summaryPublic) parts.push(hit.analysis.summaryPublic);
  if (hit.analysis.sizeBytes) parts.push(`ukuran ≈ ${humanSize(hit.analysis.sizeBytes)}`);
  if (hit.spec.confidence === "existence-only") parts.push("indikasi berbasis keberadaan file, belum diverifikasi eksekusinya");
  return `${parts.join("; ")} (nilai tidak ditampilkan)`;
}

// ---- analisis untuk hit CRITICAL_CHECKS yang sudah ada ----
export function analyzeExistingHit(path: string, text: string, headers?: Headers): SensitiveAnalysis | undefined {
  if (/\.git|logs\/HEAD|\.zip$/i.test(path)) return undefined;
  let category: SensitiveCategory = "config";
  if (/\.env/i.test(path)) category = "env";
  else if (/\.aws\/credentials|id_rsa|sftp|docker-compose/i.test(path)) category = /id_rsa/.test(path) ? "private-key" : "credentials";
  else if (/\.sql$/i.test(path)) category = "sql-dump";
  const a = analyzeText(text, category, path.replace(/^\//, ""));
  if (category === "sql-dump") {
    a.sqlTables = [...text.matchAll(/CREATE TABLE (?:IF NOT EXISTS )?[`"[]?([A-Za-z0-9_.]+)/gi)].map((m) => m[1]).slice(0, 40);
    a.remediation = [...BACKUP_REMEDIATION];
  }
  if (headers) {
    a.lastModified = headers.get("last-modified") ?? undefined;
    a.etag = headers.get("etag") ?? undefined;
    const cl = Number(headers.get("content-length"));
    if (cl > 0) a.sizeBytes = cl;
  }
  return a;
}

/** Perketat severity untuk file env/config: tanpa kredensial nyata → HIGH. */
export function severityFromAnalysis(a: SensitiveAnalysis | undefined): "CRITICAL" | "HIGH" {
  if (!a) return "CRITICAL";
  if (a.category === "private-key" || a.category === "sql-dump") return "CRITICAL";
  return a.liveCount > 0 ? "CRITICAL" : "HIGH";
}
