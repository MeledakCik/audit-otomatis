import { assertPublicHttpsTarget } from "@/lib/ssrf-guard";
import { validateDomainInput } from "@/lib/validate-domain";

export type Sev = "CRITICAL" | "HIGH";

/** Bentuk yang BOLEH tampil ke publik. Tidak pernah berisi value rahasia. */
export interface PublicFinding {
  domain: string;
  severity: Sev;
  finding: string;
  evidence_public: string;
  fix: string;
}

/** Bukti mentah → hanya masuk Vault terenkripsi. */
export interface RawEvidence {
  domain: string;
  path: string;
  status: number;
  contentType: string;
  marker: string;
  snippet: string; // ≤1 KB awal body
}

export interface AuditResult {
  domain: string;
  scannedAt: number;
  findings: PublicFinding[];
  raw: RawEvidence[];
}

const UA = "Sentinel-ID Passive Auditor/3.0 (+https://sentinel-id.net)";
const TIMEOUT_MS = 8000;
const MAX_TEXT_BYTES = 64 * 1024;
const CONCURRENCY = 6;

interface Got {
  status: number;
  headers: Headers;
  contentType: string;
  text: string;
  head: Uint8Array; // 8 byte pertama (magic bytes)
}

/** GET-only, redirect TIDAK diikuti (kecuali dipanggil lewat getFollow), body dibatasi. */
async function get(url: string, wantBytes = MAX_TEXT_BYTES): Promise<Got | null> {
  const ctl = new AbortController();
  const t = setTimeout(() => ctl.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: ctl.signal,
      headers: { "User-Agent": UA, Accept: "*/*", "Cache-Control": "no-cache" },
    });
    const reader = res.body?.getReader();
    const chunks: Uint8Array[] = [];
    let total = 0;
    if (reader && res.status === 200) {
      while (total < wantBytes) {
        const { done, value } = await reader.read();
        if (done) break;
        chunks.push(value);
        total += value.byteLength;
      }
      reader.cancel().catch(() => {});
    } else {
      reader?.cancel().catch(() => {});
    }
    const buf = Buffer.concat(chunks.map((c) => Buffer.from(c))).subarray(0, wantBytes);
    return {
      status: res.status,
      headers: res.headers,
      contentType: (res.headers.get("content-type") ?? "").toLowerCase(),
      text: buf.toString("utf8"),
      head: new Uint8Array(buf.subarray(0, 8)),
    };
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

/** Ikuti redirect hanya antar host yang sama (apex ↔ www), tiap hop divalidasi SSRF guard. */
async function getHome(origin: URL): Promise<Got | null> {
  let url = new URL(origin.toString());
  for (let i = 0; i < 3; i++) {
    const r = await get(url.toString());
    if (!r) return null;
    if (![301, 302, 303, 307, 308].includes(r.status)) return r;
    const loc = r.headers.get("location");
    if (!loc) return r;
    let next: URL;
    try {
      next = new URL(loc, url);
    } catch {
      return r;
    }
    const strip = (h: string) => h.replace(/^www\./, "");
    if (strip(next.hostname) !== strip(origin.hostname)) return r;
    try {
      next = (await assertPublicHttpsTarget(next.toString())).url;
    } catch {
      return r;
    }
    url = next;
  }
  return null;
}

// ---------- TRUE POSITIVE logic ----------

/** Marker dari spesifikasi. Hanya NAMA marker yang boleh tampil di publik. */
const MARKERS: Array<[string, RegExp]> = [
  ["DB_PASSWORD=", /\bDB_PASSWORD\s*=\s*\S+/],
  ["APP_KEY=", /\bAPP_KEY\s*=\s*\S+/],
  ["AWS_SECRET", /AWS_SECRET[A-Z_]*\s*[=:]\s*\S+|aws_secret_access_key\s*=\s*\S+/i],
  ["PRIVATE KEY block", /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/],
  ["[core]", /^\s*\[core\]\s*$/m],
];

const looksLikeHtml = (s: string) => /<(!doctype|html|head|body)\b/i.test(s.slice(0, 600));

function matchMarker(body: string, extra: Array<[string, RegExp]> = []): string | null {
  for (const [name, re] of [...MARKERS, ...extra]) if (re.test(body)) return name;
  return null;
}

export interface CriticalCheck {
  path: string;
  finding: string;
  fix: string;
  extra?: Array<[string, RegExp]>;
  zip?: boolean;
  allowPhp?: boolean; // wp-config.php.bak diawali "<?php"
}

const FIX_SECRET = "Hapus file dari webroot, blokir akses dotfile/backup di web server, lalu rotasi semua kredensial yang ada di dalamnya.";

export const CRITICAL_CHECKS: CriticalCheck[] = [
  { path: "/.env", finding: ".env exposed", fix: FIX_SECRET },
  {
    path: "/.git/HEAD",
    finding: "Git repository exposed (/.git/HEAD)",
    fix: "Blokir akses ke /.git/ di web server, hapus folder .git dari webroot, dan rotasi secret yang pernah ter-commit.",
    extra: [["git ref", /^ref:\s*refs\/heads\/[\w./-]+/m]],
  },
  {
    path: "/config",
    finding: "Config file exposed (/config)",
    fix: FIX_SECRET,
    extra: [["DB_PASSWORD (any)", /\bDB_PASSWORD['"]?\s*[:=]\s*\S+/]],
  },
  { path: "/backup.zip", finding: "Backup archive exposed (/backup.zip)", fix: "Hapus backup dari webroot, simpan di storage privat, dan anggap isinya sudah bocor (rotasi kredensial).", zip: true },
  { path: "/.aws/credentials", finding: "AWS credentials exposed", fix: "Hapus file, nonaktifkan access key di IAM SEKARANG, buat key baru, dan periksa CloudTrail." },
  {
    path: "/wp-config.php.bak",
    finding: "WordPress config backup exposed (wp-config.php.bak)",
    fix: FIX_SECRET,
    allowPhp: true,
    extra: [["DB_PASSWORD (define)", /define\(\s*['"]DB_PASSWORD['"]\s*,\s*['"][^'"]+['"]/]],
  },
];

const HIGH_DIRS = ["/uploads/", "/backup/", "/files/", "/assets/", "/images/", "/static/"];
const SWAGGER_PATHS = [
  "/swagger", "/swagger/", "/swagger-ui/", "/swagger-ui.html", "/swagger.json",
  "/api-docs", "/v2/api-docs", "/v3/api-docs", "/openapi.json",
];

/** Pure & testable: true-positive hanya jika status 200 + isi cocok marker nyata (bukan sekadar 200). */
export function evaluateCritical(
  c: CriticalCheck,
  r: { status: number; contentType: string; text: string; head: Uint8Array; headers: Headers }
): { marker: string; snippet: string } | null {
  if (r.status !== 200) return null;
  if (c.zip) {
    const h = r.head;
    if (h[0] === 0x50 && h[1] === 0x4b && h[2] === 0x03 && h[3] === 0x04)
      return { marker: "ZIP magic bytes (PK\\x03\\x04)", snippet: `magic=504b0304 content-length=${r.headers.get("content-length") ?? "?"}` };
    return null;
  }
  if (!c.allowPhp && (r.contentType.includes("text/html") || looksLikeHtml(r.text))) return null; // SPA / soft-404
  const marker = matchMarker(r.text, c.extra);
  return marker ? { marker, snippet: r.text.slice(0, 1024) } : null;
}

// ---------- runner ----------

async function pool<T, R>(items: T[], n: number, fn: (x: T) => Promise<R>): Promise<R[]> {
  const out: R[] = new Array(items.length);
  let i = 0;
  await Promise.all(
    Array.from({ length: Math.min(n, items.length) }, async () => {
      while (i < items.length) {
        const idx = i++;
        out[idx] = await fn(items[idx]);
      }
    })
  );
  return out;
}

export async function auditDomain(input: string): Promise<AuditResult> {
  const v = validateDomainInput(input);
  if (!v.ok || !v.hostname) throw new Error(v.error ?? "Domain tidak valid.");
  const domain = v.hostname.toLowerCase();
  const target = await assertPublicHttpsTarget(`https://${domain}`); // SSRF guard (resolve + range check)
  const origin = target.url;

  const findings: PublicFinding[] = [];
  const raw: RawEvidence[] = [];
  const at = (p: string) => new URL(p, origin).toString();

  // 1) CRITICAL — status 200 + body harus mengandung marker nyata
  await pool(CRITICAL_CHECKS, CONCURRENCY, async (c) => {
    const r = await get(at(c.path), c.zip ? 16 : MAX_TEXT_BYTES);
    if (!r || r.status !== 200) return;

    const hit = evaluateCritical(c, r);
    if (!hit) return; // FALSE → buang
    const { marker, snippet } = hit;

    findings.push({
      domain,
      severity: "CRITICAL",
      finding: c.finding,
      evidence_public: `200 OK, response body contains marker "${marker}" (value tidak ditampilkan)`,
      fix: c.fix,
    });
    raw.push({ domain, path: c.path, status: r.status, contentType: r.contentType, marker, snippet });
  });

  // 2) HIGH — security headers dari homepage
  const home = await getHome(origin);
  if (home && home.status >= 200 && home.status < 400) {
    const h = home.headers;
    const csp = h.get("content-security-policy") ?? "";
    const miss = (name: string, finding: string, fix: string) =>
      findings.push({ domain, severity: "HIGH", finding, evidence_public: `Header ${name} tidak ada pada response homepage`, fix });

    if (!h.get("strict-transport-security"))
      miss("Strict-Transport-Security", "Missing HSTS", "Tambahkan `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.");
    if (!csp)
      miss("Content-Security-Policy", "Missing CSP", "Tambahkan CSP minimal (`default-src 'self'`) lalu perketat bertahap.");
    if (!h.get("x-frame-options") && !/frame-ancestors/i.test(csp))
      miss("X-Frame-Options", "Missing X-Frame-Options", "Tambahkan `X-Frame-Options: DENY` atau CSP `frame-ancestors 'none'`.");

    if (/(<title>|<h1>)\s*Index of \//i.test(home.text))
      findings.push({ domain, severity: "HIGH", finding: "Directory listing enabled (/)", evidence_public: '200 OK, halaman berisi indeks direktori ("Index of /")', fix: "Nonaktifkan autoindex / Options -Indexes di web server." });
  }

  // 3) HIGH — directory listing
  await pool(HIGH_DIRS, CONCURRENCY, async (p) => {
    const r = await get(at(p));
    if (!r || r.status !== 200) return;
    if (/(<title>|<h1>)\s*Index of \//i.test(r.text)) {
      findings.push({
        domain, severity: "HIGH", finding: `Directory listing enabled (${p})`,
        evidence_public: `200 OK, halaman ${p} berisi indeks direktori ("Index of /")`,
        fix: "Nonaktifkan autoindex / Options -Indexes di web server.",
      });
    }
  });

  // 4) HIGH — swagger / api-docs
  await pool(SWAGGER_PATHS, CONCURRENCY, async (p) => {
    const r = await get(at(p));
    if (!r || r.status !== 200) return;
    const isJsonSpec = /"(swagger|openapi)"\s*:\s*"\d/.test(r.text);
    const isUi = /swagger-ui|SwaggerUIBundle|<title>[^<]*(swagger|redoc)/i.test(r.text);
    if (!isJsonSpec && !isUi) return;
    findings.push({
      domain, severity: "HIGH", finding: `API documentation exposed (${p})`,
      evidence_public: `200 OK, ${isJsonSpec ? "OpenAPI/Swagger spec" : "Swagger UI"} dapat diakses tanpa autentikasi`,
      fix: "Batasi dokumentasi API ke jaringan internal / di belakang autentikasi, atau nonaktifkan di production.",
    });
  });

  findings.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === "CRITICAL" ? -1 : 1));
  return { domain, scannedAt: Date.now(), findings, raw };
}
