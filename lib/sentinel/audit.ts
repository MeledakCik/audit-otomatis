import { assertPublicHttpsTarget } from "@/lib/ssrf-guard";
import { validateDomainInput } from "@/lib/validate-domain";
import type { CveDossier } from "./dossier";
import {
  GIT_PASSIVE_PROBES,
  validateGitProbeResponse,
  buildGitIntelReport,
  type GitExposedFileHit,
  type GitIntelReport,
} from "./git-intel";

export type Sev = "CRITICAL" | "HIGH";

/** Bentuk yang BOLEH tampil ke publik. Tidak pernah berisi value rahasia. */
export interface PublicFinding {
  domain: string;
  severity: Sev;
  finding: string;
  evidence_public: string;
  fix: string;
}

/** Bukti mentah → hanya masuk Vault terenkripsi & Admin JSON view. */
export interface RawEvidence {
  domain: string;
  path: string;
  status: number;
  contentType: string;
  marker: string;
  snippet: string; // ≤4 KB awal body atau JSON terstruktur
  gitIntel?: GitIntelReport;
  cveIntel?: CveDossier; // dossier CVE/CWE/RCE lengkap — HANYA admin (vault terenkripsi)
}

export interface AuditResult {
  domain: string;
  scannedAt: number;
  findings: PublicFinding[];
  raw: RawEvidence[];
  gitIntel?: GitIntelReport;
}

const UA = "Sentinel-ID Passive Auditor/3.2 (+https://sentinel-id.net)";
const TIMEOUT_MS = 8000;
const MAX_TEXT_BYTES = 64 * 1024;
const CONCURRENCY = 6;

interface Got {
  status: number;
  headers: Headers;
  contentType: string;
  text: string;
  head: Uint8Array;
}

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

async function getHome(origin: URL): Promise<Got | null> {
  return getFollow(origin, origin);
}

async function getFollow(start: URL, origin: URL): Promise<Got | null> {
  let url = new URL(start.toString());
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
    if (/\/(login|signin|auth)\b/i.test(next.pathname)) return r;
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

const MARKERS: Array<[string, RegExp]> = [
  ["DB_PASSWORD=", /\bDB_PASSWORD\s*=\s*\S+/],
  ["APP_KEY=", /\bAPP_KEY\s*=\s*\S+/],
  ["AWS_SECRET", /AWS_SECRET[A-Z_]*\s*[=:]\s*\S+|aws_secret_access_key\s*=\s*\S+/i],
  ["PRIVATE KEY block", /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/],
  ["[core]", /^\s*\[core\]\s*$/m],
  ["[remote origin]", /^\s*\[remote\s+"[^"]+"\]/m],
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
  allowPhp?: boolean;
}

const FIX_SECRET =
  "Hapus file dari webroot, blokir akses dotfile/backup di web server, lalu rotasi semua kredensial yang ada di dalamnya.";
const FIX_GIT =
  "Blokir akses ke /.git/ dan /logs/HEAD di konfigurasi web server (Nginx/Apache), hapus metadata .git dari webroot produksi, dan rotasi kredensial/token yang pernah ter-commit.";

export const CRITICAL_CHECKS: CriticalCheck[] = [
  { path: "/.env", finding: ".env exposed", fix: FIX_SECRET },
  {
    path: "/.git/HEAD",
    finding: "Git repository exposed (/.git/HEAD)",
    fix: FIX_GIT,
    extra: [["git ref", /^ref:\s*refs\/heads\/[\w./-]+/m]],
  },
  {
    path: "/.git/config",
    finding: "Git config exposed (/.git/config)",
    fix: FIX_GIT,
    extra: [["[remote]", /\[remote\s+"[^"]+"\]/i]],
  },
  {
    path: "/.git/config/.git",
    finding: "Nested Git config exposed (/.git/config/.git)",
    fix: FIX_GIT,
    extra: [["[core]/[remote]", /\[(core|remote\s+"[^"]+")\]/i]],
  },
  {
    path: "/.git/logs/HEAD",
    finding: "Git reflog history exposed (/.git/logs/HEAD)",
    fix: FIX_GIT,
    extra: [["git reflog", /^[0-9a-f]{40}\s+[0-9a-f]{40}\s+/m]],
  },
  {
    path: "/logs/HEAD",
    finding: "Git reflog exposed at root (/logs/HEAD)",
    fix: FIX_GIT,
    extra: [["git reflog", /^[0-9a-f]{40}\s+[0-9a-f]{40}\s+/m]],
  },
  {
    path: "/.git/refs/heads/main",
    finding: "Git branch SHA exposed (/.git/refs/heads/main)",
    fix: FIX_GIT,
    extra: [["branch main SHA", /^[0-9a-f]{40}\s*$/i]],
  },
  {
    path: "/.git/refs/heads/master",
    finding: "Git branch SHA exposed (/.git/refs/heads/master)",
    fix: FIX_GIT,
    extra: [["branch master SHA", /^[0-9a-f]{40}\s*$/i]],
  },
  {
    path: "/.git/refs/heads/production",
    finding: "Git branch SHA exposed (/.git/refs/heads/production)",
    fix: FIX_GIT,
    extra: [["branch production SHA", /^[0-9a-f]{40}\s*$/i]],
  },
  {
    path: "/.git/refs/heads/develop",
    finding: "Git branch SHA exposed (/.git/refs/heads/develop)",
    fix: FIX_GIT,
    extra: [["branch develop SHA", /^[0-9a-f]{40}\s*$/i]],
  },
  {
    path: "/.git/packed-refs",
    finding: "Git packed-refs exposed (/.git/packed-refs)",
    fix: FIX_GIT,
    extra: [["pack-refs", /^(#\s*pack-refs|[0-9a-f]{40}\s+refs\/)/m]],
  },
  {
    path: "/.git/COMMIT_EDITMSG",
    finding: "Git last commit message exposed (/.git/COMMIT_EDITMSG)",
    fix: FIX_GIT,
    extra: [["commit message", /^(feat|fix|chore|Merge|Initial|Update|Refactor|hotfix|release)\b/im]],
  },
  {
    path: "/config",
    finding: "Config file exposed (/config)",
    fix: FIX_SECRET,
    extra: [["DB_PASSWORD (any)", /\bDB_PASSWORD['"]?\s*[:=]\s*\S+/]],
  },
  { path: "/.env.production", finding: ".env.production exposed", fix: FIX_SECRET },
  { path: "/.env.local", finding: ".env.local exposed", fix: FIX_SECRET },
  { path: "/.env.bak", finding: ".env backup exposed (.env.bak)", fix: FIX_SECRET },
  {
    path: "/backup.zip",
    finding: "Backup archive exposed (/backup.zip)",
    fix: "Hapus backup dari webroot, simpan di storage privat, dan anggap isinya sudah bocor (rotasi kredensial).",
    zip: true,
  },
  {
    path: "/.aws/credentials",
    finding: "AWS credentials exposed",
    fix: "Hapus file, nonaktifkan access key di IAM SEKARANG, buat key baru, dan periksa CloudTrail.",
  },
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
  "/swagger",
  "/swagger/",
  "/swagger-ui/",
  "/swagger-ui.html",
  "/swagger.json",
  "/api-docs",
  "/v2/api-docs",
  "/v3/api-docs",
  "/openapi.json",
];

export function evaluateCritical(
  c: CriticalCheck,
  r: { status: number; contentType: string; text: string; head: Uint8Array; headers: Headers }
): { marker: string; snippet: string } | null {
  if (r.status !== 200) return null;
  if (c.zip) {
    const h = r.head;
    if (h[0] === 0x50 && h[1] === 0x4b && h[2] === 0x03 && h[3] === 0x04)
      return {
        marker: "ZIP magic bytes (PK\\x03\\x04)",
        snippet: `magic=504b0304 content-length=${r.headers.get("content-length") ?? "?"}`,
      };
    return null;
  }
  if (!c.allowPhp && (r.contentType.includes("text/html") || looksLikeHtml(r.text))) return null;

  // Check if this is one of the specialized Git probes first
  const gitSpec = GIT_PASSIVE_PROBES.find((g) => g.path === c.path);
  if (gitSpec) {
    const gv = validateGitProbeResponse(gitSpec, r.status, r.contentType, r.text);
    if (gv.valid) {
      return { marker: gv.marker, snippet: r.text.slice(0, 2048) };
    }
  }

  const marker = matchMarker(r.text, c.extra);
  return marker ? { marker, snippet: r.text.slice(0, 2048) } : null;
}

export function toPublicFinding(domain: string, c: CriticalCheck, marker: string): PublicFinding {
  return {
    domain,
    severity: "CRITICAL",
    finding: c.finding,
    evidence_public: `200 OK, response body contains marker "${marker}" (detail lengkap & JSON repo tersimpan di Admin Vault)`,
    fix: c.fix,
  };
}

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
  const target = await assertPublicHttpsTarget(`https://${domain}`);
  const origin = target.url;

  const findings: PublicFinding[] = [];
  const raw: RawEvidence[] = [];
  const gitHits: GitExposedFileHit[] = [];
  const at = (p: string) => new URL(p, origin).toString();

  // 1) CRITICAL — termasuk seluruh probe Git (/.git/config, /.git/config/.git, /logs/HEAD, /.git/refs/heads/main, dll.)
  await pool(CRITICAL_CHECKS, CONCURRENCY, async (c) => {
    const r = await get(at(c.path), c.zip ? 16 : MAX_TEXT_BYTES);
    if (!r || r.status !== 200) return;

    const hit = evaluateCritical(c, r);
    if (!hit) return;
    const { marker, snippet } = hit;

    findings.push(toPublicFinding(domain, c, marker));
    raw.push({ domain, path: c.path, status: r.status, contentType: r.contentType, marker, snippet });

    if (c.path.includes(".git") || c.path.endsWith("logs/HEAD")) {
      gitHits.push({
        path: c.path,
        status: r.status,
        marker,
        contentType: r.contentType,
        snippet,
      });
    }
  });

  // 1b) Probe additional Git paths from GIT_PASSIVE_PROBES not already in CRITICAL_CHECKS
  const extraGitProbes = GIT_PASSIVE_PROBES.filter(
    (gp) => !CRITICAL_CHECKS.some((cc) => cc.path === gp.path)
  );
  await pool(extraGitProbes, CONCURRENCY, async (gp) => {
    const r = await get(at(gp.path), MAX_TEXT_BYTES);
    if (!r || r.status !== 200) return;
    const gv = validateGitProbeResponse(gp, r.status, r.contentType, r.text);
    if (!gv.valid) return;
    const snippet = r.text.slice(0, 2048);
    gitHits.push({
      path: gp.path,
      status: r.status,
      marker: gv.marker,
      contentType: r.contentType,
      snippet,
    });
    findings.push({
      domain,
      severity: "CRITICAL",
      finding: gp.findingTitle,
      evidence_public: `200 OK, marker "${gv.marker}" terdeteksi (detail JSON tersimpan di Admin Vault)`,
      fix: FIX_GIT,
    });
    raw.push({
      domain,
      path: gp.path,
      status: r.status,
      contentType: r.contentType,
      marker: gv.marker,
      snippet,
    });
  });

  // Build structured Git & Repository Intelligence JSON if any Git artifacts were exposed
  let gitIntel: GitIntelReport | undefined;
  if (gitHits.length > 0) {
    gitIntel = buildGitIntelReport(domain, gitHits);
    if (gitIntel.primaryRepository.detected && gitIntel.primaryRepository.webUrl) {
      findings.unshift({
        domain,
        severity: "CRITICAL",
        finding: `Git Remote Repository Teridentifikasi (${gitIntel.primaryRepository.provider.toUpperCase()}: ${gitIntel.primaryRepository.repoFullName})`,
        evidence_public: `Remote origin mengarah ke ${gitIntel.primaryRepository.provider.toUpperCase()} repository (URL & JSON lengkap disimpan di Admin Console)`,
        fix: FIX_GIT,
      });
    }
    // Save structured JSON summary entry directly into Admin Vault
    raw.unshift({
      domain,
      path: "/__git-intelligence.json",
      status: 200,
      contentType: "application/json",
      marker: gitIntel.primaryRepository.webUrl
        ? `REPO: ${gitIntel.primaryRepository.webUrl}`
        : `GIT_INTEL_JSON (${gitHits.length} files)`,
      snippet: JSON.stringify(gitIntel, null, 2),
      gitIntel,
    });
  }

  // 2) HIGH — security headers dari homepage
  const home = await getHome(origin);
  if (home && home.status >= 200 && home.status < 400) {
    const h = home.headers;
    const csp = h.get("content-security-policy") ?? "";
    const miss = (name: string, finding: string, fix: string) =>
      findings.push({
        domain,
        severity: "HIGH",
        finding,
        evidence_public: `Header ${name} tidak ada pada response homepage`,
        fix,
      });

    if (!h.get("strict-transport-security"))
      miss(
        "Strict-Transport-Security",
        "Missing HSTS",
        "Tambahkan `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`."
      );
    if (!csp)
      miss(
        "Content-Security-Policy",
        "Missing CSP",
        "Tambahkan CSP minimal (`default-src 'self'`) lalu perketat bertahap."
      );
    const hsts = h.get("strict-transport-security");
    if (hsts) {
      const age = Number(/max-age\s*=\s*(\d+)/i.exec(hsts)?.[1] ?? 0);
      if (age < 15552000)
        findings.push({
          domain,
          severity: "HIGH",
          finding: "Weak HSTS (max-age terlalu pendek)",
          evidence_public: `Strict-Transport-Security max-age=${age} detik (< 180 hari)`,
          fix: "Naikkan `max-age` ke ≥ 31536000 dan tambahkan `includeSubDomains`.",
        });
    }
    if (csp) {
      const dir = /(?:^|;)\s*(?:script-src|default-src)\s+([^;]*)/gi;
      let m: RegExpExecArray | null;
      while ((m = dir.exec(csp))) {
        if (/(^|\s)(\*|https:|http:|data:)(\s|$)/.test(m[1])) {
          findings.push({
            domain,
            severity: "HIGH",
            finding: "Weak CSP (wildcard/skema terbuka di script-src/default-src)",
            evidence_public: "CSP mengizinkan sumber script yang terlalu luas (*, https:, http:, atau data:)",
            fix: "Daftarkan host script secara eksplisit atau pakai nonce/hash + 'strict-dynamic'.",
          });
          break;
        }
      }
    }
    if (!h.get("x-frame-options") && !/frame-ancestors/i.test(csp))
      miss(
        "X-Frame-Options",
        "Missing X-Frame-Options",
        "Tambahkan `X-Frame-Options: DENY` atau CSP `frame-ancestors 'none'`."
      );

    if (/(<title>|<h1>)\s*Index of \//i.test(home.text))
      findings.push({
        domain,
        severity: "HIGH",
        finding: "Directory listing enabled (/)",
        evidence_public: '200 OK, halaman berisi indeks direktori ("Index of /")',
        fix: "Nonaktifkan autoindex / Options -Indexes di web server.",
      });
  }

  // 3) HIGH — directory listing
  await pool(HIGH_DIRS, CONCURRENCY, async (p) => {
    const r = await getFollow(new URL(at(p)), origin);
    if (!r || r.status !== 200) return;
    if (/(<title>|<h1>)\s*Index of \//i.test(r.text)) {
      findings.push({
        domain,
        severity: "HIGH",
        finding: `Directory listing enabled (${p})`,
        evidence_public: `200 OK, halaman ${p} berisi indeks direktori ("Index of /")`,
        fix: "Nonaktifkan autoindex / Options -Indexes di web server.",
      });
    }
  });

  // 4) HIGH — swagger / api-docs
  await pool(SWAGGER_PATHS, CONCURRENCY, async (p) => {
    const r = await getFollow(new URL(at(p)), origin);
    if (!r || r.status !== 200) return;
    const isJsonSpec = /"(swagger|openapi)"\s*:\s*"\d/.test(r.text);
    const isUi = /swagger-ui|SwaggerUIBundle|<title>[^<]*(swagger|redoc)/i.test(r.text);
    if (!isJsonSpec && !isUi) return;
    findings.push({
      domain,
      severity: "HIGH",
      finding: `API documentation exposed (${p})`,
      evidence_public: `200 OK, ${isJsonSpec ? "OpenAPI/Swagger spec" : "Swagger UI"} dapat diakses tanpa autentikasi`,
      fix: "Batasi dokumentasi API ke jaringan internal / di belakang autentikasi, atau nonaktifkan di production.",
    });
  });

  // 5) HIGH — phpinfo()
  {
    const r = await get(at("/phpinfo.php"));
    if (
      r &&
      r.status === 200 &&
      /phpinfo\(\)|<title>phpinfo\(\)<\/title>/i.test(r.text) &&
      /PHP Version/i.test(r.text)
    )
      findings.push({
        domain,
        severity: "HIGH",
        finding: "phpinfo() exposed (/phpinfo.php)",
        evidence_public: "200 OK, halaman phpinfo() dapat diakses publik",
        fix: "Hapus phpinfo.php dari production.",
      });
  }

  findings.sort((a, b) => (a.severity === b.severity ? 0 : a.severity === "CRITICAL" ? -1 : 1));
  return { domain, scannedAt: Date.now(), findings, raw, gitIntel };
}
