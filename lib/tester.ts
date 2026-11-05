import type { Finding, Severity } from "./types";
import { chromeHeaders, detectCloudflareChallenge } from "./crawler";
import { analyzeSecurityHeaders } from "./security-headers";
import type { RequestBudget } from "./rate-limit";
import {
  CRITICAL_CHECKS,
  evaluateCritical,
  toPublicFinding,
  type PublicFinding,
  type RawEvidence,
} from "./sentinel/audit";

const LEAK_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  {
    pattern:
      /You have an error in your SQL syntax|SQLSTATE\[\w+\]|Unclosed quotation mark after the character string|pg_query\(\)|mysqli?_(?:fetch|query)\w*\(\)|SQLite3?::|sqlite3\.OperationalError|PSLException/i,
    label: "pesan error SQL",
  },
  {
    pattern:
      /\bat\s+\/(?:var\/www|home|usr|app|srv)\/[^\s<]+\.(?:php|js|py|rb|java):\d+|\bat\s+[A-Za-z]:\\[^\s<]+\.(?:cs|php|js):/i,
    label: "stack trace dengan path server",
  },
  {
    pattern:
      /(?:\n|^)\s+at\s+[\w$.<>]+\s+\((?:\/|file:|[A-Za-z]:\\)[^)\s]+:\d+:\d+\)(?:\s*\n\s+at\s+[^\n]+){2,}/,
    label: "[node2shell] stack trace Node.js",
  },
  {
    pattern:
      /RangeError:\s*(?:Index out of range|Attempt to access memory outside buffer bounds|offset is out of bounds)|ERR_BUFFER_OUT_OF_BOUNDS|ERR_OUT_OF_RANGE/i,
    label: "[Node Out-of-Bounds] RangeError / Buffer OOB exception",
  },
  {
    pattern: /(?:Warning|Fatal error|Parse error):\s+[^<\n]{3,}\s+in\s+\/[^\s<]+\.php\s+on line\s+\d+/i,
    label: "[php2shell / wp2shell] PHP error dengan path file",
  },
  {
    pattern: /goroutine\s+\d+\s+\[(?:running|chan receive|select|IO wait)\]:[\s\S]{10,200}\.go:\d+/i,
    label: "[go2shell] Go panic / goroutine stack trace",
  },
  { pattern: /\bORA-\d{5}\b/, label: "Oracle error code" },
  { pattern: /Traceback \(most recent call last\)/, label: "[py2shell] Python traceback" },
  {
    pattern: /Server Error in '\/[^']*' Application|System\.(?:Data|NullReference)\w*Exception/,
    label: "ASP.NET error page",
  },
];

const SENSITIVE_FILES = [
  "/robots.txt",
  "/.env",
  "/.env.production",
  "/.env.local",
  "/.env.bak",
  "/.git/HEAD",
  "/.git/config",
  "/.git/config/.git",
  "/.git/logs/HEAD",
  "/logs/HEAD",
  "/.git/refs/heads/main",
  "/.git/refs/heads/master",
  "/.git/packed-refs",
  "/.git/COMMIT_EDITMSG",
  "/backup.zip",
  "/wp-config.php.bak",
  "/.aws/credentials",
  "/dump.sql",
];

function snippet(text: string, max = 100): string {
  const clean = text.replace(/\s+/g, " ").trim();
  return clean.length > max ? clean.slice(0, max) + "…" : clean;
}

function newId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function mkFinding(
  severity: Severity,
  title: string,
  endpoint: string,
  evidence: string,
  impact: string,
  fix: string
): Finding {
  return { id: newId(), severity, title, endpoint, evidence, impact, fix };
}

export interface CloudflareStop {
  stopped: true;
  reason: string;
}

export async function testResponseLeakage(url: string): Promise<Finding | null> {
  try {
    const headers = chromeHeaders() as Record<string, string>;
    const res = await fetch(url, { method: "GET", headers: { "User-Agent": headers["User-Agent"] } });
    const text = await res.text();
    const cf = detectCloudflareChallenge(res.status, res.headers, text.slice(0, 2000));
    if (cf) return null;

    const ct = (res.headers.get("content-type") ?? "").toLowerCase();
    if (/image|font|video|audio|javascript|css|octet-stream/.test(ct)) return null;
    const body = text.replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ");

    for (const { pattern, label } of LEAK_PATTERNS) {
      const m = pattern.exec(body);
      if (m) {
        const at = Math.max(0, m.index - 30);
        return mkFinding(
          "HIGH",
          `Response leakage terdeteksi (${label})`,
          url,
          `HTTP ${res.status} — "…${snippet(body.slice(at, at + 140))}"`,
          "Pesan error internal (query, stack trace, buffer out-of-bounds, atau path server) bocor ke client, mempermudah reconnaissance penyerang.",
          "Matikan mode debug di production, tampilkan pesan error generik ke client, dan simpan log detail hanya di server."
        );
      }
    }
    return null;
  } catch {
    return null;
  }
}

export async function testAntiAutomation(url: string): Promise<Finding | null> {
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": "curl/8.0",
      },
    });
    const text = await res.text();
    const cf = detectCloudflareChallenge(res.status, res.headers, text.slice(0, 2000));
    if (cf) return null;

    if (res.status === 200) {
      return mkFinding(
        "MEDIUM",
        "Tidak ada proteksi anti-automation",
        url,
        `HTTP ${res.status} tanpa Sec-Fetch-Site/User-Agent browser wajar tetap diterima`,
        "Endpoint dapat diakses bebas oleh script/bot tanpa validasi asal request, mempermudah scraping/abuse otomatis.",
        "Tambahkan validasi header (Sec-Fetch-Site/Origin), rate limiting, atau proteksi bot (mis. Cloudflare, Turnstile) pada endpoint sensitif."
      );
    }
    return null;
  } catch {
    return null;
  }
}

export interface ExposedHit {
  finding: PublicFinding;
  raw: RawEvidence;
}

export async function testExposedFiles(
  origin: string,
  budget: RequestBudget,
  onHit?: (hit: ExposedHit) => void
): Promise<Finding[]> {
  const findings: Finding[] = [];
  const domain = new URL(origin).hostname.toLowerCase();

  for (const path of SENSITIVE_FILES) {
    const url = new URL(path, origin).toString();
    const result = await budget.spend(async () => {
      try {
        const res = await fetch(url, { method: "GET", headers: chromeHeaders(), redirect: "manual" });
        const buf = Buffer.from(await res.arrayBuffer());
        const text = buf.subarray(0, 64 * 1024).toString("utf8");
        const head = new Uint8Array(buf.subarray(0, 8));
        return {
          status: res.status,
          headers: res.headers,
          text,
          head,
          contentType: (res.headers.get("content-type") ?? "").toLowerCase(),
        };
      } catch {
        return null;
      }
    });
    if (!result) continue;

    const cf = detectCloudflareChallenge(result.status, result.headers, result.text.slice(0, 2000));
    if (cf) continue;

    if (path === "/robots.txt") {
      if (
        result.status === 200 &&
        /^\s*(user-agent|disallow|allow|sitemap)\s*:/im.test(result.text) &&
        !result.contentType.includes("html")
      )
        findings.push(
          mkFinding(
            "INFO",
            "robots.txt ditemukan",
            url,
            "HTTP 200 — file robots valid",
            "robots.txt bersifat publik secara normal, ini hanya info tambahan.",
            "Tidak ada aksi wajib."
          )
        );
      continue;
    }

    const check = CRITICAL_CHECKS.find((c) => c.path === path);
    if (!check) continue;
    const hit = evaluateCritical(check, result);
    if (!hit) continue;

    findings.push({
      ...mkFinding(
        "CRITICAL",
        `File sensitif ter-expose & terverifikasi: ${path}`,
        url,
        `HTTP 200 — body berisi marker "${hit.marker}" (nilai rahasia tidak bocor ke publik & disimpan terenkripsi AES-256-GCM di Admin Vault)`,
        path.startsWith("/.env") || path === "/wp-config.php.bak" || path === "/.aws/credentials"
          ? "File konfigurasi/kredensial rahasia (.env, wp-config.php.bak, AWS keys) terbuka — dampak kompromi penuh bila bocor."
          : path.endsWith(".zip") || path.endsWith(".sql")
          ? "Arsip backup / database dump terbuka di publik — membocorkan kode sumber dan data sensitif."
          : "Metadata Git (.git/config, logs/HEAD, refs/heads) ter-expose sehingga URL repository GitHub/GitLab, riwayat commit, dan source code berpotensi bocor.",
        check.fix
      ),
      category: "sensitive-file",
      confidence: "verified",
    });
    onHit?.({
      finding: toPublicFinding(domain, check, hit.marker),
      raw: {
        domain,
        path,
        status: result.status,
        contentType: result.contentType,
        marker: hit.marker,
        snippet: hit.snippet,
      },
    });
  }
  return findings;
}

export async function testSecurityHeaders(origin: string): Promise<Finding[]> {
  try {
    const res = await fetch(origin, { method: "GET", headers: chromeHeaders() });
    return analyzeSecurityHeaders(res.headers, origin);
  } catch {
    return [];
  }
}
