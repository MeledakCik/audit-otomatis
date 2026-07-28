import type { Finding, Severity } from "./types";
import { chromeHeaders, detectCloudflareChallenge } from "./crawler";
import { analyzeSecurityHeaders } from "./security-headers";
import type { RequestBudget } from "./rate-limit";

const LEAK_PATTERNS: Array<{ pattern: RegExp; label: string }> = [
  { pattern: /\bSQL\b/i, label: "kata 'SQL'" },
  { pattern: /stack\s*trace|at\s+\/var\/www|at\s+[A-Za-z]:\\/i, label: "stack trace" },
  { pattern: /token is missing/i, label: "'token is missing'" },
  { pattern: /\bexpected\b.{0,40}\bgot\b/i, label: "pesan error 'expected ... got'" },
  { pattern: /Warning:\s+.*on line \d+/i, label: "PHP warning" },
  { pattern: /ORA-\d{5}/i, label: "Oracle error code" },
  { pattern: /Traceback \(most recent call last\)/i, label: "Python traceback" },
];

const SENSITIVE_FILES = ["/robots.txt", "/.env", "/.git/HEAD"];

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

/**
 * Test 1: Response leakage — fetch tanpa cookie/header khusus, cek apakah
 * body mengandung pola bocoran error internal.
 */
export async function testResponseLeakage(url: string): Promise<Finding | null> {
  try {
    const headers = chromeHeaders() as Record<string, string>;
    const res = await fetch(url, { method: "GET", headers: { "User-Agent": headers["User-Agent"] } });
    const text = await res.text();
    const cf = detectCloudflareChallenge(res.status, res.headers, text.slice(0, 2000));
    if (cf) return null;

    for (const { pattern, label } of LEAK_PATTERNS) {
      if (pattern.test(text)) {
        return mkFinding(
          "HIGH",
          `Response leakage terdeteksi (${label})`,
          url,
          `HTTP ${res.status} — "${snippet(text)}"`,
          "Pesan error internal (query, stack trace, path server) bocor ke client, mempermudah reconnaissance penyerang.",
          "Matikan mode debug di production, tampilkan pesan error generik ke client, log detail hanya di server."
        );
      }
    }
    return null;
  } catch {
    return null;
  }
}

/**
 * Test 2: Anti-automation — fetch tanpa Sec-Fetch-Site, cek apakah tetap 200.
 * (indikasi tidak ada proteksi terhadap request otomatis/non-browser)
 */
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

/**
 * Test 3: Open file exposure — /robots.txt, /.env, /.git/HEAD.
 * Kalau 200 -> CRITICAL untuk .env dan .git/HEAD, tapi TIDAK menampilkan isi.
 */
export async function testExposedFiles(
  origin: string,
  budget: RequestBudget
): Promise<Finding[]> {
  const findings: Finding[] = [];
  for (const path of SENSITIVE_FILES) {
    const url = new URL(path, origin).toString();
    const result = await budget.spend(async () => {
      try {
        const res = await fetch(url, { method: "GET", headers: chromeHeaders() });
        const text = await res.text();
        return { status: res.status, headers: res.headers, textLen: text.length, textPreview: text.slice(0, 2000) };
      } catch {
        return null;
      }
    });
    if (!result) continue;

    const cf = detectCloudflareChallenge(result.status, result.headers, result.textPreview);
    if (cf) continue;

    if (result.status === 200) {
      const isCritical = path !== "/robots.txt";
      findings.push(
        mkFinding(
          isCritical ? "CRITICAL" : "INFO",
          `File berpotensi sensitif ter-expose: ${path}`,
          url,
          `HTTP 200 — file dapat diakses publik (isi tidak ditampilkan demi keamanan)`,
          path === "/.env"
            ? "File .env bisa berisi kredensial/API key/secret database — dampak kompromi penuh bila bocor."
            : path === "/.git/HEAD"
              ? "Folder .git ter-expose berarti seluruh riwayat source code berpotensi diunduh penyerang."
              : "robots.txt bersifat publik secara normal, ini hanya info tambahan.",
          path === "/.env"
            ? "Hapus file .env dari direktori publik, pastikan web server tidak serve dotfile, rotasi semua secret yang mungkin bocor."
            : path === "/.git/HEAD"
              ? "Blokir akses ke folder .git di konfigurasi web server/reverse proxy, atau pastikan build output tidak menyertakan .git."
              : "Tidak ada aksi wajib."
        )
      );
    }
  }
  return findings;
}

/**
 * Test 4: Security headers, logic ala securityheaders.com
 */
export async function testSecurityHeaders(origin: string): Promise<Finding[]> {
  try {
    const res = await fetch(origin, { method: "GET", headers: chromeHeaders() });
    return analyzeSecurityHeaders(res.headers, origin);
  } catch {
    return [];
  }
}
