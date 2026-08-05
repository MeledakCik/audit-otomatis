/**
 * lib/vuln/authChecker.ts
 *
 * Non-destructive check: fetch endpoint TANPA credentials (credentials:
 * "omit") dan lihat apakah tetap 200 OK padahal path-nya kelihatan seperti
 * endpoint yang harusnya butuh auth (/api/admin, /api/me, /api/user).
 * Juga cek keberadaan rate-limit header sebagai sinyal awal (bukan bukti
 * definitif) kalau endpoint tidak punya rate limiting.
 *
 * Ini cuma 1x GET read-only tanpa credential — tidak mengubah state, tidak
 * mencoba bypass beneran (tidak ada token forging / header spoofing).
 * Semua error (CORS, network, dsb) ditangkap, tidak melempar ke pemanggil.
 */

import type { AuditFinding } from "./types";

const SENSITIVE_PATH_MARKERS = ["/api/admin", "/api/me", "/api/user"] as const;
const RATE_LIMIT_HEADER_NAMES = [
  "x-ratelimit-limit",
  "ratelimit-limit",
  "x-rate-limit-limit",
  "x-ratelimit-remaining",
] as const;

export interface AuthCheckResult {
  url: string;
  reachable: boolean;
  status: number | null;
  findings: AuditFinding[];
}

function looksSensitive(endpoint: string): boolean {
  const path = endpoint.toLowerCase();
  return SENSITIVE_PATH_MARKERS.some((marker) => path.includes(marker));
}

function hasRateLimitHeader(headers: Headers): boolean {
  return RATE_LIMIT_HEADER_NAMES.some((h) => headers.has(h));
}

/**
 * Coba GET `endpoint` tanpa credentials. Kalau status 200 dan path terlihat
 * sensitif (/api/admin, /api/me, /api/user) -> AUTH_BYPASS_POTENTIAL.
 * Kalau tidak ada rate-limit header di response -> MISSING_RATE_LIMIT_HEADER.
 * Semua fetch error (CORS/network) ditangkap dan dilaporkan sebagai
 * `reachable: false`, tidak dilempar sebagai exception.
 */
export async function checkAuthBypass(endpoint: string): Promise<AuthCheckResult> {
  const findings: AuditFinding[] = [];

  let res: Response;
  try {
    res = await fetch(endpoint, { method: "GET", credentials: "omit" });
  } catch {
    return { url: endpoint, reachable: false, status: null, findings };
  }

  if (res.status === 200 && looksSensitive(endpoint)) {
    findings.push({
      type: "AUTH_BYPASS_POTENTIAL",
      severity: "high",
      url: endpoint,
      evidence: `GET ${endpoint} tanpa credentials mengembalikan HTTP 200 pada path yang terlihat butuh auth`,
    });
  }

  if (!hasRateLimitHeader(res.headers)) {
    findings.push({
      type: "MISSING_RATE_LIMIT_HEADER",
      severity: "low",
      url: endpoint,
      evidence: `Response dari ${endpoint} tidak mengandung header rate-limit umum (x-ratelimit-limit / ratelimit-limit)`,
    });
  }

  return { url: endpoint, reachable: true, status: res.status, findings };
}

/**
 * Helper buat jalanin checkAuthBypass ke banyak endpoint sekaligus,
 * dengan batas concurrency sederhana biar tidak spam request bersamaan.
 */
export async function checkAuthBypassBatch(
  endpoints: string[],
  concurrency = 4
): Promise<AuthCheckResult[]> {
  const results: AuthCheckResult[] = new Array(endpoints.length);
  let cursor = 0;

  async function worker() {
    while (cursor < endpoints.length) {
      const i = cursor++;
      results[i] = await checkAuthBypass(endpoints[i]);
    }
  }

  const workers = Array.from({ length: Math.min(concurrency, endpoints.length) }, () => worker());
  await Promise.all(workers);
  return results;
}
