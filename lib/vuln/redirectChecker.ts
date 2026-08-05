/**
 * lib/vuln/redirectChecker.ts
 *
 * Generate test case untuk OPEN_REDIRECT / SSRF dari nama query-param yang
 * "berbau" redirect/target URL. TIDAK melakukan fetch sama sekali (spec:
 * "JANGAN langsung fetch, cukup generate test case untuk laporan karena
 * CORS") — murni analisis nama param + siapin payload buat step eksekusi
 * lain (mis. tester.ts yang sudah ada, yang jalan lewat proxy/user action).
 *
 * Pure function.
 */

import type { AuditFinding, AuditSeverity } from "./types";

const REDIRECT_PARAM_NAMES = ["url", "redirect", "next", "dest", "target", "returnUrl"] as const;

const OPEN_REDIRECT_PAYLOAD = "https://evil.com";
const SSRF_PAYLOADS = ["http://127.0.0.1", "http://169.254.169.254"] as const;

export interface TestCase extends AuditFinding {
  type: "OPEN_REDIRECT" | "SSRF";
  originalUrl: string;
  param: string;
  payload: string;
}

function safeParseUrl(raw: string): URL | null {
  try {
    return new URL(raw, "https://placeholder.invalid");
  } catch {
    return null;
  }
}

function severityFor(type: TestCase["type"]): AuditSeverity {
  return type === "SSRF" ? "high" : "medium";
}

/**
 * Cek query param di `url`; kalau nama param match daftar redirect-like param
 * (url/redirect/next/dest/target/returnUrl), generate test case OPEN_REDIRECT
 * (payload https://evil.com) + test case SSRF (payload internal IP /
 * cloud metadata endpoint). Tidak melakukan request apapun.
 */
export function detectRedirectParams(url: string): TestCase[] {
  const parsed = safeParseUrl(url);
  if (!parsed) return [];

  const cases: TestCase[] = [];
  const paramNamesLower = new Set(REDIRECT_PARAM_NAMES.map((p) => p.toLowerCase()));

  for (const key of parsed.searchParams.keys()) {
    if (!paramNamesLower.has(key.toLowerCase())) continue;

    cases.push({
      type: "OPEN_REDIRECT",
      severity: severityFor("OPEN_REDIRECT"),
      url,
      originalUrl: url,
      param: key,
      payload: OPEN_REDIRECT_PAYLOAD,
      evidence: `param "${key}" terlihat seperti redirect target di ${url}`,
    });

    for (const ssrfPayload of SSRF_PAYLOADS) {
      cases.push({
        type: "SSRF",
        severity: severityFor("SSRF"),
        url,
        originalUrl: url,
        param: key,
        payload: ssrfPayload,
        evidence: `param "${key}" berpotensi dipakai server buat fetch balik ke internal/metadata endpoint`,
      });
    }
  }

  return cases;
}
