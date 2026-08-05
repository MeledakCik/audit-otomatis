/**
 * lib/fuzzer/paramDiscovery.ts
 *
 * Kumpulkan nama query-param unik dari hasil crawl (BUKAN hardcode "id"),
 * lalu sediakan generator variasi value dinamis buat dites di step lain
 * (mis. authChecker / tester.ts yang sudah ada).
 *
 * Pure function, tidak ada network call di sini.
 */

export interface UrlParams {
  url: string;
  params: string[];
}

/** Value default yang di-generate per param untuk fuzzing ringan (bukan payload serangan). */
const DEFAULT_VALUE_VARIANTS = ["true", "false", "0", "1", "admin"] as const;

function safeParseUrl(raw: string): URL | null {
  try {
    // dukung path relatif ("/x?y=1") dengan base dummy, biar URLSearchParams tetap kepakai
    return new URL(raw, "https://placeholder.invalid");
  } catch {
    return null;
  }
}

/**
 * Ambil semua nama query-param unik per URL dari daftar URL hasil crawl.
 * URL tanpa query string dilewati (tidak masuk hasil).
 */
export function discoverDynamicParams(urls: string[]): UrlParams[] {
  const results: UrlParams[] = [];
  const seenUrl = new Set<string>();

  for (const raw of urls) {
    if (seenUrl.has(raw)) continue;
    const parsed = safeParseUrl(raw);
    if (!parsed) continue;

    const paramNames = Array.from(new Set(Array.from(parsed.searchParams.keys())));
    if (paramNames.length === 0) continue;

    seenUrl.add(raw);
    results.push({ url: raw, params: paramNames });
  }

  return results;
}

/** Kumpulan semua nama param unik lintas seluruh URL yang di-crawl (agregat, buat overview). */
export function collectUniqueParamNames(urls: string[]): string[] {
  const names = new Set<string>();
  for (const { params } of discoverDynamicParams(urls)) {
    for (const p of params) names.add(p);
  }
  return Array.from(names);
}

/** Generate daftar value variasi standar (true/false/0/1/admin) untuk satu param. */
export function generateParamValueVariants(paramName: string): string[] {
  // reserved buat kalau nanti mau extend jadi context-aware per nama param
  void paramName;
  return [...DEFAULT_VALUE_VARIANTS];
}

export interface ParamFuzzCase {
  url: string;
  param: string;
  originalValue: string | null;
  candidateValue: string;
  /** URL siap-test dengan param diganti candidateValue (belum di-fetch, cuma disiapkan) */
  testUrl: string;
}

/**
 * Dari hasil discoverDynamicParams, generate daftar test case konkret
 * (url + param + value pengganti) untuk dieksekusi step lain (tester.ts /
 * authChecker.ts). Fungsi ini TIDAK melakukan fetch apapun.
 */
export function buildParamFuzzCases(entries: UrlParams[]): ParamFuzzCase[] {
  const cases: ParamFuzzCase[] = [];

  for (const { url, params } of entries) {
    const parsed = safeParseUrl(url);
    if (!parsed) continue;

    for (const param of params) {
      const originalValue = parsed.searchParams.get(param);
      for (const candidateValue of generateParamValueVariants(param)) {
        const testUrlObj = new URL(parsed.toString());
        testUrlObj.searchParams.set(param, candidateValue);
        cases.push({
          url,
          param,
          originalValue,
          candidateValue,
          testUrl: testUrlObj.toString().replace("https://placeholder.invalid", ""),
        });
      }
    }
  }

  return cases;
}
