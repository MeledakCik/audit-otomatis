/**
 * lib/discovery/passiveDiscovery.ts
 *
 * CORS-safe passive discovery: coba fetch beberapa well-known file (sitemap,
 * robots.txt, swagger/openapi spec) dan tarik path baru dari isinya.
 * Semua fetch dibungkus try-catch per-request — kalau kena CORS/network
 * error, di-skip diam-diam, TIDAK melempar error ke pemanggil (spec: "jangan
 * errorin app").
 *
 * Pure-ish (satu-satunya side effect adalah network fetch, tidak ada
 * Node.js fs / backend dependency). Jalan penuh di browser.
 */

const WELL_KNOWN_FILES = ["/sitemap.xml", "/robots.txt", "/swagger.json", "/openapi.json"] as const;

export interface DiscoveredFileResult {
  path: string;
  found: boolean;
  status?: number;
  /** path-path baru yang berhasil di-parse dari isi file ini (sitemap/robots) */
  extractedPaths: string[];
}

function normalizeBaseUrl(baseUrl: string): string {
  return baseUrl.replace(/\/+$/, "");
}

function toPath(rawUrlOrPath: string, origin: string): string | null {
  try {
    // absolute URL (mis. <loc>https://site.com/page</loc>)
    if (/^https?:\/\//i.test(rawUrlOrPath)) {
      const u = new URL(rawUrlOrPath);
      // hanya ambil kalau origin sama, biar tidak nyasar ke domain lain
      if (u.origin !== origin) return null;
      return u.pathname + u.search;
    }
    if (rawUrlOrPath.startsWith("/")) return rawUrlOrPath;
    return null;
  } catch {
    return null;
  }
}

/** Extract semua <loc>...</loc> dari sitemap.xml (regex, bukan XML parser, biar 0-dependency). */
function parseSitemapXml(xml: string, origin: string): string[] {
  const out = new Set<string>();
  const locRe = /<loc>\s*([^<\s][^<]*?)\s*<\/loc>/gi;
  let m: RegExpExecArray | null;
  while ((m = locRe.exec(xml)) !== null) {
    const p = toPath(m[1].trim(), origin);
    if (p) out.add(p);
  }
  return Array.from(out);
}

/** Extract path dari robots.txt: baris Allow:/Disallow: dan URL di baris Sitemap:. */
function parseRobotsTxt(text: string, origin: string): string[] {
  const out = new Set<string>();
  const lines = text.split(/\r?\n/);
  for (const rawLine of lines) {
    const line = rawLine.trim();
    const dirMatch = /^(Allow|Disallow)\s*:\s*(\S+)/i.exec(line);
    if (dirMatch) {
      const p = toPath(dirMatch[2].trim(), origin);
      if (p && p !== "/") out.add(p);
      continue;
    }
    const sitemapMatch = /^Sitemap\s*:\s*(\S+)/i.exec(line);
    if (sitemapMatch) {
      const p = toPath(sitemapMatch[1].trim(), origin);
      if (p) out.add(p);
    }
  }
  return Array.from(out);
}

async function tryFetchFile(url: string, origin: string): Promise<DiscoveredFileResult> {
  const path = new URL(url).pathname;
  try {
    const res = await fetch(url, { mode: "cors" });
    if (!res.ok) {
      return { path, found: false, status: res.status, extractedPaths: [] };
    }
    const text = await res.text();
    let extractedPaths: string[] = [];
    if (path.endsWith("sitemap.xml")) extractedPaths = parseSitemapXml(text, origin);
    else if (path.endsWith("robots.txt")) extractedPaths = parseRobotsTxt(text, origin);
    // swagger.json / openapi.json sengaja tidak di-parse di sini (itu tugas
    // module fingerprint/endpoint terpisah) — cukup dicatat "found" dulu.
    return { path, found: true, status: res.status, extractedPaths };
  } catch {
    // CORS error, network error, DNS fail, dll — skip diam-diam sesuai spec.
    return { path, found: false, extractedPaths: [] };
  }
}

/**
 * Coba fetch beberapa well-known file (sitemap.xml, robots.txt, swagger.json,
 * openapi.json) dari baseUrl dengan mode "cors". Setiap request di-try-catch
 * independen supaya satu file gagal (CORS/network) tidak menggagalkan yang
 * lain. Return array path unik gabungan: file yang berhasil ditemukan +
 * path baru yang berhasil diparse dari isi sitemap/robots.
 */
export async function discoverFiles(baseUrl: string): Promise<string[]> {
  const origin = new URL(normalizeBaseUrl(baseUrl)).origin;
  const targets = WELL_KNOWN_FILES.map((f) => origin + f);

  const results = await Promise.all(targets.map((url) => tryFetchFile(url, origin)));

  const discovered = new Set<string>();
  for (const r of results) {
    if (r.found) discovered.add(r.path);
    for (const p of r.extractedPaths) discovered.add(p);
  }

  return Array.from(discovered);
}

/** Variant yang mengembalikan detail per-file (status, apa yang berhasil diparse), untuk laporan. */
export async function discoverFilesDetailed(baseUrl: string): Promise<DiscoveredFileResult[]> {
  const origin = new URL(normalizeBaseUrl(baseUrl)).origin;
  const targets = WELL_KNOWN_FILES.map((f) => origin + f);
  return Promise.all(targets.map((url) => tryFetchFile(url, origin)));
}
