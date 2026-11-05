/**
 * lib/discovery/passiveDiscovery.ts
 *
 * Passive discovery: coba fetch beberapa well-known file (sitemap.xml,
 * robots.txt, swagger.json, openapi.json, .well-known/security.txt) dan tarik path baru dari isinya.
 * Mendukung pemeriksaan tetap berjalan walau ada Cloudflare / WAF dengan validasi konten non-challenge.
 */

import { chromeHeaders, detectCloudflareChallenge } from "@/lib/crawler";

const WELL_KNOWN_FILES = [
  "/sitemap.xml",
  "/robots.txt",
  "/.well-known/security.txt",
  "/swagger.json",
  "/openapi.json",
] as const;

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
    if (/^https?:\/\//i.test(rawUrlOrPath)) {
      const u = new URL(rawUrlOrPath);
      if (u.origin !== origin) return null;
      return u.pathname + u.search;
    }
    if (rawUrlOrPath.startsWith("/")) return rawUrlOrPath;
    return null;
  } catch {
    return null;
  }
}

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

async function tryFetchFile(url: string, origin: string, cfClearance?: string): Promise<DiscoveredFileResult> {
  const path = new URL(url).pathname;
  try {
    const res = await fetch(url, {
      method: "GET",
      headers: chromeHeaders(origin, cfClearance),
      redirect: "follow",
    });
    if (!res.ok) {
      return { path, found: false, status: res.status, extractedPaths: [] };
    }
    const text = await res.text();
    if (detectCloudflareChallenge(res.status, res.headers, text.slice(0, 2000))) {
      return { path, found: false, status: res.status, extractedPaths: [] };
    }
    let extractedPaths: string[] = [];
    if (path.endsWith("sitemap.xml")) {
      if (!/<(?:urlset|sitemapindex)\b/i.test(text)) {
        return { path, found: false, status: res.status, extractedPaths: [] };
      }
      extractedPaths = parseSitemapXml(text, origin);
    } else if (path.endsWith("robots.txt")) {
      if (!/^\s*(?:user-agent|disallow|allow|sitemap)\s*:/im.test(text)) {
        return { path, found: false, status: res.status, extractedPaths: [] };
      }
      extractedPaths = parseRobotsTxt(text, origin);
    } else if (path.endsWith("security.txt")) {
      if (!/^\s*(?:contact|expires|encryption|policy)\s*:/im.test(text)) {
        return { path, found: false, status: res.status, extractedPaths: [] };
      }
    } else if (path.endsWith(".json")) {
      if (!/"(?:swagger|openapi)"\s*:/i.test(text)) {
        return { path, found: false, status: res.status, extractedPaths: [] };
      }
    }
    return { path, found: true, status: res.status, extractedPaths };
  } catch {
    return { path, found: false, extractedPaths: [] };
  }
}

export async function discoverFiles(baseUrl: string, cfClearance?: string): Promise<string[]> {
  const origin = new URL(normalizeBaseUrl(baseUrl)).origin;
  const targets = WELL_KNOWN_FILES.map((f) => origin + f);

  const results = await Promise.all(targets.map((url) => tryFetchFile(url, origin, cfClearance)));

  const discovered = new Set<string>();
  for (const r of results) {
    if (r.found) discovered.add(r.path);
    for (const p of r.extractedPaths) discovered.add(p);
  }

  return Array.from(discovered);
}

export async function discoverFilesDetailed(
  baseUrl: string,
  cfClearance?: string
): Promise<DiscoveredFileResult[]> {
  const origin = new URL(normalizeBaseUrl(baseUrl)).origin;
  const targets = WELL_KNOWN_FILES.map((f) => origin + f);
  return Promise.all(targets.map((url) => tryFetchFile(url, origin, cfClearance)));
}
