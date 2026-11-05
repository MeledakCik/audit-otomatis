import * as cheerio from "cheerio";
import { parseHTML } from "linkedom";
import type { CrawlResult, FormInfo } from "./types";

const CHROME_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

export const MAX_INTERNAL_LINKS = 50;

export function sanitizeCfClearance(raw?: string): string | undefined {
  if (!raw) return undefined;
  const trimmed = raw.trim().replace(/^cf_clearance\s*=\s*/i, "").trim();
  if (!trimmed || !/^[A-Za-z0-9._-]+$/.test(trimmed)) return undefined;
  return trimmed;
}

export function chromeHeaders(referer?: string, cfClearance?: string): HeadersInit {
  const cleanToken = sanitizeCfClearance(cfClearance);
  return {
    "User-Agent": CHROME_UA,
    Accept:
      "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "id-ID,id;q=0.9,en-US;q=0.8,en;q=0.7",
    "Cache-Control": "no-cache",
    Pragma: "no-cache",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Site": referer ? "same-origin" : "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Sec-Ch-Ua": '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    ...(referer ? { Referer: referer } : {}),
    ...(cleanToken ? { Cookie: `cf_clearance=${cleanToken}` } : {}),
  };
}

export interface CloudflareChallenge {
  challenged: true;
  status: number;
  reason: string;
  wafProvider?: string;
  cfRay?: string;
}

export interface WafEdgeInfo {
  detected: boolean;
  provider: string;
  challenged: boolean;
  status: number;
  cfRay?: string;
  cacheStatus?: string;
  serverHeader?: string;
}

export function detectWafAndEdgeInfo(
  status: number,
  headers: Headers,
  bodySnippet: string
): WafEdgeInfo {
  const server = (headers.get("server") ?? "").toLowerCase();
  const cfRay = headers.get("cf-ray") ?? undefined;
  const cfCache = headers.get("cf-cache-status") ?? undefined;
  const cfMitigated = headers.get("cf-mitigated") ?? "";
  const xVercel = headers.get("x-vercel-id");
  const xSucuri = headers.get("x-sucuri-id");
  const xAkamai = headers.get("x-akamai-transformed") || headers.get("server-timing");

  let provider = "None";
  if (cfRay || server.includes("cloudflare")) provider = "Cloudflare WAF / CDN";
  else if (xSucuri || server.includes("sucuri")) provider = "Sucuri Cloudproxy WAF";
  else if (server.includes("cloudfront") || headers.get("x-amz-cf-id")) provider = "AWS CloudFront / WAF";
  else if (server.includes("akamai") || xAkamai) provider = "Akamai Edge / Kona WAF";
  else if (headers.get("x-iinfo") || /incapsula|imperva/i.test(bodySnippet)) provider = "Imperva Incapsula WAF";
  else if (xVercel || server.includes("vercel")) provider = "Vercel Edge Network";

  const ch = detectCloudflareChallenge(status, headers, bodySnippet);
  return {
    detected: provider !== "None" || Boolean(ch),
    provider: provider === "None" && ch ? "Cloudflare / Edge WAF" : provider,
    challenged: Boolean(ch) || cfMitigated === "challenge",
    status,
    cfRay,
    cacheStatus: cfCache,
    serverHeader: headers.get("server") ?? undefined,
  };
}

export function detectCloudflareChallenge(
  status: number,
  headers: Headers,
  bodySnippet: string
): CloudflareChallenge | null {
  const cfMitigated = headers.get("cf-mitigated");
  const cfRay = headers.get("cf-ray") ?? undefined;
  const bodyHasChallenge =
    /Attention Required[!]?\s*\|\s*Cloudflare/i.test(bodySnippet) ||
    /<title>\s*Just a moment\.\.\.\s*<\/title>/i.test(bodySnippet) ||
    /cf-browser-verification|__cf_chl_opt|turnstile\/v0\/api\.js/i.test(bodySnippet);
  const isChallengeStatus = (status === 403 || status === 503) && cfMitigated === "challenge";

  if (bodyHasChallenge || isChallengeStatus) {
    return {
      challenged: true,
      status,
      wafProvider: "Cloudflare",
      cfRay,
      reason: bodyHasChallenge
        ? "Halaman interaktif Cloudflare Challenge ('Just a moment' / 'Attention Required') aktif pada rute ini"
        : `Header cf-mitigated: challenge terdeteksi pada status HTTP ${status}${cfRay ? ` (CF-RAY: ${cfRay})` : ""}`,
    };
  }
  return null;
}

function resolveUrl(base: string, href: string): string | null {
  try {
    return new URL(href, base).toString();
  } catch {
    return null;
  }
}

export async function crawlHomepage(
  origin: string,
  cfClearance?: string
): Promise<{
  result: CrawlResult;
  status: number;
  cloudflare: CloudflareChallenge | null;
}> {
  const res = await fetch(origin, {
    method: "GET",
    headers: chromeHeaders(undefined, cfClearance),
    redirect: "follow",
  });

  const bodyFull = await res.text();
  const bodySnippet = bodyFull.slice(0, 2000);

  const cloudflare = detectCloudflareChallenge(res.status, res.headers, bodySnippet);
  if (cloudflare) {
    return {
      result: { origin, internalLinks: [], scripts: [], forms: [], inlineScripts: [] },
      status: res.status,
      cloudflare,
    };
  }

  const $ = cheerio.load(bodyFull);
  const originUrl = new URL(origin);

  const internalLinks = new Set<string>();
  $("a[href]").each((_, el) => {
    if (internalLinks.size >= MAX_INTERNAL_LINKS) return;
    const href = $(el).attr("href");
    if (!href || href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("tel:")) {
      return;
    }
    const resolved = resolveUrl(origin, href);
    if (!resolved) return;
    try {
      const u = new URL(resolved);
      if (u.hostname === originUrl.hostname) {
        u.hash = "";
        internalLinks.add(u.toString());
      }
    } catch {
      // ignore
    }
  });

  const scripts = new Set<string>();
  $("script[src]").each((_, el) => {
    const src = $(el).attr("src");
    if (!src) return;
    const resolved = resolveUrl(origin, src);
    if (!resolved) return;
    try {
      const u = new URL(resolved);
      scripts.add(u.toString());
    } catch {
      // ignore
    }
  });

  const forms: FormInfo[] = [];
  $("form").each((_, el) => {
    const $form = $(el);
    const actionRaw = $form.attr("action") || origin;
    const resolvedAction = resolveUrl(origin, actionRaw) || origin;
    const method = ($form.attr("method") || "GET").toUpperCase();
    const inputs: string[] = [];
    $form.find("input[name], select[name], textarea[name]").each((_, inputEl) => {
      const name = $(inputEl).attr("name");
      if (name) inputs.push(name);
    });
    forms.push({ action: resolvedAction, method, inputs });
  });
  const inlineScripts: string[] = [];
  try {
    const { document } = parseHTML(bodyFull);
    const nodeList = document.querySelectorAll("script:not([src])");
    for (const node of Array.from(nodeList) as { textContent?: string | null }[]) {
      const text = node.textContent?.trim();
      if (text && text.length > 0) inlineScripts.push(text);
    }
  } catch {
    // ignore
  }

  return {
    result: {
      origin,
      internalLinks: Array.from(internalLinks).slice(0, MAX_INTERNAL_LINKS),
      scripts: Array.from(scripts),
      forms,
      inlineScripts,
    },
    status: res.status,
    cloudflare: null,
  };
}
