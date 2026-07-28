import * as cheerio from "cheerio";
import { parseHTML } from "linkedom";
import type { CrawlResult, FormInfo } from "./types";

const CHROME_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36";

export const MAX_INTERNAL_LINKS = 50;

export function chromeHeaders(referer?: string): HeadersInit {
  return {
    "User-Agent": CHROME_UA,
    Accept:
      "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Sec-Fetch-Site": referer ? "same-origin" : "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Sec-Ch-Ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
    "Sec-Ch-Ua-Mobile": "?0",
    "Sec-Ch-Ua-Platform": '"Windows"',
    ...(referer ? { Referer: referer } : {}),
  };
}

export interface CloudflareChallenge {
  challenged: true;
  status: number;
  reason: string;
}

export function detectCloudflareChallenge(
  status: number,
  headers: Headers,
  bodySnippet: string
): CloudflareChallenge | null {
  const cfMitigated = headers.get("cf-mitigated");
  const bodyHasChallenge = /Attention Required[!]?\s*\|\s*Cloudflare/i.test(bodySnippet);
  const isChallengeStatus = status === 403 && cfMitigated === "challenge";

  if (bodyHasChallenge || isChallengeStatus) {
    return {
      challenged: true,
      status,
      reason: bodyHasChallenge
        ? "Body mengandung halaman Cloudflare 'Attention Required'"
        : "Header cf-mitigated: challenge terdeteksi pada status 403",
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

export async function crawlHomepage(origin: string): Promise<{
  result: CrawlResult;
  status: number;
  cloudflare: CloudflareChallenge | null;
}> {
  const res = await fetch(origin, {
    method: "GET",
    headers: chromeHeaders(),
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
