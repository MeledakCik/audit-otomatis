import * as cheerio from "cheerio";
import { chromeHeaders } from "@/lib/crawler";
import { RequestBudget } from "@/lib/rate-limit";

export interface MapFormInfo {
  action: string;
  method: string;
  inputs: string[];
}

export interface MapCrawledPage {
  url: string;
  depth: number;
  parentUrl: string | null;
  scripts: string[];
  externalLinks: string[];
  forms: MapFormInfo[];
}

function resolveUrl(base: string, href: string): string | null {
  try {
    return new URL(href, base).toString();
  } catch {
    return null;
  }
}

function parsePage(pageUrl: string, hostname: string, html: string) {
  const $ = cheerio.load(html);

  const internalLinks = new Set<string>();
  const externalLinks = new Set<string>();
  $("a[href]").each((_, el) => {
    const href = $(el).attr("href");
    if (!href || href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("tel:") || href.startsWith("javascript:")) return;
    const resolved = resolveUrl(pageUrl, href);
    if (!resolved) return;
    try {
      const u = new URL(resolved);
      if (u.protocol !== "http:" && u.protocol !== "https:") return;
      u.hash = "";
      if (u.hostname === hostname) internalLinks.add(u.toString());
      else externalLinks.add(u.hostname);
    } catch {
      // ignore
    }
  });

  const scripts = new Set<string>();
  $("script[src]").each((_, el) => {
    const src = $(el).attr("src");
    if (!src) return;
    const resolved = resolveUrl(pageUrl, src);
    if (!resolved) return;
    try {
      const u = new URL(resolved);
      if (u.hostname === hostname) scripts.add(u.toString());
    } catch {
      // ignore
    }
  });

  const forms: MapFormInfo[] = [];
  $("form").each((_, el) => {
    const $form = $(el);
    const actionRaw = $form.attr("action") || pageUrl;
    const resolvedAction = resolveUrl(pageUrl, actionRaw) || pageUrl;
    const method = ($form.attr("method") || "GET").toUpperCase();
    const inputs: string[] = [];
    $form.find("input[name], select[name], textarea[name]").each((_, inputEl) => {
      const name = $(inputEl).attr("name");
      if (name) inputs.push(name);
    });
    forms.push({ action: resolvedAction, method, inputs });
  });

  return {
    internalLinks: Array.from(internalLinks),
    externalLinks: Array.from(externalLinks),
    scripts: Array.from(scripts),
    forms,
  };
}

/**
 * BFS crawl same-origin, GET-only, dengan pelacakan parent (discoverer
 * pertama) supaya graph yang dihasilkan berbentuk pohon yang bersih — bukan
 * mesh penuh — dan gampang divisualisasikan di React Flow.
 */
export async function crawlForAttackMap(
  origin: string,
  hostname: string,
  budget: RequestBudget,
  maxDepth: number,
  maxPages: number
): Promise<MapCrawledPage[]> {
  const visited = new Set<string>();
  const queue: { url: string; depth: number; parentUrl: string | null }[] = [
    { url: origin, depth: 0, parentUrl: null },
  ];
  const pages: MapCrawledPage[] = [];

  while (queue.length > 0 && visited.size < maxPages) {
    const next = queue.shift()!;
    if (visited.has(next.url) || next.depth > maxDepth) continue;
    visited.add(next.url);

    if (!budget.canSpend()) break;

    const fetched = await budget.spend(async () => {
      try {
        const res = await fetch(next.url, { method: "GET", headers: chromeHeaders(), redirect: "follow" });
        const body = await res.text();
        return { status: res.status, body };
      } catch {
        return { status: 0, body: "" };
      }
    });

    if (!fetched || fetched.status === 0 || fetched.status >= 400) continue;

    const parsed = parsePage(next.url, hostname, fetched.body);
    pages.push({
      url: next.url,
      depth: next.depth,
      parentUrl: next.parentUrl,
      scripts: parsed.scripts,
      externalLinks: parsed.externalLinks,
      forms: parsed.forms,
    });

    if (next.depth < maxDepth) {
      for (const link of parsed.internalLinks) {
        if (!visited.has(link) && visited.size + queue.length < maxPages) {
          queue.push({ url: link, depth: next.depth + 1, parentUrl: next.url });
        }
      }
    }
  }

  return pages;
}
