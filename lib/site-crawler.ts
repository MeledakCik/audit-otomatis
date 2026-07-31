import * as cheerio from "cheerio";
import { parseHTML } from "linkedom";
import { chromeHeaders, detectCloudflareChallenge, type CloudflareChallenge } from "./crawler";
import type { CrawledPage, FormInfo, GraphData, GraphNode, GraphEdge } from "./types";
import type { RequestBudget } from "./rate-limit";

export const MAX_CRAWL_URLS = 50;
export const DEFAULT_MAX_DEPTH = 3; // level 0 (homepage) .. level 3
export const MAX_STORED_HTML_CHARS = 20_000; // batas HTML yang disimpan per halaman ke Redis (preview di UI cuma perlu ~2000 char)

interface PageParseResult {
  internalLinks: string[];
  scripts: string[];
  forms: FormInfo[];
  inlineScripts: string[];
}

function resolveUrl(base: string, href: string): string | null {
  try {
    return new URL(href, base).toString();
  } catch {
    return null;
  }
}

function parsePage(origin: string, pageUrl: string, html: string): PageParseResult {
  const $ = cheerio.load(html);
  const originUrl = new URL(origin);

  const internalLinks: string[] = [];
  $("a[href]").each((_, el) => {
    const href = $(el).attr("href");
    if (!href || href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("tel:")) return;
    const resolved = resolveUrl(pageUrl, href);
    if (!resolved) return;
    try {
      const u = new URL(resolved);
      if (u.hostname !== originUrl.hostname) return;
      u.hash = "";
      internalLinks.push(u.toString());
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
      scripts.add(new URL(resolved).toString());
    } catch {
      // ignore
    }
  });

  const forms: FormInfo[] = [];
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

  const inlineScripts: string[] = [];
  try {
    const { document } = parseHTML(html);
    const nodeList = document.querySelectorAll("script:not([src])");
    for (const node of Array.from(nodeList) as { textContent?: string | null }[]) {
      const text = node.textContent?.trim();
      if (text && text.length > 0) inlineScripts.push(text);
    }
  } catch {
    // linkedom gagal parse — bukan fatal
  }

  return { internalLinks, scripts: Array.from(scripts), forms, inlineScripts };
}

/**
 * Node id helper — dipakai konsisten di sini dan di scan-runner saat
 * menambahkan endpoint node hasil js-analyzer, supaya id tidak bentrok
 * antar tipe node (page vs js vs endpoint) meski string URL-nya sama.
 */
export function pageNodeId(url: string): string {
  return `page:${url}`;
}
export function jsNodeId(url: string): string {
  return `js:${url}`;
}
export function endpointNodeId(url: string): string {
  return `endpoint:${url}`;
}

export interface SiteCrawlResult {
  pages: CrawledPage[];
  allInternalLinks: string[];
  allScripts: string[];
  allForms: FormInfo[];
  allInlineScripts: { pageUrl: string; scripts: string[] }[];
  graph: GraphData;
  cloudflare: CloudflareChallenge | null;
  visitedCount: number;
}

/**
 * Crawl same-origin BFS mulai dari homepage, sampai maxDepth level atau
 * maxUrls halaman (mana yang lebih dulu tercapai). Setiap halaman baru
 * dipakai budget.spend() satu request GET — tetap tunduk pada RequestBudget
 * yang sama dengan pengujian pasif lainnya, jadi tidak menambah total
 * request di luar batas 100/scan yang sudah ada.
 */
export async function crawlSite(
  origin: string,
  budget: RequestBudget,
  onLog: (msg: string) => void,
  maxDepth = DEFAULT_MAX_DEPTH,
  maxUrls = MAX_CRAWL_URLS
): Promise<SiteCrawlResult> {
  const visited = new Set<string>();
  const queue: { url: string; depth: number }[] = [{ url: origin, depth: 0 }];
  const pages: CrawledPage[] = [];
  const allInternalLinksSet = new Set<string>();
  const allScriptsSet = new Set<string>();
  const allForms: FormInfo[] = [];
  const allInlineScripts: { pageUrl: string; scripts: string[] }[] = [];

  const nodes: GraphNode[] = [];
  const edges: GraphEdge[] = [];
  const seenNodeIds = new Set<string>();
  function addNode(node: GraphNode) {
    if (seenNodeIds.has(node.id)) return;
    seenNodeIds.add(node.id);
    nodes.push(node);
  }
  function addEdge(from: string, to: string) {
    edges.push({ from, to });
  }

  let cloudflare: CloudflareChallenge | null = null;

  while (queue.length > 0 && visited.size < maxUrls) {
    const next = queue.shift()!;
    if (visited.has(next.url) || next.depth > maxDepth) continue;
    visited.add(next.url);

    if (!budget.canSpend()) {
      onLog(`Request budget habis, hentikan crawl di ${visited.size} halaman.`);
      break;
    }

    const fetched = await budget.spend(async () => {
      try {
        const res = await fetch(next.url, { method: "GET", headers: chromeHeaders(), redirect: "follow" });
        const body = await res.text();
        return { status: res.status, headers: res.headers, body };
      } catch (err) {
        return { status: 0, headers: new Headers(), body: "", error: (err as Error).message };
      }
    });

    if (!fetched) break; // budget habis di tengah spend()
    if (fetched.status === 0) {
      onLog(`Gagal fetch ${next.url}${fetched.error ? `: ${fetched.error}` : ""}`);
      continue;
    }

    const cf = detectCloudflareChallenge(fetched.status, fetched.headers, fetched.body.slice(0, 2000));
    if (cf) {
      cloudflare = cf;
      onLog(`Cloudflare challenge terdeteksi saat crawl ${next.url}: ${cf.reason}`);
      break;
    }

    const parsed = parsePage(origin, next.url, fetched.body);

    const headersObj: Record<string, string> = {};
    fetched.headers.forEach((value, key) => {
      headersObj[key] = value;
    });
    const contentType = headersObj["content-type"] ?? "";
    const size = Buffer.byteLength(fetched.body, "utf8");

    pages.push({
      url: next.url,
      depth: next.depth,
      scripts: parsed.scripts,
      status: fetched.status,
      headers: headersObj,
      contentType,
      size,
      html: fetched.body.slice(0, MAX_STORED_HTML_CHARS),
    });
    onLog(
      `[depth ${next.depth}] ${next.url} — ${parsed.internalLinks.length} link, ${parsed.scripts.length} JS, ${parsed.forms.length} form`
    );

    addNode({ id: pageNodeId(next.url), type: "page", label: next.url, depth: next.depth });
    for (const script of parsed.scripts) {
      allScriptsSet.add(script);
      addNode({ id: jsNodeId(script), type: "js", label: new URL(script).pathname });
      addEdge(pageNodeId(next.url), jsNodeId(script));
    }
    for (const link of parsed.internalLinks) allInternalLinksSet.add(link);
    for (const form of parsed.forms) allForms.push(form);
    if (parsed.inlineScripts.length > 0) {
      allInlineScripts.push({ pageUrl: next.url, scripts: parsed.inlineScripts });
    }

    if (next.depth < maxDepth) {
      for (const link of parsed.internalLinks) {
        if (!visited.has(link) && visited.size + queue.length < maxUrls) {
          queue.push({ url: link, depth: next.depth + 1 });
        }
      }
    }
  }

  return {
    pages,
    allInternalLinks: Array.from(allInternalLinksSet).slice(0, maxUrls),
    allScripts: Array.from(allScriptsSet),
    allForms,
    allInlineScripts,
    graph: { nodes, edges },
    cloudflare,
    visitedCount: visited.size,
  };
}
