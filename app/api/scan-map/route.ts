import { validateDomainInput } from "@/lib/validate-domain";
import { chromeHeaders } from "@/lib/crawler";
import { RequestBudget } from "@/lib/rate-limit";
import { crawlForAttackMap } from "@/lib/attack-map/crawl";
import { extractApiCallsFromJs } from "@/lib/attack-map/extract-endpoints";
import { buildAttackMapGraph, type JsFinding } from "@/lib/attack-map/build-graph";

const MAX_DEPTH = 2;
const MAX_PAGES = 18;
const MAX_JS_FILES = 15;
const MAX_JS_BYTES = 3 * 1024 * 1024;
const FETCH_TIMEOUT_MS = 10_000;
// budget total: halaman (MAX_PAGES) + file JS (MAX_JS_FILES) + sedikit slack
const BUDGET_MAX = MAX_PAGES + MAX_JS_FILES + 5;

interface ScanBody {
  domain?: string;
}

function withTimeout(url: string, init: RequestInit, ms: number): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return fetch(url, { ...init, signal: controller.signal }).finally(() => clearTimeout(timer));
}

export async function POST(req: Request) {
  let body: ScanBody;
  try {
    body = (await req.json()) as ScanBody;
  } catch {
    return Response.json({ ok: false, error: "Body request tidak valid (harus JSON)." }, { status: 400 });
  }

  const raw = (body.domain ?? "").toString();
  const validation = validateDomainInput(raw);
  if (!validation.ok || !validation.normalizedUrl || !validation.hostname) {
    return Response.json({ ok: false, error: validation.error ?? "Domain tidak valid." }, { status: 400 });
  }

  const origin = validation.normalizedUrl;
  const hostname = validation.hostname;
  const budget = new RequestBudget(BUDGET_MAX, 250);

  let pages;
  try {
    pages = await crawlForAttackMap(origin, hostname, budget, MAX_DEPTH, MAX_PAGES);
  } catch {
    return Response.json(
      { ok: false, error: "Gagal melakukan crawl. Pastikan domain aktif dan dapat diakses publik." },
      { status: 502 }
    );
  }

  if (pages.length === 0) {
    return Response.json(
      { ok: false, error: "Tidak ada halaman yang berhasil di-crawl (domain mungkin down atau memblokir request)." },
      { status: 502 }
    );
  }

  // Kumpulkan JS same-origin unik dari semua halaman, fetch isi & extract API call-nya.
  const uniqueScripts = Array.from(new Set(pages.flatMap((p) => p.scripts))).slice(0, MAX_JS_FILES);
  const jsFindings: JsFinding[] = [];

  for (const scriptUrl of uniqueScripts) {
    if (!budget.canSpend()) break;
    const text = await budget.spend(async () => {
      try {
        const res = await withTimeout(scriptUrl, { method: "GET", headers: chromeHeaders(origin) }, FETCH_TIMEOUT_MS);
        if (!res.ok) return null;
        const contentLength = Number(res.headers.get("content-length") ?? "0");
        if (contentLength && contentLength > MAX_JS_BYTES) return null;
        const body = await res.text();
        return body.length > MAX_JS_BYTES ? body.slice(0, MAX_JS_BYTES) : body;
      } catch {
        return null;
      }
    });
    if (!text) continue;
    const apiCalls = extractApiCallsFromJs(text);
    if (apiCalls.length > 0) jsFindings.push({ assetUrl: scriptUrl, apiCalls });
  }

  const report = buildAttackMapGraph({ origin, hostname, pages, jsFindings, maxPages: MAX_PAGES });

  return Response.json({ ok: true, report });
}
