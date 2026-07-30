import * as cheerio from "cheerio";
import type { QcIssue, QcPerfMetrics, QcPerfResult } from "./qc-types";

const PSI_ENDPOINT = "https://www.googleapis.com/pagespeedonline/v5/runPagespeed";
const PSI_TIMEOUT_MS = 25_000;
const MODERN_IMAGE_EXT = /\.(webp|avif)(\?|$)/i;

interface PsiNode {
  nodeLabel?: string;
  snippet?: string;
  selector?: string;
}
interface PsiAuditDetailItem {
  node?: PsiNode;
  items?: PsiAuditDetailItem[];
}
interface PsiAudit {
  score?: number | null;
  numericValue?: number;
  displayValue?: string;
  details?: { items?: PsiAuditDetailItem[] };
}
interface PsiResponse {
  lighthouseResult?: {
    categories?: { performance?: { score?: number } };
    audits?: Record<string, PsiAudit>;
  };
}

/**
 * Ambil elemen penyebab LCP dari audit "largest-contentful-paint-element" —
 * PSI menaruh node-nya di details.items[0].node (versi lama) ATAU
 * ternested di details.items[0].items[].node (versi dengan breakdown
 * subItems), jadi dicoba dua-duanya. Dikombinasikan dengan audit
 * "lcp-lazy-loaded" untuk tahu apakah elemen LCP-nya kena
 * loading="lazy" (kontraproduktif — elemen paling penting harusnya
 * di-load duluan, bukan ditunda).
 */
function extractLcpElement(audits: Record<string, PsiAudit>): QcPerfMetrics["lcpElement"] {
  const lcpElAudit = audits["largest-contentful-paint-element"];
  const firstItem = lcpElAudit?.details?.items?.[0];
  const node = firstItem?.node ?? firstItem?.items?.[0]?.node;
  if (!node) return null;

  const lazyAudit = audits["lcp-lazy-loaded"];
  // Audit "lcp-lazy-loaded" score 1 = pass (TIDAK lazy-loaded, bagus),
  // score 0 = fail (KENA lazy-loaded, ini yang bikin LCP lambat).
  const isLazyLoaded = lazyAudit && typeof lazyAudit.score === "number" ? lazyAudit.score < 1 : null;

  return {
    snippet: node.snippet ?? node.nodeLabel ?? null,
    selector: node.selector ?? null,
    isLazyLoaded,
  };
}

function withTimeout(ms: number): { signal: AbortSignal; cancel: () => void } {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), ms);
  return { signal: controller.signal, cancel: () => clearTimeout(t) };
}

async function fetchPageSpeedInsights(
  targetUrl: string
): Promise<{ data: PsiResponse; reason?: undefined } | { data: null; reason: string }> {
  const apiKey = process.env.GOOGLE_PAGESPEED_API_KEY;
  const url = new URL(PSI_ENDPOINT);
  url.searchParams.set("url", targetUrl);
  url.searchParams.set("strategy", "mobile");
  url.searchParams.set("category", "performance");
  if (apiKey) url.searchParams.set("key", apiKey);

  const { signal, cancel } = withTimeout(PSI_TIMEOUT_MS);
  try {
    const res = await fetch(url.toString(), { signal });
    cancel();

    if (!res.ok) {
      // Coba baca body error dari Google supaya alasan sebenarnya kelihatan
      // (misal: "API key not valid", "quota exceeded", key dibatasi
      // referrer, PSI API belum di-enable di project GCP, dst) — bukan
      // cuma "gagal" tanpa penjelasan.
      let detail = "";
      try {
        const body = await res.json();
        detail = body?.error?.message ?? "";
      } catch {
        // body bukan JSON / kosong, abaikan
      }
      return {
        data: null,
        reason: `HTTP ${res.status}${detail ? ` — ${detail}` : ""}`,
      };
    }

    const json = (await res.json()) as PsiResponse;
    if (!json.lighthouseResult) {
      return { data: null, reason: "Response PSI tidak berisi lighthouseResult (kemungkinan URL tidak bisa di-crawl Google)." };
    }
    return { data: json };
  } catch (err) {
    cancel();
    const isAbort = err instanceof Error && err.name === "AbortError";
    return {
      data: null,
      reason: isAbort
        ? `Timeout setelah ${PSI_TIMEOUT_MS / 1000}s menunggu PageSpeed Insights.`
        : `Gagal fetch PSI: ${err instanceof Error ? err.message : "unknown error"}`,
    };
  }
}

function scoreFromPsi(psi: PsiResponse): { metrics: QcPerfMetrics; issues: QcIssue[]; score: number } {
  const issues: QcIssue[] = [];
  const audits = psi.lighthouseResult?.audits ?? {};
  const perfScoreRaw = psi.lighthouseResult?.categories?.performance?.score;
  const score = typeof perfScoreRaw === "number" ? Math.round(perfScoreRaw * 100) : 0;

  const lcpAudit = audits["largest-contentful-paint"];
  const clsAudit = audits["cumulative-layout-shift"];
  const fcpAudit = audits["first-contentful-paint"];
  const tbtAudit = audits["total-blocking-time"];
  const sizeAudit = audits["total-byte-weight"];
  const modernImgAudit = audits["modern-image-formats"];
  const cacheAudit = audits["uses-long-cache-ttl"];
  const lazyAudit = audits["offscreen-images"];

  const lcpElement = extractLcpElement(audits);

  if (lcpAudit && (lcpAudit.score ?? 1) < 0.9) {
    const elementNote = lcpElement?.selector ? ` Elemen: \`${lcpElement.selector}\`.` : "";
    issues.push({
      level: (lcpAudit.score ?? 1) < 0.5 ? "critical" : "warning",
      msg: `LCP lambat: ${lcpAudit.displayValue ?? "N/A"} (target < 2.5s).${elementNote}`,
    });
  }
  if (lcpElement?.isLazyLoaded) {
    issues.push({
      level: "warning",
      msg: "Elemen LCP kena loading=\"lazy\" — ini kontraproduktif, elemen paling penting di layar harus di-load duluan (fetchpriority=\"high\"), bukan ditunda.",
    });
  }
  if (clsAudit && (clsAudit.score ?? 1) < 0.9) {
    issues.push({
      level: (clsAudit.score ?? 1) < 0.5 ? "critical" : "warning",
      msg: `CLS tinggi: ${clsAudit.displayValue ?? "N/A"} (target < 0.1).`,
    });
  }
  if (tbtAudit && (tbtAudit.score ?? 1) < 0.9) {
    issues.push({
      level: "warning",
      msg: `Total Blocking Time tinggi: ${tbtAudit.displayValue ?? "N/A"}.`,
    });
  }
  if (sizeAudit?.numericValue && sizeAudit.numericValue > 500 * 1024) {
    issues.push({
      level: "warning",
      msg: `Total payload halaman ${(sizeAudit.numericValue / 1024).toFixed(0)}KB (di atas 500KB).`,
    });
  }
  if (modernImgAudit && (modernImgAudit.score ?? 1) < 0.9) {
    issues.push({
      level: "warning",
      msg: "Sebagian gambar belum pakai format modern (WebP/AVIF).",
    });
  }
  if (cacheAudit && (cacheAudit.score ?? 1) < 0.9) {
    issues.push({
      level: "info",
      msg: "Sebagian asset belum pakai cache header jangka panjang (Cache-Control).",
    });
  }
  if (lazyAudit && (lazyAudit.score ?? 1) < 0.9) {
    issues.push({
      level: "info",
      msg: "Ada gambar offscreen yang belum di-lazy-load.",
    });
  }

  const metrics: QcPerfMetrics = {
    lcp: lcpAudit?.displayValue ?? null,
    cls: clsAudit?.displayValue ?? null,
    fcp: fcpAudit?.displayValue ?? null,
    tbt: tbtAudit?.displayValue ?? null,
    sizeBytes: sizeAudit?.numericValue ?? null,
    modernImageFormat: modernImgAudit ? (modernImgAudit.score ?? 1) >= 0.9 : null,
    cacheHeaders: cacheAudit ? (cacheAudit.score ?? 1) >= 0.9 : null,
    lazyLoading: lazyAudit ? (lazyAudit.score ?? 1) >= 0.9 : null,
    source: "pagespeed",
    lcpElement,
  };

  return { metrics, issues, score };
}

/**
 * Fallback manual kalau PageSpeed Insights API gagal/limit: cek content-length
 * (>500KB dianggap berat) dan keberadaan loading="lazy" / format gambar modern
 * langsung dari HTML yang sudah di-fetch crawler (tanpa request tambahan).
 */
function manualFallback(html: string, contentLength: number | null, reason: string): QcPerfResult {
  const $ = cheerio.load(html);
  const issues: QcIssue[] = [];
  let score = 100;

  const imgs = $("img");
  const totalImgs = imgs.length;
  let modernCount = 0;
  let lazyCount = 0;
  imgs.each((_, el) => {
    const src = $(el).attr("src") || $(el).attr("srcset") || "";
    if (MODERN_IMAGE_EXT.test(src)) modernCount++;
    if ($(el).attr("loading") === "lazy") lazyCount++;
  });

  const modernImageFormat = totalImgs === 0 ? null : modernCount === totalImgs;
  const lazyLoading = totalImgs === 0 ? null : lazyCount > 0;

  if (contentLength !== null && contentLength > 500 * 1024) {
    issues.push({
      level: "warning",
      msg: `Ukuran HTML halaman ${(contentLength / 1024).toFixed(0)}KB (di atas 500KB).`,
    });
    score -= 20;
  }
  if (totalImgs > 0 && modernCount < totalImgs) {
    issues.push({
      level: "warning",
      msg: `${totalImgs - modernCount}/${totalImgs} gambar belum pakai format WebP/AVIF (deteksi dari ekstensi src).`,
    });
    score -= 15;
  }
  if (totalImgs > 3 && lazyCount === 0) {
    issues.push({
      level: "warning",
      msg: `Tidak ada gambar dengan loading="lazy" dari ${totalImgs} gambar terdeteksi.`,
    });
    score -= 15;
  }

  issues.push({
    level: "info",
    msg: `PageSpeed Insights API gagal dipakai (${reason}) — skor dihitung dari cek manual (content-length & atribut HTML), bukan Lighthouse penuh.`,
  });

  score = Math.max(0, Math.min(100, Math.round(score)));

  return {
    score,
    issues,
    metrics: {
      lcp: null,
      cls: null,
      fcp: null,
      tbt: null,
      sizeBytes: contentLength,
      modernImageFormat,
      cacheHeaders: null,
      lazyLoading,
      source: "fallback",
      lcpElement: null,
    },
  };
}

export async function analyzePerformance(
  targetUrl: string,
  homepageHtml: string,
  homepageContentLength: number | null,
  onLog?: (msg: string) => void
): Promise<QcPerfResult> {
  const psi = await fetchPageSpeedInsights(targetUrl);

  if (!psi.data) {
    onLog?.(`PageSpeed Insights gagal — ${psi.reason}. Fallback ke cek manual.`);
    return manualFallback(homepageHtml, homepageContentLength, psi.reason);
  }

  const { metrics, issues, score } = scoreFromPsi(psi.data);
  return { score, issues, metrics };
}