import * as cheerio from "cheerio";
import { chromeHeaders, detectCloudflareChallenge, MAX_INTERNAL_LINKS } from "./crawler";
import { RequestBudget } from "./rate-limit";
import { analyzeSeo } from "./qc-seo";
import { analyzePerformance } from "./qc-performance";
import { analyzeContent } from "./qc-content";
import {
  bumpQcRequestCount,
  getQc,
  logQc,
  markQcDone,
  markQcError,
  setModuleResult,
  setOverallScore,
  setQcStatus,
} from "./qc-store";
import type { QcModulesSelection } from "./qc-types";

const CF_MESSAGE = "Domain dilindungi Cloudflare Challenge — homepage tidak bisa di-crawl untuk QC.";

interface HomepageFetch {
  html: string;
  contentLength: number | null;
  internalLinks: string[];
  cloudflare: boolean;
  cloudflareReason?: string;
}

/**
 * Satu fetch homepage saja (dipakai bersama oleh SEO/Perf/Content), reuse
 * header & deteksi Cloudflare dari lib/crawler.ts supaya konsisten dengan
 * Page 1, tanpa fetch berulang-ulang ke origin yang sama.
 */
async function fetchHomepageOnce(origin: string): Promise<HomepageFetch> {
  const res = await fetch(origin, { method: "GET", headers: chromeHeaders(), redirect: "follow" });
  const html = await res.text();
  const bodySnippet = html.slice(0, 2000);

  const cf = detectCloudflareChallenge(res.status, res.headers, bodySnippet);
  if (cf) {
    return { html: "", contentLength: null, internalLinks: [], cloudflare: true, cloudflareReason: cf.reason };
  }

  const headerLen = res.headers.get("content-length");
  const contentLength = headerLen ? parseInt(headerLen, 10) : new TextEncoder().encode(html).length;

  const $ = cheerio.load(html);
  const originUrl = new URL(origin);
  const internalLinks = new Set<string>();
  $("a[href]").each((_, el) => {
    if (internalLinks.size >= MAX_INTERNAL_LINKS) return;
    const href = $(el).attr("href");
    if (!href || href.startsWith("#") || href.startsWith("mailto:") || href.startsWith("tel:")) return;
    try {
      const u = new URL(href, origin);
      if (u.hostname === originUrl.hostname) {
        u.hash = "";
        internalLinks.add(u.toString());
      }
    } catch {
      // ignore
    }
  });

  return {
    html,
    contentLength: Number.isFinite(contentLength) ? contentLength : null,
    internalLinks: Array.from(internalLinks),
    cloudflare: false,
  };
}

export async function runQc(qcId: string, origin: string, modules: QcModulesSelection) {
  const budget = new RequestBudget(100, 300);

  try {
    await setQcStatus(qcId, "crawling");
    await logQc(qcId, `Mengambil homepage ${origin} untuk analisis QC...`);

    const home = await fetchHomepageOnce(origin);
    await bumpQcRequestCount(qcId, 1);

    if (home.cloudflare) {
      await logQc(qcId, `Cloudflare challenge terdeteksi: ${home.cloudflareReason}`);
      await markQcError(qcId, CF_MESSAGE);
      return;
    }

    await logQc(qcId, `Homepage berhasil diambil — ${home.internalLinks.length} link internal ditemukan.`);

    const tasks: Promise<void>[] = [];

    if (modules.seo) {
      tasks.push(
        (async () => {
          await setQcStatus(qcId, "running_seo");
          await logQc(qcId, "Menjalankan QC SEO Otomatis...");
          const result = analyzeSeo(home.html, origin);
          await setModuleResult(qcId, "seo", result);
          await logQc(qcId, `QC SEO selesai — skor ${result.score}/100, ${result.issues.length} issue.`);
        })()
      );
    }

    if (modules.perf) {
      tasks.push(
        (async () => {
          await setQcStatus(qcId, "running_perf");
          await logQc(qcId, "Menjalankan QC Performance (PageSpeed Insights)...");
          const result = await analyzePerformance(origin, home.html, home.contentLength);
          await setModuleResult(qcId, "perf", result);
          await logQc(
            qcId,
            `QC Performance selesai — skor ${result.score}/100 (sumber: ${result.metrics.source}).`
          );
        })()
      );
    }

    if (modules.content) {
      tasks.push(
        (async () => {
          await setQcStatus(qcId, "running_content");
          await logQc(qcId, "Menjalankan QC Content/Link (cek broken link & a11y)...");
          const result = await analyzeContent(home.html, home.internalLinks, budget, (msg) =>
            logQc(qcId, msg)
          );
          await bumpQcRequestCount(qcId, result.checked.linksChecked);
          await setModuleResult(qcId, "content", result);
          await logQc(
            qcId,
            `QC Content selesai — skor ${result.score}/100, ${result.brokenLinks.length} broken link.`
          );
        })()
      );
    }

    if (tasks.length === 0) {
      await logQc(qcId, "Tidak ada modul QC yang dipilih.");
    }

    await Promise.all(tasks);

    // --- Overall score: rata-rata dari modul yang dijalankan ---
    const finalState = await getQc(qcId);
    const scores: number[] = [];
    if (finalState?.result.seo) scores.push(finalState.result.seo.score);
    if (finalState?.result.perf) scores.push(finalState.result.perf.score);
    if (finalState?.result.content) scores.push(finalState.result.content.score);
    const overall = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
    await setOverallScore(qcId, overall);

    await logQc(qcId, `QC selesai — skor keseluruhan ${overall}/100.`);
    await setQcStatus(qcId, "done");
    await markQcDone(qcId);
  } catch (err) {
    await markQcError(qcId, err instanceof Error ? err.message : "Error tidak diketahui saat QC.");
  }
}
