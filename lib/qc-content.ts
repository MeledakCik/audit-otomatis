import * as cheerio from "cheerio";
import { chromeHeaders } from "./crawler";
import type { RequestBudget } from "./rate-limit";
import type { QcContentResult, QcIssue } from "./qc-types";

const HEAD_CONCURRENCY = 10;
const HEAD_TIMEOUT_MS = 8000;
const SKIP_INPUT_TYPES = new Set(["hidden", "submit", "button", "reset", "image"]);

function chunk<T>(arr: T[], size: number): T[][] {
  const out: T[][] = [];
  for (let i = 0; i < arr.length; i += size) out.push(arr.slice(i, i + size));
  return out;
}

async function headCheck(url: string): Promise<{ url: string; ok: boolean; status: number }> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), HEAD_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "HEAD",
      headers: chromeHeaders(),
      redirect: "follow",
      signal: controller.signal,
    });
    clearTimeout(t);
    // Sebagian server tidak dukung HEAD (405/501) — anggap bukan broken,
    // cuma metode tidak didukung, jangan false-positive.
    if (res.status === 405 || res.status === 501) {
      return { url, ok: true, status: res.status };
    }
    return { url, ok: res.status < 400, status: res.status };
  } catch {
    clearTimeout(t);
    return { url, ok: false, status: 0 };
  }
}

/**
 * QC Content/Link — input link internal dari crawler yang sudah ada di
 * Page 1 (lib/crawler.ts / lib/site-crawler.ts). Cek 404 via HEAD batch
 * (10 concurrent), lalu a11y dasar dari HTML: input form tanpa <label>,
 * dan tag <a> tanpa href / href kosong.
 */
export async function analyzeContent(
  html: string,
  internalLinks: string[],
  budget: RequestBudget,
  onLog: (msg: string) => void
): Promise<QcContentResult> {
  const issues: QcIssue[] = [];
  const brokenLinks: string[] = [];

  // --- Broken link check (HEAD, batch 10 concurrent, tunduk RequestBudget) ---
  const candidateLinks = internalLinks.slice(0, Math.max(0, budget.remaining));
  let linksChecked = 0;

  for (const batch of chunk(candidateLinks, HEAD_CONCURRENCY)) {
    if (!budget.canSpend(batch.length)) {
      const affordable = budget.remaining;
      if (affordable <= 0) break;
      batch.length = affordable;
    }
    const results = await Promise.all(
      batch.map((url) => budget.spend(() => headCheck(url)))
    );
    for (const r of results) {
      if (!r) continue;
      linksChecked++;
      if (!r.ok) brokenLinks.push(`${r.url} (HTTP ${r.status || "gagal fetch"})`);
    }
    onLog(`Cek link: ${linksChecked}/${candidateLinks.length} — ${brokenLinks.length} broken sejauh ini.`);
  }

  // Catatan: ringkasan broken link ditaruh di field `brokenLinks` (bukan
  // a11yIssues), supaya konsisten dengan bentuk output QC Content di spec —
  // a11yIssues khusus isu aksesibilitas (label form, anchor kosong).

  // --- A11y: form input tanpa <label> ---
  const $ = cheerio.load(html);
  let formsChecked = 0;
  let inputsWithoutLabel = 0;

  $("form").each((_, formEl) => {
    formsChecked++;
    const $form = $(formEl);
    $form.find("input, select, textarea").each((_, inputEl) => {
      const $input = $(inputEl);
      const type = ($input.attr("type") || "text").toLowerCase();
      if (SKIP_INPUT_TYPES.has(type)) return;

      const id = $input.attr("id");
      const ariaLabel = $input.attr("aria-label");
      const ariaLabelledBy = $input.attr("aria-labelledby");
      const hasForLabel = id ? $(`label[for="${id}"]`).length > 0 : false;
      const isWrappedInLabel = $input.closest("label").length > 0;

      const hasAccessibleLabel = Boolean(
        hasForLabel || isWrappedInLabel || ariaLabel || ariaLabelledBy
      );

      if (!hasAccessibleLabel) inputsWithoutLabel++;
    });
  });

  if (inputsWithoutLabel > 0) {
    issues.push({
      level: "warning",
      msg: `${inputsWithoutLabel} input form tanpa <label> (atau aria-label) yang terasosiasi.`,
    });
  }

  // --- A11y: <a> tanpa href atau href kosong/"#" ---
  const anchors = $("a");
  const anchorsChecked = anchors.length;
  let emptyAnchors = 0;
  anchors.each((_, el) => {
    const href = $(el).attr("href");
    if (href === undefined || href.trim() === "" || href.trim() === "#") emptyAnchors++;
  });

  if (emptyAnchors > 0) {
    issues.push({
      level: "info",
      msg: `${emptyAnchors} tag <a> tanpa href atau href kosong/"#" (bukan tautan yang berfungsi).`,
    });
  }

  // --- Scoring ---
  let score = 100;
  const brokenRatio = linksChecked > 0 ? brokenLinks.length / linksChecked : 0;
  score -= Math.round(brokenRatio * 50); // sampai -50 kalau semua link broken
  score -= Math.min(20, inputsWithoutLabel * 4);
  score -= Math.min(15, emptyAnchors * 2);
  score = Math.max(0, Math.min(100, score));

  return {
    score,
    brokenLinks,
    a11yIssues: issues,
    checked: { linksChecked, formsChecked, anchorsChecked },
  };
}
