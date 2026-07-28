import * as cheerio from "cheerio";
import type { QcIssue, QcSeoResult } from "./qc-types";

const OG_REQUIRED = ["og:title", "og:description", "og:image", "og:url"];

/**
 * QC SEO Otomatis — parsing HTML string dengan cheerio, cek elemen SEO
 * standar. Setiap issue punya bobot penalti sendiri terhadap score (mulai
 * dari 100, dikurangi per issue, minimum 0).
 */
export function analyzeSeo(html: string, _pageUrl: string): QcSeoResult {
  const $ = cheerio.load(html);
  const issues: QcIssue[] = [];
  let score = 100;

  const penalize = (level: QcIssue["level"], msg: string, weight: number) => {
    issues.push({ level, msg });
    score -= weight;
  };

  // --- Title ---
  const title = $("title").first().text().trim();
  if (!title) {
    penalize("critical", "Tag <title> kosong atau tidak ada.", 20);
  } else if (title.length > 60) {
    penalize("warning", `Title terlalu panjang (${title.length} karakter, ideal <=60).`, 5);
  }

  // --- Meta description ---
  const metaDescription = $('meta[name="description"]').attr("content")?.trim() ?? "";
  if (!metaDescription) {
    penalize("critical", "Meta description tidak ditemukan.", 15);
  } else if (metaDescription.length > 160) {
    penalize(
      "warning",
      `Meta description terlalu panjang (${metaDescription.length} karakter, maks 160).`,
      8
    );
  } else if (metaDescription.length < 50) {
    penalize(
      "warning",
      `Meta description terlalu pendek (${metaDescription.length} karakter, minimal 50).`,
      8
    );
  }

  // --- H1 ---
  const h1Count = $("h1").length;
  if (h1Count === 0) {
    penalize("critical", "Tidak ada tag <h1> di halaman.", 12);
  } else if (h1Count > 1) {
    penalize("warning", `Ditemukan ${h1Count} tag <h1> (sebaiknya cuma 1).`, 8);
  }

  // --- Images tanpa alt ---
  const imgs = $("img");
  const imgTotal = imgs.length;
  let imgWithoutAlt = 0;
  imgs.each((_, el) => {
    const alt = $(el).attr("alt");
    if (alt === undefined || alt.trim() === "") imgWithoutAlt++;
  });
  if (imgWithoutAlt > 0) {
    penalize(
      "warning",
      `${imgWithoutAlt}/${imgTotal} gambar tanpa atribut alt.`,
      Math.min(15, imgWithoutAlt * 2)
    );
  }

  // --- Canonical ---
  const canonical = $('link[rel="canonical"]').attr("href")?.trim() || null;
  if (!canonical) {
    penalize("warning", "Tag <link rel=\"canonical\"> tidak ditemukan.", 10);
  }

  // --- Open Graph ---
  const ogTagsFound: string[] = [];
  for (const tag of OG_REQUIRED) {
    const content = $(`meta[property="${tag}"]`).attr("content");
    if (content) ogTagsFound.push(tag);
  }
  const ogMissing = OG_REQUIRED.filter((t) => !ogTagsFound.includes(t));
  if (ogMissing.length === OG_REQUIRED.length) {
    penalize("warning", "Tidak ada tag Open Graph sama sekali (og:title, og:description, dst).", 10);
  } else if (ogMissing.length > 0) {
    penalize("info", `Open Graph tags belum lengkap, hilang: ${ogMissing.join(", ")}.`, 4);
  }

  score = Math.max(0, Math.min(100, Math.round(score)));

  return {
    score,
    issues,
    meta: {
      title: title || null,
      titleLength: title.length,
      metaDescription: metaDescription || null,
      metaDescriptionLength: metaDescription.length,
      h1Count,
      imgTotal,
      imgWithoutAlt,
      canonical,
      ogTagsFound,
    },
  };
}
