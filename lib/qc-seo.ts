import * as cheerio from "cheerio";
import type { QcIssue, QcSeoResult, SeoKeywordStat } from "./qc-types";

const OG_REQUIRED = ["og:title", "og:description", "og:image", "og:url", "og:type", "og:site_name"];
const TWITTER_REQUIRED = ["twitter:card", "twitter:title", "twitter:description", "twitter:image"];

const STOP_WORDS = new Set([
  // English stop words
  "the", "and", "for", "that", "this", "with", "from", "your", "are", "was", "were", "have", "has",
  "had", "not", "but", "what", "all", "can", "will", "more", "about", "into", "than", "them", "then",
  "some", "such", "only", "other", "over", "also", "after", "before", "most", "our", "out", "you",
  "who", "how", "when", "where", "which", "their", "there", "been", "being", "each", "both", "any",
  // Indonesian stop words
  "dan", "yang", "untuk", "dari", "dengan", "pada", "ini", "itu", "atau", "dalam", "tidak", "akan",
  "ke", "di", "oleh", "sebagai", "dapat", "bisa", "lebih", "juga", "sudah", "telah", "kami", "kita",
  "anda", "mereka", "secara", "tanpa", "agar", "serta", "saat", "karena", "jika", "kalau", "ada",
]);

function extractJsonLdTypes(rawJson: string): string[] {
  const types: string[] = [];
  try {
    const parsed = JSON.parse(rawJson);
    const visit = (node: unknown) => {
      if (!node || typeof node !== "object") return;
      if (Array.isArray(node)) {
        node.forEach(visit);
        return;
      }
      const rec = node as Record<string, unknown>;
      if (typeof rec["@type"] === "string") {
        types.push(rec["@type"]);
      } else if (Array.isArray(rec["@type"])) {
        for (const t of rec["@type"]) {
          if (typeof t === "string") types.push(t);
        }
      }
      if (Array.isArray(rec["@graph"])) {
        rec["@graph"].forEach(visit);
      }
    };
    visit(parsed);
  } catch {
    // ignore malformed json-ld
  }
  return Array.from(new Set(types));
}

function computeTopKeywords(bodyText: string): { wordCount: number; topKeywords: SeoKeywordStat[] } {
  const tokens = bodyText
    .toLowerCase()
    .replace(/[^a-z0-9\u00C0-\u024F\s-]/gi, " ")
    .split(/\s+/)
    .map((w) => w.trim())
    .filter((w) => w.length >= 3);

  const wordCount = tokens.length;
  if (wordCount === 0) return { wordCount: 0, topKeywords: [] };

  const freq = new Map<string, number>();
  for (const token of tokens) {
    if (STOP_WORDS.has(token) || /^\d+$/.test(token)) continue;
    freq.set(token, (freq.get(token) ?? 0) + 1);
  }

  const topKeywords: SeoKeywordStat[] = Array.from(freq.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([word, count]) => ({
      word,
      count,
      densityPct: Number(((count / wordCount) * 100).toFixed(2)),
    }));

  return { wordCount, topKeywords };
}

/**
 * QC SEO Master & International Rank #1 Analyzer
 * Evaluates 35+ technical, content, structured data (JSON-LD), and international (hreflang/locale) SEO factors.
 */
export function analyzeSeo(html: string, pageUrl: string): QcSeoResult {
  const $ = cheerio.load(html);
  const issues: QcIssue[] = [];
  const recommendations: string[] = [];

  let techPenalty = 0;
  let intlPenalty = 0;
  let contentPenalty = 0;

  const penalize = (
    level: QcIssue["level"],
    msg: string,
    weight: number,
    bucket: "tech" | "intl" | "content" = "tech",
    rec?: string
  ) => {
    issues.push({ level, msg });
    if (bucket === "tech") techPenalty += weight;
    if (bucket === "intl") intlPenalty += weight;
    if (bucket === "content") contentPenalty += weight;
    if (rec) recommendations.push(rec);
  };

  let originHostname = "";
  let isHttps = false;
  try {
    const parsedUrl = new URL(pageUrl);
    originHostname = parsedUrl.hostname;
    isHttps = parsedUrl.protocol === "https:";
  } catch {
    isHttps = pageUrl.startsWith("https://");
  }

  // --- 1. HTTPS Security Signal ---
  if (!isHttps) {
    penalize(
      "critical",
      "URL tidak menggunakan protokol HTTPS (faktor peringkat utama Google).",
      15,
      "tech",
      "Aktifkan HTTPS + HSTS preload agar Google memberikan sinyal kepercayaan penuh."
    );
  }

  // --- 2. Title Tag ---
  const title = $("title").first().text().trim();
  if (!title) {
    penalize(
      "critical",
      "Tag <title> kosong atau tidak ditemukan.",
      22,
      "content",
      "Tambahkan <title> unik (50–60 karakter) dengan keyword utama di awal judul."
    );
  } else if (title.length < 25) {
    penalize(
      "warning",
      `Title terlalu pendek (${title.length} karakter, ideal 50–60 karakter untuk CTR Google maksimal).`,
      7,
      "content",
      "Perluas <title> dengan variasi keyword utama dalam Bahasa Inggris & Indonesia."
    );
  } else if (title.length > 68) {
    penalize(
      "warning",
      `Title berpotensi terpotong di SERP (${title.length} karakter, ideal <= 65 karakter).`,
      4,
      "content",
      "Ringkas <title> menjadi sekitar 55–65 karakter agar tidak terkena ellipsis di Google."
    );
  }

  // --- 3. Meta Description ---
  const metaDescription = $('meta[name="description"]').attr("content")?.trim() ?? "";
  if (!metaDescription) {
    penalize(
      "critical",
      "Meta description tidak ditemukan.",
      18,
      "content",
      "Tambahkan <meta name=\"description\"> sepanjang 120–160 karakter yang memuat value proposition & call-to-action."
    );
  } else if (metaDescription.length > 168) {
    penalize(
      "warning",
      `Meta description terlalu panjang (${metaDescription.length} karakter, ideal 120–160).`,
      5,
      "content",
      "Pangkas meta description ke rentang 120–160 karakter agar tampil utuh di snippet Google."
    );
  } else if (metaDescription.length < 60) {
    penalize(
      "warning",
      `Meta description terlalu pendek (${metaDescription.length} karakter, minimal 60).`,
      7,
      "content",
      "Perkaya meta description dengan kata kunci sekunder dan fitur utama."
    );
  }

  // --- 4. Meta Keywords ---
  const metaKeywords = $('meta[name="keywords"]').attr("content")?.trim() || null;

  // --- 5. Heading Hierarchy (H1 / H2 / H3) ---
  const h1Els = $("h1");
  const h1Count = h1Els.length;
  const h1Text = h1Els.first().text().trim() || null;
  const h2Count = $("h2").length;
  const h3Count = $("h3").length;

  if (h1Count === 0) {
    penalize(
      "critical",
      "Tidak ada tag <h1> utama di halaman.",
      15,
      "content",
      "Tambahkan tepat satu <h1> yang merangkum topik utama & keyword target halaman."
    );
  } else if (h1Count > 1) {
    penalize(
      "warning",
      `Ditemukan ${h1Count} tag <h1> (praktik terbaik semantik HTML5 adalah 1 <h1> utama).`,
      6,
      "content",
      "Gunakan satu <h1> untuk judul utama dan ubah subjudul lainnya menjadi <h2> / <h3>."
    );
  }

  if (h2Count === 0) {
    penalize(
      "info",
      "Tidak ditemukan sub-heading <h2> untuk menstrukturkan topik pendukung.",
      4,
      "content",
      "Tambahkan <h2> dengan long-tail keywords (Inggris & Indonesia) untuk memperluas cakupan kueri Google."
    );
  }

  // --- 6. Images & Alt Text ---
  const imgs = $("img");
  const imgTotal = imgs.length;
  let imgWithoutAlt = 0;
  imgs.each((_, el) => {
    const alt = $(el).attr("alt");
    const ariaHidden = $(el).attr("aria-hidden");
    if (ariaHidden === "true") return;
    if (alt === undefined || alt.trim() === "") imgWithoutAlt++;
  });
  if (imgWithoutAlt > 0) {
    penalize(
      "warning",
      `${imgWithoutAlt}/${imgTotal} gambar tidak memiliki atribut alt deskriptif (penting untuk Google Images & A11y).`,
      Math.min(12, imgWithoutAlt * 2),
      "content",
      "Isi atribut alt pada setiap gambar dengan deskripsi relevan untuk peringkat Google Image Search."
    );
  }

  // --- 7. Canonical URL ---
  const canonical = $('link[rel="canonical"]').attr("href")?.trim() || null;
  if (!canonical) {
    penalize(
      "warning",
      'Tag <link rel="canonical"> tidak ditemukan (risiko duplikasi URL di indeks Google).',
      10,
      "tech",
      'Pasang <link rel="canonical" href="https://domain-anda.com/path" /> di setiap halaman.'
    );
  }

  // --- 8. International SEO: HTML lang, Hreflang & x-default ---
  const htmlLang = $("html").attr("lang")?.trim() || null;
  if (!htmlLang) {
    penalize(
      "warning",
      "Atribut lang pada <html lang=\"...\"> tidak ditemukan (sinyal bahasa utama untuk mesin pencari global).",
      15,
      "intl",
      'Tambahkan atribut lang pada elemen root, misalnya <html lang="id"> atau <html lang="en">.'
    );
  }

  const hreflangTags: { lang: string; href: string }[] = [];
  $('link[rel="alternate"][hreflang]').each((_, el) => {
    const lang = $(el).attr("hreflang")?.trim();
    const href = $(el).attr("href")?.trim();
    if (lang && href) {
      hreflangTags.push({ lang, href });
    }
  });

  const hasXDefaultHreflang = hreflangTags.some((h) => h.lang.toLowerCase() === "x-default");
  const hasEnglishHreflang = hreflangTags.some((h) => h.lang.toLowerCase().startsWith("en"));

  if (hreflangTags.length === 0) {
    penalize(
      "warning",
      'Belum ada tag <link rel="alternate" hreflang="..."> untuk penargetan Google Internasional.',
      25,
      "intl",
      'Tambahkan tag hreflang (id-ID, en-US, en-GB, en-SG, x-default) agar halaman muncul di hasil pencarian Google global.'
    );
  } else {
    if (!hasXDefaultHreflang) {
      penalize(
        "info",
        'Tag hreflang="x-default" belum disetel sebagai fallback trafik global.',
        10,
        "intl",
        'Tambahkan <link rel="alternate" hreflang="x-default" href="..." /> untuk pengguna internasional di luar negara spesifik.'
      );
    }
    if (!hasEnglishHreflang) {
      penalize(
        "info",
        'Tag hreflang bahasa Inggris (en / en-US / en-GB) belum ditemukan.',
        10,
        "intl",
        'Sertakan hreflang="en-US" dan "en-GB" untuk menembus SERP internasional berbahasa Inggris.'
      );
    }
  }

  // --- 9. Open Graph & Multi-Locale OG ---
  const ogTagsFound: string[] = [];
  for (const tag of OG_REQUIRED) {
    const content = $(`meta[property="${tag}"]`).attr("content");
    if (content) ogTagsFound.push(tag);
  }
  const ogLocale = $('meta[property="og:locale"]').attr("content")?.trim() || null;
  const ogAlternateLocales: string[] = [];
  $('meta[property="og:locale:alternate"]').each((_, el) => {
    const val = $(el).attr("content")?.trim();
    if (val) ogAlternateLocales.push(val);
  });

  const ogMissing = ["og:title", "og:description", "og:image", "og:url"].filter(
    (t) => !ogTagsFound.includes(t)
  );
  if (ogMissing.length === 4) {
    penalize(
      "warning",
      "Tidak ada tag Open Graph utama (og:title, og:description, og:image, og:url).",
      10,
      "tech",
      "Pasang metadata Open Graph lengkap untuk meningkatkan CTR sosial & sinyal entitas."
    );
  } else if (ogMissing.length > 0) {
    penalize(
      "info",
      `Open Graph belum lengkap, kurang: ${ogMissing.join(", ")}.`,
      4,
      "tech",
      `Tambahkan tag Open Graph yang belum ada: ${ogMissing.join(", ")}.`
    );
  }

  if (!ogLocale) {
    penalize(
      "info",
      'Meta property="og:locale" tidak ditemukan untuk penargetan bahasa sosial global.',
      5,
      "intl",
      'Tambahkan <meta property="og:locale" content="en_US" /> dan og:locale:alternate (id_ID, en_GB).'
    );
  }

  // --- 10. Twitter / X Card ---
  const twitterTagsFound: string[] = [];
  for (const tag of TWITTER_REQUIRED) {
    const content = $(`meta[name="${tag}"], meta[property="${tag}"]`).attr("content");
    if (content) twitterTagsFound.push(tag);
  }
  const twitterCard =
    $('meta[name="twitter:card"], meta[property="twitter:card"]').attr("content")?.trim() || null;
  if (!twitterCard) {
    penalize(
      "info",
      'Meta twitter:card (summary_large_image) tidak ditemukan.',
      4,
      "tech",
      'Tambahkan <meta name="twitter:card" content="summary_large_image" />.'
    );
  }

  // --- 11. JSON-LD Structured Data (Schema.org Rich Snippets) ---
  const jsonLdScripts = $('script[type="application/ld+json"]');
  const jsonLdCount = jsonLdScripts.length;
  const jsonLdTypesSet = new Set<string>();
  jsonLdScripts.each((_, el) => {
    const raw = $(el).html() || $(el).text();
    for (const t of extractJsonLdTypes(raw)) {
      jsonLdTypesSet.add(t);
    }
  });
  const jsonLdTypes = Array.from(jsonLdTypesSet);

  if (jsonLdCount === 0) {
    penalize(
      "warning",
      'Structured Data JSON-LD (Schema.org) tidak ditemukan — halaman kehilangan peluang Rich Snippets & FAQ di Google.',
      12,
      "tech",
      'Tambahkan <script type="application/ld+json"> berisi skema Organization, WebSite, SoftwareApplication, dan FAQPage.'
    );
  }

  // --- 12. Robots, Viewport, Charset, Favicon, Manifest, RSS ---
  const robotsMeta = $('meta[name="robots"]').attr("content")?.trim() || null;
  if (robotsMeta && /noindex/i.test(robotsMeta)) {
    penalize(
      "critical",
      `Halaman memiliki direktif meta robots "${robotsMeta}" yang memblokir pengindeksan Google!`,
      35,
      "tech",
      'Ubah meta robots menjadi "index, follow, max-image-preview:large, max-snippet:-1".'
    );
  }

  const viewport = $('meta[name="viewport"]').attr("content")?.trim() || null;
  if (!viewport) {
    penalize(
      "warning",
      'Meta viewport tidak ditemukan (wajib untuk Google Mobile-First Indexing).',
      10,
      "tech",
      'Tambahkan <meta name="viewport" content="width=device-width, initial-scale=1" />.'
    );
  }

  const charset =
    $("meta[charset]").attr("charset")?.trim() ||
    $('meta[http-equiv="Content-Type"]').attr("content")?.trim() ||
    null;

  const hasFavicon = $('link[rel*="icon"]').length > 0;
  const hasManifest = $('link[rel="manifest"]').length > 0;
  const hasRssFeed = $('link[type="application/rss+xml"], link[type="application/atom+xml"]').length > 0;

  // --- 13. Links & Content / Keyword Density Analysis ---
  let internalLinkCount = 0;
  let externalLinkCount = 0;
  $("a[href]").each((_, el) => {
    const href = $(el).attr("href")?.trim();
    if (!href || href.startsWith("#") || href.startsWith("javascript:") || href.startsWith("mailto:")) return;
    if (href.startsWith("/")) {
      internalLinkCount++;
      return;
    }
    try {
      const u = new URL(href, pageUrl);
      if (originHostname && u.hostname === originHostname) {
        internalLinkCount++;
      } else {
        externalLinkCount++;
      }
    } catch {
      internalLinkCount++;
    }
  });

  if (internalLinkCount < 3) {
    penalize(
      "info",
      `Hanya ditemukan ${internalLinkCount} tautan internal (internal linking lemah untuk distribusi PageRank).`,
      4,
      "content",
      "Perkuat internal linking ke halaman fitur/modul utama agar Googlebot dapat merayapi seluruh struktur situs."
    );
  }

  const $clone = $.root().clone();
  $clone.find("script, style, noscript, svg").remove();
  const bodyText = $clone.text();
  const { wordCount, topKeywords } = computeTopKeywords(bodyText);

  if (wordCount < 120) {
    penalize(
      "warning",
      `Konten teks halaman relatif tipis (${wordCount} kata, rekomendasi >= 250 kata untuk otoritas topik).`,
      8,
      "content",
      "Tambahkan bagian penjelasan fitur, daftar kapabilitas, dan FAQ bilingual (ID + EN) untuk memperkaya kata kunci semantik."
    );
  }

  const technicalScore = Math.max(0, Math.min(100, Math.round(100 - techPenalty)));
  const internationalScore = Math.max(0, Math.min(100, Math.round(100 - intlPenalty)));
  const contentScore = Math.max(0, Math.min(100, Math.round(100 - contentPenalty)));

  // Weighted composite SEO Master Score
  const score = Math.max(
    0,
    Math.min(100, Math.round(technicalScore * 0.4 + contentScore * 0.35 + internationalScore * 0.25))
  );

  if (recommendations.length === 0) {
    recommendations.push(
      "Pertahankan struktur JSON-LD, tag Hreflang multi-region, dan kecepatan Core Web Vitals untuk menjaga posisi Rank #1 Google Global."
    );
  }

  return {
    score,
    internationalScore,
    technicalScore,
    contentScore,
    issues,
    recommendations,
    meta: {
      title: title || null,
      titleLength: title.length,
      metaDescription: metaDescription || null,
      metaDescriptionLength: metaDescription.length,
      metaKeywords,
      h1Count,
      h1Text,
      h2Count,
      h3Count,
      wordCount,
      imgTotal,
      imgWithoutAlt,
      canonical,
      htmlLang,
      hreflangTags,
      hasXDefaultHreflang,
      ogTagsFound,
      ogLocale,
      ogAlternateLocales,
      twitterTagsFound,
      twitterCard,
      jsonLdCount,
      jsonLdTypes,
      robotsMeta,
      viewport,
      charset,
      hasFavicon,
      hasManifest,
      hasRssFeed,
      isHttps,
      internalLinkCount,
      externalLinkCount,
      topKeywords,
    },
  };
}
