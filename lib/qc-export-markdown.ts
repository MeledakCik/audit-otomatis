import type { QcState } from "./qc-types";

const LEVEL_EMOJI: Record<string, string> = {
  critical: "🟥",
  warning: "🟨",
  info: "⬜",
};

function isoDate(ts: number): string {
  return new Date(ts).toISOString().slice(0, 19).replace("T", " ");
}

export function exportQcToObsidianMarkdown(qc: QcState): string {
  const { result } = qc;
  const lines: string[] = [];

  lines.push("---");
  lines.push(`title: "QC & SEO Master Report - ${qc.domain}"`);
  lines.push(`domain: "${qc.domain}"`);
  lines.push(`qc_id: "${qc.id}"`);
  lines.push(`date: ${isoDate(qc.createdAt)}`);
  lines.push(`status: ${qc.status}`);
  lines.push(`overall_score: ${result.overallScore ?? "-"}`);
  lines.push(`tags: [qc-otomatis, seo-master, international-seo, auto-security-auditor, "${qc.domain}"]`);
  lines.push("---");
  lines.push("");
  lines.push(`# 🧪 QC & SEO Master Report — ${qc.domain}`);
  lines.push("");
  lines.push("> [!info] Ringkasan");
  lines.push(`> - Origin: ${qc.origin}`);
  lines.push(`> - Waktu QC: ${isoDate(qc.createdAt)}`);
  lines.push(`> - Skor keseluruhan: ${result.overallScore ?? "-"}/100`);
  lines.push(`> - Total request terpakai: ${qc.requestsMade}`);
  lines.push(`> - Status: ${qc.status}`);
  lines.push("");

  if (qc.error) {
    lines.push("## ⚠️ QC Diblokir / Error");
    lines.push("");
    lines.push(qc.error);
    lines.push("");
  }

  lines.push("## Ringkasan Skor Modul");
  lines.push("");
  lines.push("| Modul | Skor |");
  lines.push("|---|---|");
  lines.push(`| SEO Master (Overall) | ${result.seo ? `${result.seo.score}/100` : "tidak dijalankan"} |`);
  if (result.seo) {
    lines.push(`| ↳ Technical & Schema SEO | ${result.seo.technicalScore}/100 |`);
    lines.push(`| ↳ International & Hreflang SEO | ${result.seo.internationalScore}/100 |`);
    lines.push(`| ↳ Content & Keyword Authority | ${result.seo.contentScore}/100 |`);
  }
  lines.push(`| Performance | ${result.perf ? `${result.perf.score}/100` : "tidak dijalankan"} |`);
  lines.push(`| Content/Link | ${result.content ? `${result.content.score}/100` : "tidak dijalankan"} |`);
  lines.push("");

  if (result.seo) {
    lines.push("## 🔎 QC SEO Master & International SERP Readiness");
    lines.push("");
    lines.push(`- **Skor SEO Master**: ${result.seo.score}/100 (Tech: ${result.seo.technicalScore} · Intl: ${result.seo.internationalScore} · Content: ${result.seo.contentScore})`);
    lines.push(`- **Title**: \`${result.seo.meta.title ?? "(kosong)"}\` (${result.seo.meta.titleLength} char)`);
    lines.push(`- **Meta description**: ${result.seo.meta.metaDescriptionLength} char`);
    lines.push(`- **Heading (H1 / H2 / H3)**: ${result.seo.meta.h1Count} / ${result.seo.meta.h2Count} / ${result.seo.meta.h3Count}`);
    lines.push(`- **Total kata (Word Count)**: ${result.seo.meta.wordCount}`);
    lines.push(`- **Gambar tanpa alt**: ${result.seo.meta.imgWithoutAlt}/${result.seo.meta.imgTotal}`);
    lines.push(`- **Canonical**: ${result.seo.meta.canonical ?? "tidak ada"}`);
    lines.push(`- **HTML Lang**: \`${result.seo.meta.htmlLang ?? "tidak ada"}\``);
    lines.push(
      `- **International Hreflang (${result.seo.meta.hreflangTags.length})**: ${
        result.seo.meta.hreflangTags.length > 0
          ? result.seo.meta.hreflangTags.map((h) => h.lang).join(", ")
          : "tidak ada"
      } (x-default: ${fmtBool(result.seo.meta.hasXDefaultHreflang)})`
    );
    lines.push(
      `- **Structured Data JSON-LD (${result.seo.meta.jsonLdCount})**: ${
        result.seo.meta.jsonLdTypes.length > 0 ? result.seo.meta.jsonLdTypes.join(", ") : "tidak ada"
      }`
    );
    lines.push(
      `- **Open Graph ditemukan**: ${result.seo.meta.ogTagsFound.length > 0 ? result.seo.meta.ogTagsFound.join(", ") : "tidak ada"} (og:locale: ${result.seo.meta.ogLocale ?? "-"})`
    );
    lines.push(
      `- **Twitter Card**: ${result.seo.meta.twitterCard ?? "tidak ada"} (${result.seo.meta.twitterTagsFound.join(", ") || "-"})`
    );
    lines.push(`- **Links (Internal / External)**: ${result.seo.meta.internalLinkCount} / ${result.seo.meta.externalLinkCount}`);
    lines.push("");

    if (result.seo.meta.topKeywords.length > 0) {
      lines.push("### Top Keywords & Density");
      lines.push("");
      lines.push("| Keyword | Count | Density |");
      lines.push("|---|---:|---:|");
      for (const kw of result.seo.meta.topKeywords) {
        lines.push(`| \`${kw.word}\` | ${kw.count} | ${kw.densityPct}% |`);
      }
      lines.push("");
    }

    if (result.seo.issues.length > 0) {
      lines.push("### Temuan & Issue SEO");
      lines.push("");
      lines.push("| Level | Issue |");
      lines.push("|---|---|");
      for (const issue of result.seo.issues) {
        lines.push(`| ${LEVEL_EMOJI[issue.level]} ${issue.level} | ${issue.msg} |`);
      }
      lines.push("");
    }

    if (result.seo.recommendations.length > 0) {
      lines.push("### Rekomendasi Prioritas Rank #1 Google");
      lines.push("");
      for (const rec of result.seo.recommendations) {
        lines.push(`- ${rec}`);
      }
      lines.push("");
    }
  }

  if (result.perf) {
    lines.push("## ⚡ QC Performance");
    lines.push("");
    lines.push(`- **Skor**: ${result.perf.score}/100`);
    lines.push(`- **Sumber data**: ${result.perf.metrics.source === "pagespeed" ? "Google PageSpeed Insights" : "Fallback manual"}`);
    lines.push(`- **LCP**: ${result.perf.metrics.lcp ?? "-"}`);
    lines.push(`- **CLS**: ${result.perf.metrics.cls ?? "-"}`);
    lines.push(`- **FCP**: ${result.perf.metrics.fcp ?? "-"}`);
    lines.push(`- **TBT**: ${result.perf.metrics.tbt ?? "-"}`);
    lines.push(
      `- **Ukuran halaman**: ${result.perf.metrics.sizeBytes ? `${(result.perf.metrics.sizeBytes / 1024).toFixed(0)} KB` : "-"}`
    );
    lines.push(`- **Format gambar modern (WebP/AVIF)**: ${fmtBool(result.perf.metrics.modernImageFormat)}`);
    lines.push(`- **Cache header**: ${fmtBool(result.perf.metrics.cacheHeaders)}`);
    lines.push(`- **Lazy loading**: ${fmtBool(result.perf.metrics.lazyLoading)}`);
    if (result.perf.metrics.lcpElement) {
      lines.push(`- **Elemen penyebab LCP**: \`${result.perf.metrics.lcpElement.selector ?? "-"}\``);
      if (result.perf.metrics.lcpElement.snippet) {
        lines.push("  ```html");
        lines.push(`  ${result.perf.metrics.lcpElement.snippet}`);
        lines.push("  ```");
      }
      if (result.perf.metrics.lcpElement.isLazyLoaded) {
        lines.push("  - ⚠ Elemen ini kena `loading=\"lazy\"` (kontraproduktif untuk LCP).");
      }
    }
    lines.push("");
    if (result.perf.issues.length > 0) {
      lines.push("| Level | Issue |");
      lines.push("|---|---|");
      for (const issue of result.perf.issues) {
        lines.push(`| ${LEVEL_EMOJI[issue.level]} ${issue.level} | ${issue.msg} |`);
      }
      lines.push("");
    }
  }

  if (result.content) {
    lines.push("## 🔗 QC Content / Link");
    lines.push("");
    lines.push(`- **Skor**: ${result.content.score}/100`);
    lines.push(`- **Link dicek**: ${result.content.checked.linksChecked}`);
    lines.push(`- **Form dicek**: ${result.content.checked.formsChecked}`);
    lines.push(`- **Anchor dicek**: ${result.content.checked.anchorsChecked}`);
    lines.push("");
    if (result.content.brokenLinks.length > 0) {
      lines.push("### Broken Links");
      lines.push("");
      for (const link of result.content.brokenLinks) {
        lines.push(`- \`${link}\``);
      }
      lines.push("");
    }
    if (result.content.a11yIssues.length > 0) {
      lines.push("### A11y Issues");
      lines.push("");
      lines.push("| Level | Issue |");
      lines.push("|---|---|");
      for (const issue of result.content.a11yIssues) {
        lines.push(`| ${LEVEL_EMOJI[issue.level]} ${issue.level} | ${issue.msg} |`);
      }
      lines.push("");
    }
  }

  lines.push("---");
  lines.push("*Dihasilkan otomatis oleh QC Otomatis & SEO Master — Sentinel-ID Auto Security Auditor.*");

  return lines.join("\n");
}

function fmtBool(v: boolean | null): string {
  if (v === null) return "-";
  return v ? "✅ ya" : "❌ tidak";
}