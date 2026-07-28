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
  lines.push(`title: "QC Report - ${qc.domain}"`);
  lines.push(`domain: "${qc.domain}"`);
  lines.push(`qc_id: "${qc.id}"`);
  lines.push(`date: ${isoDate(qc.createdAt)}`);
  lines.push(`status: ${qc.status}`);
  lines.push(`overall_score: ${result.overallScore ?? "-"}`);
  lines.push(`tags: [qc-otomatis, auto-security-auditor, "${qc.domain}"]`);
  lines.push("---");
  lines.push("");
  lines.push(`# 🧪 QC Report — ${qc.domain}`);
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
  lines.push(`| SEO | ${result.seo ? `${result.seo.score}/100` : "tidak dijalankan"} |`);
  lines.push(`| Performance | ${result.perf ? `${result.perf.score}/100` : "tidak dijalankan"} |`);
  lines.push(`| Content/Link | ${result.content ? `${result.content.score}/100` : "tidak dijalankan"} |`);
  lines.push("");

  if (result.seo) {
    lines.push("## 🔎 QC SEO Otomatis");
    lines.push("");
    lines.push(`- **Skor**: ${result.seo.score}/100`);
    lines.push(`- **Title**: \`${result.seo.meta.title ?? "(kosong)"}\` (${result.seo.meta.titleLength} char)`);
    lines.push(
      `- **Meta description**: ${result.seo.meta.metaDescriptionLength} char`
    );
    lines.push(`- **Jumlah H1**: ${result.seo.meta.h1Count}`);
    lines.push(`- **Gambar tanpa alt**: ${result.seo.meta.imgWithoutAlt}/${result.seo.meta.imgTotal}`);
    lines.push(`- **Canonical**: ${result.seo.meta.canonical ?? "tidak ada"}`);
    lines.push(
      `- **Open Graph ditemukan**: ${result.seo.meta.ogTagsFound.length > 0 ? result.seo.meta.ogTagsFound.join(", ") : "tidak ada"}`
    );
    lines.push("");
    if (result.seo.issues.length > 0) {
      lines.push("| Level | Issue |");
      lines.push("|---|---|");
      for (const issue of result.seo.issues) {
        lines.push(`| ${LEVEL_EMOJI[issue.level]} ${issue.level} | ${issue.msg} |`);
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
  lines.push("*Dihasilkan otomatis oleh QC Otomatis — Auto Security Auditor.*");

  return lines.join("\n");
}

function fmtBool(v: boolean | null): string {
  if (v === null) return "-";
  return v ? "✅ ya" : "❌ tidak";
}
