import type { SubdomainWatchReport } from "./types";

function triggerDownload(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function csvEscape(value: string): string {
  if (/[",\n]/.test(value)) {
    return `"${value.replace(/"/g, '""')}"`;
  }
  return value;
}

export function downloadSubdomainWatchAsCsv(report: SubdomainWatchReport) {
  const header = ["subdomain", "source", "http_status", "cname", "service", "risk", "reason"];
  const lines = [header.join(",")];

  for (const row of report.rows) {
    lines.push(
      [
        row.subdomain,
        "crt.sh",
        row.httpStatus?.toString() ?? "",
        row.cname ?? "",
        row.service ?? "",
        row.risk,
        row.reason ?? "",
      ]
        .map((v) => csvEscape(String(v)))
        .join(",")
    );
  }

  triggerDownload(lines.join("\n"), `sentinel-subdomain-watch-${report.domain}.csv`, "text/csv");
}

export function buildDnsCleanupReport(report: SubdomainWatchReport): string {
  const flagged = report.rows.filter((r) => r.risk === "HIGH" || r.risk === "MEDIUM");
  const high = flagged.filter((r) => r.risk === "HIGH");
  const medium = flagged.filter((r) => r.risk === "MEDIUM");

  const lines: string[] = [];
  lines.push(`# DNS Cleanup Report — ${report.domain}`);
  lines.push(`Generated: ${new Date(report.createdAt).toISOString()}`);
  lines.push(`Source: crt.sh Certificate Transparency logs (passive only, no bruteforce)`);
  lines.push(`Total subdomains found: ${report.totalFound}${report.truncated ? " (truncated to first 100)" : ""}`);
  lines.push(`Checked: ${report.rows.length} | HIGH risk: ${high.length} | MEDIUM risk: ${medium.length}`);
  lines.push("");

  if (flagged.length === 0) {
    lines.push("No potential takeover candidates found among the checked subdomains.");
    lines.push("This does not guarantee the domain is fully safe — only the checked subset was analyzed.");
    return lines.join("\n");
  }

  if (high.length > 0) {
    lines.push("## HIGH RISK — likely takeover, act now");
    lines.push("");
    for (const row of high) {
      lines.push(`- ${row.subdomain}`);
      lines.push(`  CNAME: ${row.cname ?? "-"}`);
      lines.push(`  Service: ${row.service ?? "-"}`);
      lines.push(`  Reason: ${row.reason ?? "-"}`);
      lines.push(`  Fix: ${row.fix ?? "Claim the resource or remove the DNS record."}`);
      lines.push("");
    }
  }

  if (medium.length > 0) {
    lines.push("## MEDIUM RISK — dangling CNAME, verify manually");
    lines.push("");
    for (const row of medium) {
      lines.push(`- ${row.subdomain}`);
      lines.push(`  CNAME: ${row.cname ?? "-"}`);
      lines.push(`  Service: ${row.service ?? "-"}`);
      lines.push(`  Reason: ${row.reason ?? "-"}`);
      lines.push(`  Fix: ${row.fix ?? "Verify ownership, then claim or remove the DNS record."}`);
      lines.push("");
    }
  }

  lines.push("## Recommended next steps");
  lines.push("1. For each HIGH risk entry, either re-claim the resource at the third-party service,");
  lines.push("   or delete the dangling CNAME record from your DNS zone immediately.");
  lines.push("2. For MEDIUM risk entries, manually verify whether the resource is still owned before acting.");
  lines.push("3. Re-run this scan periodically — new certificates (and new dangling CNAMEs) appear over time.");

  return lines.join("\n");
}

export function downloadDnsCleanupReport(report: SubdomainWatchReport) {
  const content = buildDnsCleanupReport(report);
  triggerDownload(content, `sentinel-dns-cleanup-report-${report.domain}.txt`, "text/plain");
}
