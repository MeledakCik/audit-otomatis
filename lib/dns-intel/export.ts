import type { DnsIntelReport } from "./types";

/** Bentuk JSON export sesuai spesifikasi: { domain, records, security }. */
export function toExportShape(report: DnsIntelReport) {
  return {
    domain: report.domain,
    scannedAt: new Date(report.createdAt).toISOString(),
    scanDurationMs: report.scanDurationMs,
    records: report.records,
    security: report.security,
    queryErrors: report.queryErrors,
  };
}

export function downloadDnsIntelAsJson(report: DnsIntelReport) {
  const blob = new Blob([JSON.stringify(toExportShape(report), null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sentinel-dns-intel-${report.domain}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export async function copyDnsIntelAsJson(report: DnsIntelReport): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(JSON.stringify(toExportShape(report), null, 2));
    return true;
  } catch {
    return false;
  }
}
