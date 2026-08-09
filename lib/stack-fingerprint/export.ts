import type { StackFingerprintReport } from "./types";

export function downloadStackFingerprintAsJson(report: StackFingerprintReport) {
  const payload = {
    domain: report.domain,
    targetUrl: report.targetUrl,
    scannedAt: new Date(report.createdAt).toISOString(),
    statusCode: report.statusCode,
    disclaimer: "For educational asset inventory purposes. Detects public tech markers only. No CVE/vulnerability data included.",
    stacks: report.stacks.map((s) => ({
      name: s.name,
      category: s.category,
      confidence: s.confidence,
      version: s.version,
      evidence: s.evidence.map((e) => e.label),
    })),
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sentinel-stack-report-${report.domain}.json`;
  a.click();
  URL.revokeObjectURL(url);
}
