import type { SecurityReport } from "./types";

function isoDate(ts: number): string {
  return new Date(ts).toISOString().slice(0, 19).replace("T", " ");
}

export function downloadReportAsJson(report: SecurityReport) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sentinel-maintenance-log-${report.id}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Membuka jendela print browser berisi laporan yang sudah diformat rapi,
 * supaya user tinggal "Save as PDF" — tanpa perlu dependency PDF generator baru.
 */
export function exportReportAsPdf(report: SecurityReport) {
  const win = window.open("", "_blank", "width=900,height=1000");
  if (!win) return;

  const findingsHtml = report.findings
    .map(
      (f, i) => `
      <section style="margin-bottom:24px;padding:16px;border:1px solid #333;border-radius:12px;">
        <h3 style="margin:0 0 6px;">#${i + 1} [${f.severity}] ${escapeHtml(f.title)}</h3>
        <p style="margin:2px 0;color:#aaa;">${escapeHtml(f.vulnerabilityType)} — ${escapeHtml(f.owaspCategory)}</p>
        <p style="margin:6px 0;"><strong>Lokasi:</strong> ${escapeHtml(
          [f.leakLocation.file, f.leakLocation.line ? `:${f.leakLocation.line}` : "", f.leakLocation.endpoint]
            .filter(Boolean)
            .join(" ")
        )}</p>
        ${f.codeSnippet ? `<pre style="background:#111;color:#f66;padding:8px;border-radius:8px;overflow:auto;">${escapeHtml(f.codeSnippet)}</pre>` : ""}
        <p style="margin:6px 0;"><strong>Attack Vector:</strong> ${escapeHtml(f.attackVector)}</p>
        ${f.payloadExample ? `<p style="margin:6px 0;"><strong>Contoh Payload:</strong> <code>${escapeHtml(f.payloadExample)}</code></p>` : ""}
        <p style="margin:6px 0;"><strong>Remediation:</strong></p>
        <ol>
          ${f.remediationSteps.map((s) => `<li>${escapeHtml(s.step)}</li>`).join("")}
        </ol>
        <p style="margin:6px 0;"><strong>Prevention:</strong> ${escapeHtml(f.prevention)}</p>
      </section>`
    )
    .join("");

  win.document.write(`
    <html>
      <head>
        <title>Sentinel-ID Maintenance Log Report</title>
        <style>
          body { font-family: ui-monospace, monospace; background:#0a0713; color:#eee; padding:32px; }
          h1 { color:#e93ee8; }
        </style>
      </head>
      <body>
        <h1>Sentinel-ID — Maintenance Log Report</h1>
        <p><strong>Source:</strong> ${escapeHtml(report.sourceName)}</p>
        <p><strong>Generated:</strong> ${isoDate(report.createdAt)}</p>
        <p><strong>Overall Severity:</strong> ${report.overallSeverity}</p>
        <p><strong>Summary:</strong> ${escapeHtml(report.summary)}</p>
        <hr style="border-color:#333;margin:20px 0;" />
        ${findingsHtml || "<p>Tidak ada temuan.</p>"}
      </body>
    </html>
  `);
  win.document.close();
  win.focus();
  win.print();
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
