import type { HeaderScanReport } from "./types";
import { generateHardeningKit } from "./checks";

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function isoDate(ts: number): string {
  return new Date(ts).toISOString().slice(0, 19).replace("T", " ");
}

export function downloadHeaderScanAsJson(report: HeaderScanReport) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sentinel-header-scan-${report.hostname}-${report.id}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export function downloadHardeningKit(report: HeaderScanReport) {
  const content = generateHardeningKit(report.checks);
  const blob = new Blob([content], { type: "text/javascript" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `next.config.hardening-kit.${report.hostname}.js`;
  a.click();
  URL.revokeObjectURL(url);
}

export function exportHeaderScanAsPdf(report: HeaderScanReport) {
  const win = window.open("", "_blank", "width=900,height=1000");
  if (!win) return;

  const rowsHtml = report.checks
    .map(
      (c) => `
      <tr>
        <td style="padding:8px;border-bottom:1px solid #333;">
          <span style="color:${c.pass ? "#38d47a" : "#ff4d6d"};font-weight:bold;">${c.pass ? "PASS" : "MISS"}</span>
        </td>
        <td style="padding:8px;border-bottom:1px solid #333;">${escapeHtml(c.headerName)}</td>
        <td style="padding:8px;border-bottom:1px solid #333;color:#aaa;font-size:12px;">${escapeHtml(c.value ?? "—")}</td>
        <td style="padding:8px;border-bottom:1px solid #333;">${c.severity}</td>
      </tr>`
    )
    .join("");

  const missingHtml = report.checks
    .filter((c) => !c.pass)
    .map(
      (c) => `
      <section style="margin-bottom:16px;padding:14px;border:1px solid #333;border-radius:10px;">
        <h3 style="margin:0 0 6px;color:#e93ee8;">${escapeHtml(c.headerName)}</h3>
        <p style="margin:2px 0;color:#ccc;">${escapeHtml(c.risk)}</p>
        <pre style="background:#111;color:#38d47a;padding:8px;border-radius:8px;overflow:auto;font-size:12px;">${escapeHtml(c.fixNextConfig)}</pre>
      </section>`
    )
    .join("");

  win.document.write(`
    <html>
      <head>
        <title>Sentinel-ID Header Armor Report — ${escapeHtml(report.hostname)}</title>
        <style>
          body { font-family: ui-monospace, monospace; background:#0a0713; color:#eee; padding:32px; }
          h1 { color:#e93ee8; }
          table { width:100%; border-collapse:collapse; margin:16px 0; }
          th { text-align:left; padding:8px; border-bottom:2px solid #555; color:#e93ee8; font-size:12px; text-transform:uppercase; }
        </style>
      </head>
      <body>
        <h1>Sentinel-ID — Header Armor Report</h1>
        <p><strong>Target:</strong> ${escapeHtml(report.finalUrl)}</p>
        <p><strong>Generated:</strong> ${isoDate(report.createdAt)}</p>
        <p><strong>Grade:</strong> ${report.grade} &nbsp;·&nbsp; <strong>Score:</strong> ${report.score}/100</p>
        <p><strong>HTTP Status:</strong> ${report.statusCode}</p>
        <hr style="border-color:#333;margin:20px 0;" />
        <table>
          <thead><tr><th>Status</th><th>Header</th><th>Value</th><th>Severity</th></tr></thead>
          <tbody>${rowsHtml}</tbody>
        </table>
        <hr style="border-color:#333;margin:20px 0;" />
        <h2 style="color:#e93ee8;font-size:16px;">Hardening — Missing Headers</h2>
        ${missingHtml || "<p>Semua header yang dicek sudah terpasang. 🎉</p>"}
      </body>
    </html>
  `);
  win.document.close();
  win.focus();
  win.print();
}
