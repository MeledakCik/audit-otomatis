import type { Finding, ScanState, Severity } from "./types";

const SEVERITY_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

const SEVERITY_COLOR: Record<Severity, string> = {
  CRITICAL: "#f43f5e",
  HIGH: "#f97316",
  MEDIUM: "#eab308",
  LOW: "#3b82f6",
  INFO: "#94a3b8",
};

// Muted card background per severity (used only when count > 0, to make
// non-empty severities pop the way they do in the reference design).
const SEVERITY_BG: Record<Severity, string> = {
  CRITICAL: "rgba(244, 63, 94, 0.16)",
  HIGH: "rgba(249, 115, 22, 0.16)",
  MEDIUM: "rgba(234, 179, 8, 0.16)",
  LOW: "rgba(59, 130, 246, 0.22)",
  INFO: "rgba(148, 163, 184, 0.14)",
};

function esc(s: string | undefined | null): string {
  // Beberapa Finding lama/edge-case bisa kehilangan field opsional; jangan
  // sampai satu field kosong bikin seluruh report.html gagal di-generate
  // (sebelumnya ini bisa throw "Cannot read properties of undefined" dan
  // route handler mengembalikan response kosong / halaman blank ke user).
  return String(s ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function isoDate(ts: number): string {
  return new Date(ts).toISOString().slice(0, 19).replace("T", " ") + " UTC";
}

/** Estimasi CVSS kalau finding tidak sudah membawa nilai eksplisit
 * (mis. temuan dari tester.ts lama yang belum di-tag cvss). Estimasi kasar
 * berbasis severity, bukan perhitungan CVSS vector penuh. */
function estimateCvss(f: Finding): number {
  if (typeof f.cvss === "number") return f.cvss;
  const bySeverity: Record<Severity, number> = {
    CRITICAL: 9.1,
    HIGH: 7.5,
    MEDIUM: 5.3,
    LOW: 3.1,
    INFO: 0,
  };
  return bySeverity[f.severity];
}

function vulnId(index: number): string {
  return `VULN-${String(index + 1).padStart(3, "0")}`;
}

// Ikon mata (buka/tutup) buat toggle detail finding. Inline SVG biar report
// tetap satu file mandiri, tanpa dependensi icon font/CDN eksternal.
const EYE_OPEN_SVG =
  '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-7 11-7 11 7 11 7-4 7-11 7-11-7-11-7Z"/><circle cx="12" cy="12" r="3"/></svg>';
const EYE_CLOSED_SVG =
  '<svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.94 10.94 0 0 1 12 19c-7 0-11-7-11-7a21.6 21.6 0 0 1 5.06-5.94M9.9 4.24A10.94 10.94 0 0 1 12 4c7 0 11 7 11 7a21.6 21.6 0 0 1-2.29 3.22M14.12 14.12a3 3 0 1 1-4.24-4.24"/><path d="M1 1l22 22"/></svg>';

/**
 * Render laporan gaya pentest lengkap: header bar + executive summary +
 * finding inventory + temuan terurut CRITICAL -> LOW, masing-masing dengan
 * format [VULN-XXX] [SEVERITY] Title, Location, Severity+CVSS, Evidence,
 * Impact, PoC non-destruktif, Remediation.
 */
export function renderPentestReportHtml(scan: ScanState): string {
  const sorted = [...scan.findings].sort(
    (a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)
  );

  const counts = SEVERITY_ORDER.reduce<Record<Severity, number>>((acc, sev) => {
    acc[sev] = scan.findings.filter((f) => f.severity === sev).length;
    return acc;
  }, {} as Record<Severity, number>);

  const secretCount = scan.findings.filter((f) => f.category === "secret").length;
  const cveCount = scan.findings.filter((f) => f.category === "outdated-library").length;

  const inventoryRows = sorted
    .map((f, i) => {
      const id = vulnId(i);
      const color = SEVERITY_COLOR[f.severity];
      return `
      <div class="inv-row" onclick="revealFinding('${id}')">
        <span class="inv-dot" style="background:${color}"></span>
        <span class="inv-id">[${id}]</span>
        <span class="inv-sev" style="color:${color}">[${f.severity}]</span>
        <span class="inv-title">${esc(f.title)}</span>
        <span class="eye-icon inv-eye">${EYE_OPEN_SVG}</span>
      </div>`;
    })
    .join("\n");

  const findingRows = sorted
    .map((f, i) => {
      const id = vulnId(i);
      const cvss = estimateCvss(f);
      const color = SEVERITY_COLOR[f.severity];
      return `
      <section class="finding" id="${id}">
        <div class="finding-head" style="border-left-color:${color}" onclick="toggleFinding('${id}')">
          <span class="badge" style="background:${color}">${f.severity}</span>
          <h3>[${id}] ${esc(f.title)}</h3>
          <button class="eye-icon eye-btn" data-eye="${id}" onclick="event.stopPropagation(); toggleFinding('${id}')" aria-label="Buka/tutup detail temuan">${EYE_OPEN_SVG}</button>
        </div>
        <div class="finding-body" id="body-${id}">
          <div class="finding-meta">
            <div class="mcell">
              <div class="flabel">Location</div>
              <div class="fval"><code>${esc(f.endpoint)}</code></div>
            </div>
            <div class="mcell">
              <div class="flabel">Severity</div>
              <div class="fval">${f.severity} &mdash; CVSS <strong>${cvss.toFixed(1)}</strong>${f.cwe ? ` &mdash; <code>${esc(f.cwe)}</code>` : ""}</div>
            </div>
            <div class="mcell">
              <div class="flabel">Evidence</div>
              <div class="fval"><code>${esc(f.evidence)}</code></div>
            </div>
          </div>
          <div class="finding-detail">
            <div class="fcol">
              <div class="flabel">Impact</div>
              <div class="fval">${esc(f.impact)}</div>
              ${
                f.poc
                  ? `<div class="flabel">PoC (Non-Destruktif)</div><pre>${esc(f.poc)}</pre>`
                  : ""
              }
            </div>
            <div class="fcol">
              <div class="callout">
                <div class="callout-head">🛠️ Recommended Action</div>
                <pre>${esc(f.fix)}</pre>
              </div>
            </div>
          </div>
        </div>
      </section>`;
    })
    .join("\n");
  const graphNodeCount = scan.graph?.nodes.length ?? 0;
  const graphEdgeCount = scan.graph?.edges.length ?? 0;

  const endpointRows = (scan.endpoints ?? [])
    .map((ep) => {
      const curl =
        ep.method === "GET"
          ? `curl -sS -i -X GET '${ep.url}'`
          : `curl -sS -i -X ${ep.method} '${ep.url}' -H 'Content-Type: application/json' -d '${
              ep.payload && ep.payload.length > 0
                ? JSON.stringify(Object.fromEntries(ep.payload.map((f) => [f, ""])))
                : "{}"
            }'`;
      return `
      <tr>
        <td><span class="badge" style="background:${
          ep.method === "GET" ? "#3b82f6" : "#f97316"
        }">${esc(ep.method)}</span></td>
        <td><code>${esc(ep.url)}</code></td>
        <td style="color:#8b93a7;">${esc(ep.source)}</td>
        <td><code>${esc(curl)}</code></td>
      </tr>`;
    })
    .join("\n");

  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="utf-8" />
<title>Pentest Report — ${esc(scan.domain)}</title>
<style>
  :root { color-scheme: dark; }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, "Segoe UI", Inter, Roboto, sans-serif;
    background: #0b0e17;
    color: #dbe1ec;
    margin: 0;
    padding: 0;
  }
  code, pre { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; }
  .wrap { max-width: 980px; margin: 0 auto; padding: 24px 24px 80px; }

  /* Header */
  .topbar {
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    gap: 16px;
    background: #10141f;
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 10px;
    padding: 16px 20px;
    margin-bottom: 24px;
  }
  .topbar h1 { font-size: 17px; margin: 0 0 6px; color: #f8fafc; display: flex; align-items: center; gap: 8px; }
  .topbar .sub { color: #8b93a7; font-size: 12px; }
  .topbar .sub a { color: #60a5fa; text-decoration: none; }
  .topbar .sub a:hover { text-decoration: underline; }
  .topbar-actions { display: flex; gap: 8px; flex-shrink: 0; }
  .btn {
    font-size: 12px;
    font-weight: 600;
    padding: 8px 14px;
    border-radius: 7px;
    border: 1px solid rgba(255,255,255,0.12);
    background: #171c2b;
    color: #dbe1ec;
    white-space: nowrap;
  }
  .btn.primary {
    background: linear-gradient(135deg, #a21caf, #db2777);
    border: none;
    color: #fff;
  }

  /* Summary */
  .summary { background: #10141f; border: 1px solid rgba(255,255,255,0.07); border-radius: 10px; padding: 20px; margin-bottom: 24px; }
  .summary h2 { margin: 0 0 14px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: #8b93a7; }
  .stat-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 10px; margin-bottom: 14px; }
  .stat { background: #171c2b; border: 1px solid rgba(255,255,255,0.06); border-radius: 8px; padding: 14px 14px 12px; }
  .stat .n { font-size: 24px; font-weight: 700; color: #f8fafc; line-height: 1.1; }
  .stat .l { font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; color: #8b93a7; margin-top: 4px; }

  .sev-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 10px; margin-bottom: 14px; }
  .sev { border-radius: 8px; padding: 12px 10px; text-align: center; border: 1px solid rgba(255,255,255,0.06); background: #171c2b; }
  .sev .n { font-size: 19px; font-weight: 700; }
  .sev .l { font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; margin-top: 2px; opacity: 0.9; }

  .summary p.note { font-size: 12px; color: #8b93a7; margin: 10px 0 0; line-height: 1.6; }

  /* Finding inventory */
  .inventory { background: #10141f; border: 1px solid rgba(255,255,255,0.07); border-radius: 10px; padding: 18px 20px; margin-bottom: 24px; }
  .inventory h2 { margin: 0 0 10px; font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: #8b93a7; }
  .inv-row { display: flex; align-items: center; gap: 8px; padding: 9px 10px; border-radius: 6px; text-decoration: none; font-size: 12.5px; cursor: pointer; transition: background 0.12s ease; }
  .inv-row:hover { background: #171c2b; }
  .inv-row:hover .inv-eye { color: #dbe1ec; }
  .inv-dot { width: 7px; height: 7px; border-radius: 50%; flex-shrink: 0; }
  .inv-id { color: #6b7280; font-family: ui-monospace, monospace; font-size: 11.5px; }
  .inv-sev { font-weight: 700; font-family: ui-monospace, monospace; font-size: 11px; }
  .inv-title { color: #dbe1ec; flex: 1; }
  .inv-eye { margin-left: auto; color: #5b6478; flex-shrink: 0; transition: color 0.12s ease; }

  /* Findings */
  .finding {
    border: 1px solid rgba(255,255,255,0.07);
    border-radius: 12px;
    margin-bottom: 16px;
    background: #10141f;
    overflow: hidden;
    box-shadow: 0 1px 2px rgba(0,0,0,0.25);
    transition: box-shadow 0.15s ease, border-color 0.15s ease;
  }
  .finding:hover { box-shadow: 0 4px 16px rgba(0,0,0,0.35); border-color: rgba(255,255,255,0.12); }
  .finding-head { display: flex; align-items: center; gap: 10px; padding: 14px 16px 14px 14px; border-left: 4px solid; background: #171c2b; cursor: pointer; }
  .finding-head h3 { margin: 0; font-size: 14.5px; color: #f8fafc; font-weight: 600; flex: 1; }
  .badge {
    color: #0b0e17;
    font-size: 10px;
    font-weight: 800;
    padding: 4px 9px;
    border-radius: 6px;
    letter-spacing: 0.04em;
    flex-shrink: 0;
    font-family: ui-monospace, monospace;
    text-transform: uppercase;
  }
  .eye-icon { display: inline-flex; align-items: center; justify-content: center; }
  .eye-btn {
    background: transparent;
    border: none;
    color: #8b93a7;
    cursor: pointer;
    padding: 4px;
    border-radius: 6px;
    flex-shrink: 0;
    transition: background 0.12s ease, color 0.12s ease;
  }
  .eye-btn:hover { background: rgba(255,255,255,0.08); color: #f8fafc; }
  .finding.collapsed .finding-body { display: none; }
  .finding.collapsed .finding-head { border-radius: 0; }

  .finding-body { padding: 16px 18px 18px; }

  .finding-meta {
    display: grid;
    grid-template-columns: repeat(3, 1fr);
    gap: 14px 20px;
    padding-bottom: 14px;
    margin-bottom: 14px;
    border-bottom: 1px solid rgba(255,255,255,0.06);
  }
  .mcell { min-width: 0; }
  .mcell .fval code { display: inline-block; max-width: 100%; }

  .finding-detail { display: grid; grid-template-columns: 1.3fr 1fr; gap: 20px; align-items: start; }

  @media (max-width: 720px) {
    .finding-meta { grid-template-columns: 1fr; }
    .finding-detail { grid-template-columns: 1fr; }
    .stat-grid, .sev-grid { grid-template-columns: repeat(2, 1fr); }
  }
  .flabel { font-size: 10px; text-transform: uppercase; letter-spacing: 0.06em; color: #8b93a7; margin: 10px 0 4px; }
  .flabel:first-child { margin-top: 0; }
  .fval { font-size: 12.5px; line-height: 1.5; color: #dbe1ec; }
  code { background: #0b0e17; padding: 1px 5px; border-radius: 3px; word-break: break-all; color: #e2e8f0; border: 1px solid rgba(255,255,255,0.06); font-size: 12px; }
  pre { background: #0b0e17; padding: 8px 10px; border-radius: 6px; overflow-x: auto; margin: 0; white-space: pre-wrap; word-break: break-all; color: #e2e8f0; border: 1px solid rgba(255,255,255,0.06); font-size: 12px; }
  .callout { border: 1px solid rgba(168, 85, 247, 0.3); background: rgba(168, 85, 247, 0.08); border-radius: 8px; padding: 10px 12px; }
  .callout-head { font-size: 11.5px; font-weight: 700; color: #d8b4fe; margin-bottom: 6px; }
  .callout pre { background: transparent; border: none; padding: 0; color: #e9d5ff; }

  .warn { border: 1px solid rgba(244, 63, 94, 0.35); background: rgba(244, 63, 94, 0.1); color: #fca5a5; padding: 12px 16px; border-radius: 8px; margin-bottom: 20px; font-size: 13px; }

  h2.section { font-size: 12px; text-transform: uppercase; letter-spacing: 0.08em; color: #8b93a7; margin: 32px 0 12px; }
  table.endpoints { width: 100%; border-collapse: collapse; font-size: 11.5px; margin-bottom: 12px; }
  table.endpoints th { text-align: left; color: #8b93a7; text-transform: uppercase; font-size: 10px; letter-spacing: 0.05em; padding: 8px; border-bottom: 1px solid rgba(255,255,255,0.08); }
  table.endpoints td { padding: 8px; vertical-align: top; border-bottom: 1px solid rgba(255,255,255,0.04); }
  table.endpoints td code { display: inline-block; max-width: 100%; }
  footer { margin-top: 40px; color: #64748b; font-size: 11px; text-align: center; line-height: 1.6; }
</style>
</head>
<body>
<div class="wrap">

  <div class="topbar">
    <div>
      <h1>🔍 Pentest-Style Security Audit Report</h1>
      <div class="sub">Target: <a href="${esc(scan.origin)}">${esc(scan.origin)}</a> &middot; Scan ID: ${esc(scan.id)} &middot; ${isoDate(scan.createdAt)}</div>
    </div>
  </div>

  ${scan.blockedReason ? `<div class="warn"><strong>⚠️ Scan dihentikan (Cloudflare Challenge):</strong> ${esc(scan.blockedReason)}</div>` : ""}

  <div class="summary">
    <h2>Executive Summary</h2>
    <div class="stat-grid">
      <div class="stat"><div class="n">${scan.pagesCrawled}</div><div class="l">URL Crawled</div></div>
      <div class="stat"><div class="n">${scan.jsFilesScanned}</div><div class="l">JS Scanned</div></div>
      <div class="stat"><div class="n">${secretCount}</div><div class="l">Secrets Found</div></div>
      <div class="stat"><div class="n">${cveCount}</div><div class="l">CVE Matches</div></div>
    </div>
    <div class="sev-grid">
      ${SEVERITY_ORDER.map(
        (sev) =>
          `<div class="sev" style="color:${SEVERITY_COLOR[sev]};${counts[sev] > 0 ? `background:${SEVERITY_BG[sev]};border-color:${SEVERITY_COLOR[sev]}55;` : ""}"><div class="n">${counts[sev]}</div><div class="l">${sev}</div></div>`
      ).join("")}
    </div>
    <p class="note">
      Total ${sorted.length} temuan dari ${scan.requestsMade} request (semua GET, non-destruktif, same-origin only).
      Peta relasi: ${graphNodeCount} node (page/js/endpoint), ${graphEdgeCount} edge &mdash; lihat
      <code>graph.json</code> untuk visualisasi D3.
    </p>
  </div>

  <div class="inventory">
    <h2>Finding Inventory</h2>
    ${inventoryRows || `<p style="color:#8b93a7;font-size:12.5px;">Belum ada temuan.</p>`}
  </div>

  ${findingRows || ""}

  <h2 class="section">Appendix &mdash; Link &amp; API Endpoint Ditemukan (${(scan.endpoints ?? []).length})</h2>
  ${
    (scan.endpoints ?? []).length > 0
      ? `<table class="endpoints">
    <thead><tr><th>Method</th><th>URL</th><th>Sumber</th><th>Contoh cURL</th></tr></thead>
    <tbody>${endpointRows}</tbody>
  </table>
  <p style="font-size:12px;color:#8b93a7;margin-bottom:24px;">
    Method selain GET cuma ditampilkan sebagai referensi (payload field hasil tebakan statis dari JS/form) &mdash;
    tool ini tidak pernah mengeksekusi POST/PUT/DELETE/PATCH secara otomatis. Uji manual pakai cURL di atas.
  </p>`
      : `<p style="color:#8b93a7;margin-bottom:24px;">Belum ada link/endpoint ditemukan.</p>`
  }

  <footer>
    Dihasilkan otomatis oleh Auto Security Auditor &mdash; Passive-only, same-origin, non-destruktif.<br/>
    Hanya untuk audit domain milik sendiri atau yang sudah berizin tertulis.
  </footer>
</div>
<script>
  // Toggle buka/tutup detail satu finding lewat ikon mata di header card.
  function toggleFinding(id) {
    var section = document.getElementById(id);
    if (!section) return;
    var collapsed = section.classList.toggle('collapsed');
    var btn = section.querySelector('[data-eye="' + id + '"]');
    if (btn) btn.innerHTML = collapsed ? ${JSON.stringify(EYE_CLOSED_SVG)} : ${JSON.stringify(EYE_OPEN_SVG)};
  }

  // Dipanggil dari baris Finding Inventory: pastikan card-nya kebuka lalu scroll ke situ.
  function revealFinding(id) {
    var section = document.getElementById(id);
    if (!section) return;
    if (section.classList.contains('collapsed')) {
      toggleFinding(id);
    }
    section.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
</script>
</body>
</html>`;
}