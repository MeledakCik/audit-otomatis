import type { ScanState } from "./types";

const SEVERITY_EMOJI: Record<string, string> = {
  CRITICAL: "🟥",
  HIGH: "🟧",
  MEDIUM: "🟨",
  LOW: "🟦",
  INFO: "⬜",
};

const CATEGORY_LABELS: Record<string, string> = {
  secret: "Secret",
  "outdated-library": "Outdated Library / CVE",
  generic: "Generic",
  "dom-xss-sink": "DOM XSS Sink",
  "open-redirect": "Open Redirect (kandidat)",
  ssrf: "SSRF (kandidat)",
  "idor-candidate": "IDOR (kandidat)",
  "auth-bypass": "Auth Bypass Potential",
  "missing-rate-limit": "Missing Rate Limit",
  "passive-discovery": "Passive Discovery",
};

function isoDate(ts: number): string {
  return new Date(ts).toISOString().slice(0, 19).replace("T", " ");
}
export function exportScanToObsidianMarkdown(scan: ScanState): string {
  const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
  const sorted = [...scan.findings].sort(
    (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
  );

  const counts = severityOrder.reduce<Record<string, number>>((acc, sev) => {
    acc[sev] = scan.findings.filter((f) => f.severity === sev).length;
    return acc;
  }, {});

  const lines: string[] = [];

  lines.push("---");
  lines.push(`title: "Audit Report - ${scan.domain}"`);
  lines.push(`domain: "${scan.domain}"`);
  lines.push(`scan_id: "${scan.id}"`);
  lines.push(`date: ${isoDate(scan.createdAt)}`);
  lines.push(`status: ${scan.status}`);
  lines.push(`tags: [security-audit, auto-security-auditor, "${scan.domain}"]`);
  lines.push("---");
  lines.push("");
  lines.push(`# 🔍 Audit Report — ${scan.domain}`);
  lines.push("");
  lines.push(`> [!info] Ringkasan`);
  lines.push(`> - Origin: ${scan.origin}`);
  lines.push(`> - Waktu scan: ${isoDate(scan.createdAt)}`);
  lines.push(`> - Total request terpakai: ${scan.requestsMade}`);
  lines.push(`> - Endpoint diuji: ${scan.endpointsDiscovered}`);
  lines.push(`> - Status: ${scan.status}`);
  lines.push("");
  lines.push("## Ringkasan Severity");
  lines.push("");
  lines.push("| Severity | Jumlah |");
  lines.push("|---|---|");
  for (const sev of severityOrder) {
    lines.push(`| ${SEVERITY_EMOJI[sev]} ${sev} | ${counts[sev]} |`);
  }
  lines.push("");

  const categoryCounts = scan.findings.reduce<Record<string, number>>((acc, f) => {
    const key = f.category ?? "generic";
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {});
  const categoryKeys = Object.keys(categoryCounts);
  if (categoryKeys.length > 0) {
    lines.push("## Ringkasan Kategori (termasuk hasil Deep Passive Audit)");
    lines.push("");
    lines.push("| Kategori | Jumlah |");
    lines.push("|---|---|");
    for (const key of categoryKeys.sort((a, b) => categoryCounts[b] - categoryCounts[a])) {
      lines.push(`| ${CATEGORY_LABELS[key] ?? key} | ${categoryCounts[key]} |`);
    }
    lines.push("");
    lines.push(
      "> Kategori kandidat (Open Redirect/SSRF/IDOR) adalah hasil analisis pola URL — belum dieksekusi, perlu verifikasi manual sebelum dianggap kerentanan nyata."
    );
    lines.push("");
  }

  if (scan.blockedReason) {
    lines.push("## ⚠️ Scan Diblokir");
    lines.push("");
    lines.push(scan.blockedReason);
    lines.push("");
  }

  lines.push("## Tabel Temuan");
  lines.push("");
  lines.push("| Severity | Judul | Endpoint |");
  lines.push("|---|---|---|");
  for (const f of sorted) {
    lines.push(
      `| ${SEVERITY_EMOJI[f.severity]} ${f.severity} | ${f.title} | \`${f.endpoint}\` |`
    );
  }
  lines.push("");

  if (scan.endpoints.length > 0) {
    lines.push("## Link & Endpoint Ditemukan");
    lines.push("");
    lines.push(`> Total ${scan.endpoints.length} link/endpoint (crawl link, form, endpoint dari JS). Method GET/POST apa adanya sesuai yang terdeteksi di source — request aktual yang dikirim scanner tetap GET-only (passive scan).`);
    lines.push("");
    lines.push("| Method | URL | Payload | Sumber |");
    lines.push("|---|---|---|---|");
    for (const ep of scan.endpoints) {
      lines.push(
        `| ${ep.method} | \`${ep.url}\` | ${ep.payload && ep.payload.length > 0 ? "`" + ep.payload.join(", ") + "`" : "-"} | ${ep.source} |`
      );
    }
    lines.push("");
  }

  lines.push("## Detail Temuan");
  lines.push("");
  for (const f of sorted) {
    lines.push(`### ${SEVERITY_EMOJI[f.severity]} [${f.severity}] ${f.title}`);
    lines.push("");
    lines.push(`- **Endpoint**: \`${f.endpoint}\``);
    if (f.category) lines.push(`- **Kategori**: ${CATEGORY_LABELS[f.category] ?? f.category}`);
    lines.push(`- **Bukti**: ${f.evidence}`);
    if (typeof f.cvss === "number") {
      lines.push(`- **CVSS**: ${f.cvss.toFixed(1)}${f.cwe ? ` (${f.cwe})` : ""}`);
    }
    lines.push(`- **Dampak**: ${f.impact}`);
    if (f.poc) lines.push(`- **PoC (non-destruktif)**: \`${f.poc}\``);
    lines.push(`- **Fix**: ${f.fix}`);
    lines.push("");
    lines.push(`> [!note] Referensi`);
    lines.push(`> Lihat vault \`01-07\` untuk detail remediasi kategori ini.`);
    lines.push("");
    lines.push("---");
    lines.push("");
  }

  lines.push("## Log Aktivitas Scan");
  lines.push("");
  lines.push("```");
  for (const l of scan.logs) {
    if (l.type === "log" || l.type === "status" || l.type === "blocked" || l.type === "error") {
      lines.push(`[${isoDate(l.timestamp)}] ${l.type.toUpperCase()}: ${l.message ?? l.status ?? ""}`);
    }
  }
  lines.push("```");
  lines.push("");
  lines.push("---");
  lines.push(`*Dihasilkan otomatis oleh Auto Security Auditor. Hanya untuk domain milik sendiri / berizin.*`);

  return lines.join("\n");
}
