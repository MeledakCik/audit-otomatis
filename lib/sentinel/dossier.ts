// Pure (tanpa import node) → dipakai server (menyusun) dan client admin (ekspor laporan).
import type { Severity } from "@/lib/types";
import { cweName } from "@/lib/vuln/cwe";

export interface Component {
  name: string;
  version: string;
  kind: "npm" | "cpe";
  cpe?: { vendor: string; product: string };
  source: string;   // URL/halaman asal deteksi
  evidence: string; // nilai header / banner yang dipakai (hanya admin)
}

export interface CveHit {
  id: string; // CVE-xxxx-yyyy (atau GHSA bila belum ada CVE)
  source: "osv" | "nvd";
  severity: Severity;
  cvss?: number;
  cwe: string[];
  summary: string;
  rce: boolean;
  refs: string[];
  component: string;
  versionFound: string;
  published?: string;
}

export interface RceSurfaceEvidence {
  path: string;
  title: string;
  severity: Severity;
  cwe: string[];
  cve: string[];
  status: number;
  marker: string;
  snippet: string; // ≤300 char, HANYA admin
}

export interface CveDossier {
  version: 1;
  domain: string;
  origin: string;
  generatedAt: number;
  summary: {
    components: number;
    cveTotal: number;
    rcePotential: number;
    rceSurface: number;
    bySeverity: Record<string, number>;
    cweTop: Array<{ cwe: string; name: string; count: number }>;
  };
  components: Component[];
  cves: CveHit[];
  rceSurface: RceSurfaceEvidence[];
  findingsOverview: Array<{ severity: string; title: string; endpoint: string; cwe?: string }>;
  caveats: string[];
}

const SEV_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function buildDossier(input: {
  domain: string;
  origin: string;
  components: Component[];
  hits: CveHit[];
  rceSurface: RceSurfaceEvidence[];
  findings: Array<{ severity: string; title: string; endpoint: string; cwe?: string }>;
}): CveDossier {
  const bySeverity: Record<string, number> = {};
  const cweCount = new Map<string, number>();
  for (const h of input.hits) {
    bySeverity[h.severity] = (bySeverity[h.severity] ?? 0) + 1;
    for (const c of h.cwe) cweCount.set(c, (cweCount.get(c) ?? 0) + 1);
  }
  for (const r of input.rceSurface) for (const c of r.cwe) cweCount.set(c, (cweCount.get(c) ?? 0) + 1);

  return {
    version: 1,
    domain: input.domain,
    origin: input.origin,
    generatedAt: Date.now(),
    summary: {
      components: input.components.length,
      cveTotal: input.hits.length,
      rcePotential: input.hits.filter((h) => h.rce).length,
      rceSurface: input.rceSurface.length,
      bySeverity,
      cweTop: [...cweCount.entries()]
        .sort((a, b) => b[1] - a[1])
        .slice(0, 10)
        .map(([cwe, count]) => ({ cwe, name: cweName(cwe), count })),
    },
    components: input.components,
    cves: [...input.hits].sort(
      (a, b) =>
        Number(b.rce) - Number(a.rce) ||
        SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity) ||
        (b.cvss ?? 0) - (a.cvss ?? 0)
    ),
    rceSurface: input.rceSurface,
    findingsOverview: input.findings.slice(0, 200),
    caveats: [
      "Seluruh temuan dihasilkan oleh pengecekan PASIF (GET-only). Tidak ada payload eksploitasi yang dikirim ke target.",
      "Kecocokan CVE didasarkan pada VERSI yang terdeteksi. Distro/vendor sering melakukan backport patch tanpa mengubah nomor versi, sehingga hasil dapat berupa false positive. Verifikasi manual diperlukan sebelum pelaporan.",
      "Label 'potensi RCE' berasal dari klasifikasi CWE/deskripsi CVE, bukan bukti bahwa RCE berhasil dieksploitasi.",
    ],
  };
}

const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");

/** Laporan Markdown untuk admin. Sengaja TIDAK menyertakan snippet/evidence mentah. */
export function dossierToMarkdown(d: CveDossier): string {
  const L: string[] = [];
  const date = new Date(d.generatedAt).toISOString();
  L.push(`# Laporan Temuan Kerentanan (Pasif) — ${d.domain}`, "");
  L.push(`- **Target:** ${d.origin}`, `- **Dibuat:** ${date}`, `- **Metode:** pasif (GET-only), pencocokan versi ke OSV.dev / NVD`);
  L.push(`- **Diverifikasi oleh:** ______________________ (nama / instansi)`);
  L.push(`- **Dilaporkan kepada:** ______________________ (mis. BSSN / CSIRT terkait)`, "");

  L.push("## Ringkasan", "");
  L.push(`| Komponen terdeteksi | CVE cocok | Potensi RCE | Endpoint rawan RCE |`, `|---|---|---|---|`);
  L.push(`| ${d.summary.components} | ${d.summary.cveTotal} | ${d.summary.rcePotential} | ${d.summary.rceSurface} |`, "");
  const sev = Object.entries(d.summary.bySeverity).map(([k, v]) => `${k}: ${v}`).join(" · ");
  if (sev) L.push(`Sebaran severity CVE: ${sev}`, "");

  if (d.rceSurface.length) {
    L.push("## Endpoint rawan RCE yang terbuka (terverifikasi dari isi respons)", "");
    L.push("| Path | Temuan | Severity | CWE | CVE |", "|---|---|---|---|---|");
    for (const r of d.rceSurface)
      L.push(`| \`${esc(r.path)}\` | ${esc(r.title)} | ${r.severity} | ${r.cwe.join(", ") || "-"} | ${r.cve.join(", ") || "-"} |`);
    L.push("");
  }

  if (d.cves.length) {
    L.push("## CVE yang cocok dengan versi terdeteksi", "");
    L.push("| CVE | Komponen | Versi | Severity | CVSS | CWE | RCE? |", "|---|---|---|---|---|---|---|");
    for (const h of d.cves)
      L.push(`| ${h.id} | ${esc(h.component)} | ${esc(h.versionFound)} | ${h.severity} | ${h.cvss ?? "-"} | ${h.cwe.join(", ") || "-"} | ${h.rce ? "potensi" : "-"} |`);
    L.push("");
    L.push("### Rincian", "");
    for (const h of d.cves.slice(0, 40)) {
      L.push(`**${h.id}** — ${esc(h.component)} ${esc(h.versionFound)} (${h.severity}${h.cvss ? `, CVSS ${h.cvss}` : ""})`);
      L.push(`${esc(h.summary)}`);
      if (h.refs[0]) L.push(`Referensi: ${h.refs.slice(0, 3).join(" · ")}`);
      L.push("");
    }
  }

  if (d.summary.cweTop.length) {
    L.push("## Kategori kelemahan (CWE)", "");
    for (const c of d.summary.cweTop) L.push(`- ${c.cwe}${c.name ? ` — ${c.name}` : ""} (${c.count})`);
    L.push("");
  }

  L.push("## Catatan & batasan", "");
  for (const c of d.caveats) L.push(`- ${c}`);
  L.push("", "## Rekomendasi umum", "");
  L.push("- Perbarui komponen yang rentan ke versi ter-patch, lalu verifikasi ulang.", "- Matikan debug/diagnostic endpoint di production atau batasi ke jaringan internal.", "- Rotasi kredensial yang mungkin terekspos.");
  L.push("", "> Bukti rinci (header/banner/potongan respons) tersimpan terenkripsi di Sentinel Vault dan tidak disertakan di dokumen ini.");
  return L.join("\n");
}
