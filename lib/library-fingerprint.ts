import type { Finding, LibraryDetection, Severity } from "./types";


interface CveEntry {
  library: string;
  maxAffectedVersion: string; // versi < ini dianggap rentan
  cve: string;
  severity: Severity;
  cvss: number;
  cweId: string;
  description: string;
  url: string;
}

const CVE_TABLE: CveEntry[] = [
  {
    library: "jquery",
    maxAffectedVersion: "3.5.0",
    cve: "CVE-2020-11022",
    severity: "HIGH",
    cvss: 6.1,
    cweId: "CWE-79",
    description:
      "jQuery < 3.5.0 rentan XSS: passing HTML yang mengandung <option> ke method DOM manipulation (mis. .html()) bisa mengeksekusi kode tanpa sanitasi.",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2020-11022",
  },
  {
    library: "jquery",
    maxAffectedVersion: "3.5.0",
    cve: "CVE-2020-11023",
    severity: "HIGH",
    cvss: 6.1,
    cweId: "CWE-79",
    description: "jQuery < 3.5.0 rentan XSS serupa lewat option elements yang dibuat dari string HTML tidak terpercaya.",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2020-11023",
  },
  {
    library: "jquery",
    maxAffectedVersion: "3.0.0",
    cve: "CVE-2015-9251",
    severity: "MEDIUM",
    cvss: 5.4,
    cweId: "CWE-79",
    description: "jQuery < 3.0.0 rentan XSS lewat cross-domain Ajax request yang mengembalikan JSON yang di-load sebagai HTML.",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2015-9251",
  },
  {
    library: "lodash",
    maxAffectedVersion: "4.17.21",
    cve: "CVE-2020-28500",
    severity: "MEDIUM",
    cvss: 5.3,
    cweId: "CWE-1333",
    description: "lodash < 4.17.21 rentan ReDoS (Regular Expression Denial of Service) lewat fungsi trim/pad pada string yang panjang.",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2020-28500",
  },
  {
    library: "lodash",
    maxAffectedVersion: "4.17.12",
    cve: "CVE-2019-10744",
    severity: "CRITICAL",
    cvss: 9.1,
    cweId: "CWE-1321",
    description: "lodash < 4.17.12 rentan Prototype Pollution lewat fungsi defaultsDeep.",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2019-10744",
  },
  {
    library: "moment",
    maxAffectedVersion: "2.29.4",
    cve: "CVE-2022-31129",
    severity: "HIGH",
    cvss: 7.5,
    cweId: "CWE-1333",
    description: "moment.js < 2.29.4 rentan ReDoS lewat parsing string tanggal dengan format tertentu.",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2022-31129",
  },
  {
    library: "axios",
    maxAffectedVersion: "0.21.2",
    cve: "CVE-2021-3749",
    severity: "MEDIUM",
    cvss: 5.3,
    cweId: "CWE-1333",
    description: "axios < 0.21.2 rentan ReDoS lewat regex trim pada header.",
    url: "https://nvd.nist.gov/vuln/detail/CVE-2021-3749",
  },
];

function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map((n) => parseInt(n, 10) || 0);
  const pb = b.split(".").map((n) => parseInt(n, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (diff !== 0) return diff;
  }
  return 0;
}

interface FingerprintRule {
  library: string;
  patterns: RegExp[];
}

const FINGERPRINT_RULES: FingerprintRule[] = [
  {
    library: "jquery",
    patterns: [/jQuery\s+v?([0-9]+\.[0-9]+\.[0-9]+)/, /jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js/i],
  },
  {
    library: "lodash",
    patterns: [/lodash\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)/, /lodash@([0-9]+\.[0-9]+\.[0-9]+)/],
  },
  {
    library: "moment",
    patterns: [/moment\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)/, /moment@([0-9]+\.[0-9]+\.[0-9]+)/],
  },
  {
    library: "axios",
    patterns: [/axios@([0-9]+\.[0-9]+\.[0-9]+)/],
  },
  {
    library: "react",
    patterns: [/React\s+v?([0-9]+\.[0-9]+\.[0-9]+)/],
  },
];
export function fingerprintLibraries(source: string, sourceLabel: string): LibraryDetection[] {
  const detections: LibraryDetection[] = [];
  const seen = new Set<string>();

  for (const rule of FINGERPRINT_RULES) {
    for (const pattern of rule.patterns) {
      const match = pattern.exec(source);
      if (!match || !match[1]) continue;
      const key = `${rule.library}@${match[1]}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const cveMatch = CVE_TABLE.filter(
        (c) => c.library === rule.library && compareVersions(match[1], c.maxAffectedVersion) < 0
      ).sort((a, b) => compareVersions(b.maxAffectedVersion, a.maxAffectedVersion))[0];

      detections.push({
        name: rule.library,
        version: match[1],
        source: sourceLabel,
        cve: cveMatch?.cve,
        cveSeverity: cveMatch?.severity,
        cveUrl: cveMatch?.url,
      });
    }
  }

  return detections;
}
export function detectNextJs(scriptUrls: string[]): boolean {
  return scriptUrls.some((u) => u.includes("/_next/static/"));
}

function newId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}
export function libraryDetectionsToFindings(detections: LibraryDetection[]): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  for (const d of detections) {
    if (!d.cve || !d.cveSeverity) continue;
    const key = `${d.name}:${d.cve}`;
    if (seen.has(key)) continue;
    seen.add(key);

    const entry = CVE_TABLE.find((c) => c.cve === d.cve);
    findings.push({
      id: newId(),
      severity: d.cveSeverity,
      title: `Library jadul terdeteksi: ${d.name} v${d.version} (${d.cve})`,
      endpoint: d.source,
      evidence: `Fingerprint versi ${d.name} v${d.version} ditemukan di ${d.source}.`,
      impact: entry?.description ?? "Versi library ini memiliki CVE publik yang diketahui.",
      fix: `Upgrade ${d.name} ke versi terbaru (di atas ${entry?.maxAffectedVersion ?? "versi rentan"}). Lihat advisory resmi sebelum upgrade untuk breaking changes.`,
      cvss: entry?.cvss,
      cwe: entry?.cweId,
      poc: entry?.url ? `Referensi: ${entry.url} (passive fingerprint saja, tidak ada exploit yang dijalankan)` : undefined,
      category: "outdated-library",
    });
  }

  return findings;
}
