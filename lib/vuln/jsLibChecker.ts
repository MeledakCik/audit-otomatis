/**
 * lib/vuln/jsLibChecker.ts
 *
 * "Retire.js lite": deteksi versi library JS dari raw bundle text (banner
 * comment / minified marker string) lalu cocokkan ke local vuln DB.
 * Ini heuristik murni string-matching, jadi false-negative wajar kalau versi
 * marker-nya sudah di-strip habis oleh minifier — cukup buat quick win.
 *
 * Pure function, tanpa network call.
 */

import type { AuditFinding, AuditSeverity } from "./types";

export interface Vuln extends AuditFinding {
  library: string;
  versionFound: string;
  cve: string;
}

interface VulnRule {
  /** versi < below dianggap vulnerable */
  below: string;
  cve: string;
  severity: AuditSeverity;
}

// Local DB, gampang di-extend. Format: libraryKey -> daftar rule "below version".
const VULN_DB: Record<string, VulnRule[]> = {
  jquery: [
    { below: "3.5.0", cve: "CVE-2020-11022 XSS via jQuery.htmlPrefilter", severity: "medium" },
    { below: "3.4.0", cve: "CVE-2019-11358 prototype pollution in jQuery.extend", severity: "high" },
    { below: "1.9.0", cve: "CVE-2015-9251 XSS via cross-domain ajax", severity: "medium" },
  ],
  lodash: [
    { below: "4.17.12", cve: "CVE-2019-10744 prototype pollution in _.defaultsDeep", severity: "high" },
    { below: "4.17.11", cve: "CVE-2018-16487 prototype pollution in _.merge/_.mergeWith", severity: "high" },
  ],
  moment: [{ below: "2.29.4", cve: "CVE-2022-31129 ReDoS in moment parsing", severity: "medium" }],
  bootstrap: [
    { below: "4.3.1", cve: "CVE-2019-8331 XSS via data-template/data-content in tooltip/popover", severity: "medium" },
  ],
  angular: [{ below: "1.8.0", cve: "CVE-2020-7676 XSS bypass via angular.element", severity: "high" },
  ],
};

// Regex untuk narik versi dari banner/minified marker string di dalam bundle.
const VERSION_PATTERNS: { library: string; regex: RegExp }[] = [
  { library: "jquery", regex: /jQuery\s+(?:JavaScript Library\s+)?v?([0-9]+\.[0-9]+\.[0-9]+)/i },
  { library: "jquery", regex: /jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js/i },
  { library: "lodash", regex: /lodash(?:\.js)?\s+v?([0-9]+\.[0-9]+\.[0-9]+)/i },
  { library: "lodash", regex: /lodash@([0-9]+\.[0-9]+\.[0-9]+)/i },
  { library: "moment", regex: /moment\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)/i },
  { library: "bootstrap", regex: /Bootstrap\s+v([0-9]+\.[0-9]+\.[0-9]+)/i },
  { library: "angular", regex: /angular[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js/i },
];

function parseVersion(v: string): number[] {
  return v.split(".").map((n) => parseInt(n, 10) || 0);
}

/** true kalau `version` < `bound`, pakai perbandingan numerik per-segmen (bukan string compare). */
function isVersionBelow(version: string, bound: string): boolean {
  const a = parseVersion(version);
  const b = parseVersion(bound);
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const ai = a[i] ?? 0;
    const bi = b[i] ?? 0;
    if (ai !== bi) return ai < bi;
  }
  return false; // equal
}

/**
 * Deteksi versi library dari raw JS text (banner/minified marker), lalu
 * cocokkan ke VULN_DB lokal. Return daftar Vuln, satu per rule yang match.
 */
export function checkVulnerableLibs(jsContent: string): Vuln[] {
  if (!jsContent) return [];
  const results: Vuln[] = [];
  const detectedVersions: Record<string, string> = {};

  for (const { library, regex } of VERSION_PATTERNS) {
    if (detectedVersions[library]) continue; // sudah ketemu versi utk lib ini, skip pattern lain
    const m = regex.exec(jsContent);
    if (m && m[1]) detectedVersions[library] = m[1];
  }

  for (const [library, version] of Object.entries(detectedVersions)) {
    const rules = VULN_DB[library];
    if (!rules) continue;
    for (const rule of rules) {
      if (isVersionBelow(version, rule.below)) {
        results.push({
          type: "VULNERABLE_LIBRARY",
          severity: rule.severity,
          evidence: `${library}@${version} matched by rule "<${rule.below}"`,
          library,
          versionFound: version,
          cve: rule.cve,
        });
      }
    }
  }

  return results;
}
