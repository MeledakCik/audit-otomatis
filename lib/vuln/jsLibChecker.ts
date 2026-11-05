/**
 * lib/vuln/jsLibChecker.ts
 *
 * "Retire.js lite": deteksi versi library JS/Node dari raw bundle text (banner
 * comment / minified marker string) lalu cocokkan ke local vuln DB termasuk
 * kerentanan Prototype Pollution (node2shell), Out-of-Bounds / ReDoS (node-oob), dan XSS/RCE.
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

const VULN_DB: Record<string, VulnRule[]> = {
  jquery: [
    { below: "3.5.0", cve: "CVE-2020-11022 XSS via jQuery.htmlPrefilter", severity: "medium" },
    { below: "3.4.0", cve: "CVE-2019-11358 prototype pollution in jQuery.extend (node2shell/DOM)", severity: "high" },
    { below: "1.9.0", cve: "CVE-2015-9251 XSS via cross-domain ajax", severity: "medium" },
  ],
  lodash: [
    { below: "4.17.21", cve: "CVE-2021-23337 Command Injection via template() (node2shell RCE)", severity: "high" },
    { below: "4.17.12", cve: "CVE-2019-10744 prototype pollution in _.defaultsDeep (node2shell)", severity: "high" },
    { below: "4.17.11", cve: "CVE-2018-16487 prototype pollution in _.merge/_.mergeWith", severity: "high" },
  ],
  moment: [{ below: "2.29.4", cve: "CVE-2022-31129 ReDoS & path traversal in moment locale", severity: "medium" }],
  bootstrap: [
    { below: "4.3.1", cve: "CVE-2019-8331 XSS via data-template/data-content in tooltip/popover", severity: "medium" },
  ],
  angular: [
    { below: "1.8.0", cve: "CVE-2020-7676 XSS bypass via angular.element", severity: "high" },
  ],
  handlebars: [
    { below: "4.7.7", cve: "CVE-2021-23369 Remote Code Execution via prototype pollution in Handlebars (node2shell)", severity: "high" },
  ],
  axios: [
    { below: "1.6.0", cve: "CVE-2023-45857 CSRF / XSRF-TOKEN leakage & SSRF/OOB exposure", severity: "high" },
  ],
  underscore: [
    { below: "1.13.6", cve: "CVE-2021-23358 Arbitrary Code Execution via template() (node2shell)", severity: "high" },
  ],
};

const VERSION_PATTERNS: { library: string; regex: RegExp }[] = [
  { library: "jquery", regex: /jQuery\s+(?:JavaScript Library\s+)?v?([0-9]+\.[0-9]+\.[0-9]+)/i },
  { library: "jquery", regex: /jquery[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js/i },
  { library: "lodash", regex: /lodash(?:\.js)?\s+v?([0-9]+\.[0-9]+\.[0-9]+)/i },
  { library: "lodash", regex: /lodash@([0-9]+\.[0-9]+\.[0-9]+)/i },
  { library: "moment", regex: /moment\.js\s+v?([0-9]+\.[0-9]+\.[0-9]+)/i },
  { library: "bootstrap", regex: /Bootstrap\s+v([0-9]+\.[0-9]+\.[0-9]+)/i },
  { library: "angular", regex: /angular[.-]([0-9]+\.[0-9]+\.[0-9]+)(?:\.min)?\.js/i },
  { library: "handlebars", regex: /Handlebars(?:\.VERSION\s*=\s*["']|\s+v)([0-9]+\.[0-9]+\.[0-9]+)/i },
  { library: "axios", regex: /axios\/([0-9]+\.[0-9]+\.[0-9]+)/i },
  { library: "underscore", regex: /Underscore\.js\s+([0-9]+\.[0-9]+\.[0-9]+)/i },
];

function parseVersion(v: string): number[] {
  return v.split(".").map((n) => parseInt(n, 10) || 0);
}

function isVersionBelow(version: string, bound: string): boolean {
  const a = parseVersion(version);
  const b = parseVersion(bound);
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const ai = a[i] ?? 0;
    const bi = b[i] ?? 0;
    if (ai !== bi) return ai < bi;
  }
  return false;
}

export function checkVulnerableLibs(jsContent: string): Vuln[] {
  if (!jsContent) return [];
  const results: Vuln[] = [];
  const detectedVersions: Record<string, string> = {};

  for (const { library, regex } of VERSION_PATTERNS) {
    if (detectedVersions[library]) continue;
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
