import type { Finding } from "@/lib/types";

/** Katalog CWE yang dipakai scanner (pure, aman dipakai di client maupun server). */
export const CWE_NAMES: Record<string, string> = {
  "CWE-20": "Improper Input Validation",
  "CWE-22": "Path Traversal",
  "CWE-77": "Command Injection",
  "CWE-78": "OS Command Injection",
  "CWE-79": "Cross-site Scripting (XSS)",
  "CWE-89": "SQL Injection",
  "CWE-94": "Code Injection",
  "CWE-95": "Eval Injection",
  "CWE-96": "Static Code Injection",
  "CWE-98": "PHP Remote File Inclusion",
  "CWE-119": "Memory Buffer Bounds Violation",
  "CWE-200": "Exposure of Sensitive Information",
  "CWE-209": "Error Message Containing Sensitive Information",
  "CWE-215": "Sensitive Information in Debugging Code",
  "CWE-287": "Improper Authentication",
  "CWE-306": "Missing Authentication for Critical Function",
  "CWE-307": "Excessive Authentication Attempts",
  "CWE-319": "Cleartext Transmission of Sensitive Information",
  "CWE-352": "Cross-Site Request Forgery (CSRF)",
  "CWE-400": "Uncontrolled Resource Consumption",
  "CWE-416": "Use After Free",
  "CWE-434": "Unrestricted Upload of Dangerous File Type",
  "CWE-444": "HTTP Request Smuggling",
  "CWE-489": "Active Debug Code",
  "CWE-502": "Deserialization of Untrusted Data",
  "CWE-527": "Exposure of Version-Control Repository",
  "CWE-530": "Exposure of Backup File",
  "CWE-532": "Sensitive Information in Log File",
  "CWE-538": "Sensitive Information in Externally-Accessible File",
  "CWE-548": "Exposure via Directory Listing",
  "CWE-601": "Open Redirect",
  "CWE-611": "XML External Entity (XXE)",
  "CWE-614": "Sensitive Cookie Without 'Secure' Attribute",
  "CWE-639": "Authorization Bypass via User-Controlled Key (IDOR)",
  "CWE-693": "Protection Mechanism Failure",
  "CWE-770": "Resource Allocation Without Limits or Throttling",
  "CWE-787": "Out-of-bounds Write",
  "CWE-798": "Use of Hard-coded Credentials",
  "CWE-799": "Improper Control of Interaction Frequency",
  "CWE-863": "Incorrect Authorization",
  "CWE-917": "Expression Language Injection",
  "CWE-918": "Server-Side Request Forgery (SSRF)",
  "CWE-942": "Permissive Cross-domain Policy",
  "CWE-1021": "Improper Restriction of Rendered UI Layers (Clickjacking)",
  "CWE-1321": "Prototype Pollution",
  "CWE-1333": "Inefficient Regular Expression (ReDoS)",
  "CWE-1395": "Dependency on Vulnerable Third-Party Component",
};

/** CWE yang secara definisi mengarah ke eksekusi kode / perintah dari jarak jauh. */
export const RCE_CWES = new Set(["CWE-77", "CWE-78", "CWE-94", "CWE-95", "CWE-96", "CWE-98", "CWE-502", "CWE-917", "CWE-434"]);

export const RCE_TEXT = /remote code execution|arbitrary (?:code|command)s? execution|execute arbitrary (?:code|commands?|php|os)|(?:os )?command injection|code injection|\bRCE\b/i;

export const cweName = (id: string) => CWE_NAMES[id] ?? "";
export const normalizeCwe = (x: string) => (/^CWE-\d+$/i.test(x) ? x.toUpperCase() : /^\d+$/.test(x) ? `CWE-${x}` : "");

const TITLE_RULES: Array<[RegExp, string]> = [
  [/\.git\b|git (?:remote|repository|config)/i, "CWE-527"],
  [/\.env|wp-config|config file/i, "CWE-538"],
  [/backup/i, "CWE-530"],
  [/aws|credentials|secret|api[ _-]?key|private key/i, "CWE-798"],
  [/hsts|strict-transport/i, "CWE-319"],
  [/x-frame|clickjack/i, "CWE-1021"],
  [/content-security|\bcsp\b/i, "CWE-693"],
  [/directory listing/i, "CWE-548"],
  [/response leakage|stack trace|error/i, "CWE-209"],
  [/anti-automation/i, "CWE-799"],
  [/swagger|api doc|phpinfo|server-status/i, "CWE-200"],
  [/cookie/i, "CWE-614"],
  [/cors/i, "CWE-942"],
];
const CATEGORY_RULES: Record<string, string> = {
  secret: "CWE-798",
  "dom-xss-sink": "CWE-79",
  "open-redirect": "CWE-601",
  ssrf: "CWE-918",
  "idor-candidate": "CWE-639",
  "auth-bypass": "CWE-306",
  "missing-rate-limit": "CWE-770",
};

/** Beri tag CWE ke temuan lama yang belum punya (heuristik pada kategori/judul). */
export function withCwe(f: Finding): Finding {
  if (f.cwe) return f;
  const byCat = f.category ? CATEGORY_RULES[f.category] : undefined;
  const byTitle = TITLE_RULES.find(([re]) => re.test(f.title))?.[1];
  const cwe = byCat ?? byTitle;
  return cwe ? { ...f, cwe } : f;
}
