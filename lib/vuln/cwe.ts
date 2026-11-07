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
  "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
  "CWE-125": "Out-of-bounds Read",
  "CWE-200": "Exposure of Sensitive Information",
  "CWE-209": "Error Message Containing Sensitive Information",
  "CWE-215": "Sensitive Information in Debugging Code",
  "CWE-284": "Improper Access Control",
  "CWE-287": "Improper Authentication",
  "CWE-306": "Missing Authentication for Critical Function",
  "CWE-307": "Improper Restriction of Excessive Authentication Attempts",
  "CWE-319": "Cleartext Transmission of Sensitive Information",
  "CWE-352": "Cross-Site Request Forgery (CSRF)",
  "CWE-400": "Uncontrolled Resource Consumption",
  "CWE-416": "Use After Free",
  "CWE-434": "Unrestricted Upload of File with Dangerous Type",
  "CWE-444": "HTTP Request Smuggling",
  "CWE-489": "Active Debug Code",
  "CWE-502": "Deserialization of Untrusted Data",
  "CWE-527": "Exposure of Version-Control Repository",
  "CWE-530": "Exposure of Backup File",
  "CWE-532": "Sensitive Information in Log File",
  "CWE-538": "Insertion of Sensitive Information into Externally-Accessible File or Directory",
  "CWE-548": "Exposure of Information Through Directory Listing",
  "CWE-601": "URL Redirection to Untrusted Site (Open Redirect)",
  "CWE-611": "Improper Restriction of XML External Entity Reference (XXE)",
  "CWE-614": "Sensitive Cookie in HTTPS Session Without 'Secure' Attribute",
  "CWE-639": "Authorization Bypass Through User-Controlled Key (IDOR)",
  "CWE-693": "Protection Mechanism Failure",
  "CWE-770": "Allocation of Resources Without Limits or Throttling",
  "CWE-787": "Out-of-bounds Write",
  "CWE-788": "Access of Memory Location After End of Buffer",
  "CWE-798": "Use of Hard-coded Credentials",
  "CWE-799": "Improper Control of Interaction Frequency",
  "CWE-863": "Incorrect Authorization",
  "CWE-915": "Improperly Controlled Modification of Dynamically-Determined Object Attributes",
  "CWE-917": "Expression Language Injection",
  "CWE-918": "Server-Side Request Forgery (SSRF)",
  "CWE-942": "Permissive Cross-domain Policy",
  "CWE-1021": "Improper Restriction of Rendered UI Layers (Clickjacking)",
  "CWE-1321": "Improperly Controlled Modification of Object Prototype Attributes (Prototype Pollution)",
  "CWE-1333": "Inefficient Regular Expression Complexity (ReDoS)",
  "CWE-1395": "Dependency on Vulnerable Third-Party Component",
};

/** CWE yang secara definisi mengarah ke eksekusi kode / perintah dari jarak jauh atau korupsi memori kritis. */
export const RCE_CWES = new Set([
  "CWE-77",
  "CWE-78",
  "CWE-94",
  "CWE-95",
  "CWE-96",
  "CWE-98",
  "CWE-119",
  "CWE-416",
  "CWE-434",
  "CWE-502",
  "CWE-787",
  "CWE-917",
  "CWE-1321",
]);

export const RCE_TEXT =
  /remote code execution|arbitrary (?:code|command)s? execution|execute arbitrary (?:code|commands?|php|os)|(?:os )?command injection|code injection|out-of-bounds write|prototype pollution|\bRCE\b/i;

export const cweName = (id: string) => CWE_NAMES[id] ?? "";
export const normalizeCwe = (x: string) =>
  /^CWE-\d+$/i.test(x) ? x.toUpperCase() : /^\d+$/.test(x) ? `CWE-${x}` : "";

const TITLE_RULES: Array<[RegExp, string]> = [
  [/wp2shell|wordpress|wp-config|xmlrpc|wp-json/i, "CWE-284"],
  [/php2shell|phpunit|eval-stdin|ignition|phpinfo|fpm-status/i, "CWE-94"],
  [/node2shell|v8 inspector|child_process|prototype pollution/i, "CWE-94"],
  [/go2shell|pprof|expvar/i, "CWE-215"],
  [/py2shell|werkzeug|jupyter|celery|django debug/i, "CWE-489"],
  [/out-of-bounds|out of bound|node-oob|allocUnsafe|heapdump/i, "CWE-119"],
  [/\.git\b|git (?:remote|repository|config)/i, "CWE-527"],
  [/\.env|wp-config|config file|sftp-config|docker-compose/i, "CWE-538"],
  [/backup|\.sql|dump\.sql|\.zip/i, "CWE-530"],
  [/aws|credentials|secret|api[ _-]?key|private key|id_rsa/i, "CWE-798"],
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
  wp2shell: "CWE-434",
  php2shell: "CWE-94",
  node2shell: "CWE-94",
  go2shell: "CWE-215",
  py2shell: "CWE-489",
  "node-oob": "CWE-119",
  webshell: "CWE-434",
  "filemanager-shell": "CWE-434",
  "sensitive-file": "CWE-538",
};

/** Beri tag CWE ke temuan lama yang belum punya (heuristik pada kategori/judul). */
export function withCwe(f: Finding): Finding {
  if (f.cwe) return f;
  const byCat = f.category ? CATEGORY_RULES[f.category] : undefined;
  const byTitle = TITLE_RULES.find(([re]) => re.test(f.title))?.[1];
  const cwe = byCat ?? byTitle;
  return cwe ? { ...f, cwe } : f;
}
