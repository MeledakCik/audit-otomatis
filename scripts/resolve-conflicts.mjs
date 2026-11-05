import fs from "node:fs";
import path from "node:path";

const ROOTS = ["app", "components", "lib"];
const EXTENSIONS = new Set([".ts", ".tsx", ".js", ".jsx", ".mjs", ".json", ".css", ".md"]);

// Matches Git merge conflict blocks and keeps the HEAD (top) section
const CONFLICT_RE = /^<{7}[^\r\n]*\r?\n([\s\S]*?)^={7}\r?\n[\s\S]*?^>{7}[^\r\n]*\r?\n?/gm;

function walk(dir, out = []) {
  if (!fs.existsSync(dir)) return out;
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === ".next" || entry.name === ".git") continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full, out);
    } else if (EXTENSIONS.has(path.extname(entry.name))) {
      out.push(full);
    }
  }
  return out;
}

let fixedCount = 0;
for (const root of ROOTS) {
  const files = walk(path.join(process.cwd(), root));
  for (const file of files) {
    const raw = fs.readFileSync(file, "utf8");
    if (raw.includes("<<<<<<<") && raw.includes("=======") && raw.includes(">>>>>>>")) {
      const cleaned = raw.replace(CONFLICT_RE, (_match, headPart) => headPart);
      if (cleaned !== raw) {
        fs.writeFileSync(file, cleaned, "utf8");
        fixedCount++;
        console.log(`[resolve-conflicts] Cleaned merge conflict markers in: ${path.relative(process.cwd(), file)}`);
      }
    }
  }
}

// Self-heal partial Git merges in lib/tester.ts
const testerPath = path.join(process.cwd(), "lib", "tester.ts");
if (fs.existsSync(testerPath)) {
  let t = fs.readFileSync(testerPath, "utf8");
  const orig = t;
  if (!t.includes("const head = new Uint8Array") && t.includes("head,")) {
    t = t.replace(
      /(const text = [^\r\n]+;\r?\n)/,
      "$1        const head = new Uint8Array(buf.subarray(0, 8));\n"
    );
  }
  if (t !== orig) {
    fs.writeFileSync(testerPath, t, "utf8");
    console.log("[resolve-conflicts] Repaired missing 'head' declaration in lib/tester.ts");
  }
}

// Self-heal partial Git merges in lib/sentinel/audit.ts
const auditPath = path.join(process.cwd(), "lib", "sentinel", "audit.ts");
if (fs.existsSync(auditPath)) {
  let a = fs.readFileSync(auditPath, "utf8");
  const orig = a;
  if (!a.includes("detectWafAndEdgeInfo")) {
    a = a.replace(
      /import\s*\{\s*chromeHeaders,\s*detectCloudflareChallenge\s*\}\s*from\s*["']@\/lib\/crawler["'];?/,
      'import { chromeHeaders, detectCloudflareChallenge, detectWafAndEdgeInfo } from "@/lib/crawler";'
    );
  }
  if (!a.includes("wafDetected?:")) {
    a = a.replace(
      /(export interface AuditResult\s*\{[\s\S]*?gitIntel\?:\s*GitIntelReport;\r?\n)/,
      "$1  wafDetected?: {\n    provider: string;\n    challenged: boolean;\n    cfRay?: string;\n    status: number;\n  };\n"
    );
  }
  if (!a.includes("let wafDetected") || !a.includes("const wafInfo =")) {
    a = a.replace(
      /const home = await getHome\([^)]*\);\r?\n\s*if\s*\(home\s*&&\s*home\.status[^)]*\)\s*\{/,
      `const home = await getHome(origin, cfClearance);
  let wafDetected: AuditResult["wafDetected"];
  if (home && home.status >= 200 && home.status <= 503) {
    const wafInfo = detectWafAndEdgeInfo(home.status, home.headers, home.text.slice(0, 2000));
    if (wafInfo.detected) {
      wafDetected = {
        provider: wafInfo.provider,
        challenged: wafInfo.challenged,
        cfRay: wafInfo.cfRay,
        status: home.status,
      };
    }`
    );
  }
  if (a !== orig) {
    fs.writeFileSync(auditPath, a, "utf8");
    console.log("[resolve-conflicts] Repaired 'wafInfo' and 'wafDetected' declarations in lib/sentinel/audit.ts");
  }
}

if (fixedCount > 0) {
  console.log(`[resolve-conflicts] Resolved merge conflicts in ${fixedCount} file(s).`);
}
