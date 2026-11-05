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

if (fixedCount > 0) {
  console.log(`[resolve-conflicts] Resolved merge conflicts in ${fixedCount} file(s).`);
}
