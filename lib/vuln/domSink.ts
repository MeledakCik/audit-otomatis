/**
 * lib/vuln/domSink.ts
 *
 * Deteksi sink berbahaya di raw JS/TS bundle text secara pasif (tanpa network call):
 * 1. DOM XSS sinks (innerHTML, outerHTML, document.write, eval, setTimeout string, location.hash/search)
 * 2. node2shell sinks (child_process.exec/spawn, vm.runInNewContext, deserialization unserialize/node-serialize, prototype pollution __proto__)
 * 3. node-oob (Node Out-of-Bounds / Memory Buffer sinks: Buffer.allocUnsafe, new Buffer(), DataView/TypedArray unchecked byteOffset)
 * 4. wp2shell / php2shell client-side bridge indicators (wp_ajax_nopriv dynamic action / admin-ajax.php)
 */

import type { AuditFinding, AuditSeverity } from "./types";

export type SinkType =
  | "innerHTML"
  | "outerHTML"
  | "document.write"
  | "eval"
  | "setTimeout_string"
  | "location.hash"
  | "location.search"
  | "node2shell_child_process"
  | "node2shell_vm_eval"
  | "node2shell_deserialization"
  | "node2shell_prototype_pollution"
  | "node_oob_buffer"
  | "wp2shell_admin_ajax";

export interface Sink extends AuditFinding {
  type: SinkType;
  line: number;
  snippet: string;
}

interface SinkPatternDef {
  type: SinkType;
  regex: RegExp;
  severity: AuditSeverity;
}

const SINK_PATTERNS: SinkPatternDef[] = [
  { type: "innerHTML", regex: /\.innerHTML\s*=/g, severity: "medium" },
  { type: "outerHTML", regex: /\.outerHTML\s*=/g, severity: "medium" },
  { type: "document.write", regex: /\bdocument\.write(?:ln)?\s*\(/g, severity: "high" },
  { type: "eval", regex: /\beval\s*\(/g, severity: "high" },
  {
    type: "setTimeout_string",
    regex: /\bset(?:Timeout|Interval)\s*\(\s*(?:`[^`]*`|'[^']*'|"[^"]*")/g,
    severity: "high",
  },
  { type: "location.hash", regex: /\blocation\.hash\b/g, severity: "medium" },
  { type: "location.search", regex: /\blocation\.search\b/g, severity: "medium" },
  // node2shell — Node.js command execution / VM / deserialization / prototype pollution sinks
  {
    type: "node2shell_child_process",
    regex: /\b(?:child_process|execSync|spawnSync|execFile)\b|\.\s*(?:exec|spawn)\s*\(/g,
    severity: "high",
  },
  {
    type: "node2shell_vm_eval",
    regex: /\bvm\.runIn(?:New|This)?Context\s*\(|\bnew\s+Function\s*\(/g,
    severity: "high",
  },
  {
    type: "node2shell_deserialization",
    regex: /\b(?:node-serialize|serialize-javascript)\b|\.\s*unserialize\s*\(/g,
    severity: "high",
  },
  {
    type: "node2shell_prototype_pollution",
    regex: /\b__proto__\b|\[['"]__proto__['"]\]|\[['"]prototype['"]\]/g,
    severity: "medium",
  },
  // node-oob — Node.js Out-of-Bounds / Unsafe Memory Buffer allocation
  {
    type: "node_oob_buffer",
    regex: /\bBuffer\.allocUnsafe(?:Slow)?\s*\(|\bnew\s+Buffer\s*\(\s*\d+|\bDataView\s*\([^)]*byteOffset/g,
    severity: "high",
  },
  // wp2shell — WordPress unauthenticated AJAX / dynamic plugin action sink
  {
    type: "wp2shell_admin_ajax",
    regex: /\/wp-admin\/admin-ajax\.php\b|\bwp_ajax_nopriv_[a-zA-Z0-9_]+/g,
    severity: "medium",
  },
];

function lineNumberAt(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content.charCodeAt(i) === 10) line++;
  }
  return line;
}

function snippetAround(content: string, index: number, radius = 40): string {
  const start = Math.max(0, index - radius);
  const end = Math.min(content.length, index + radius);
  const raw = content.slice(start, end).replace(/\s+/g, " ").trim();
  return (start > 0 ? "…" : "") + raw + (end < content.length ? "…" : "");
}

/**
 * Cari sink DOM-XSS, node2shell, node-oob buffer, dan wp2shell AJAX di raw JS text.
 */
export function findDomSinks(jsContent: string): Sink[] {
  if (!jsContent) return [];
  const results: Sink[] = [];

  for (const { type, regex, severity } of SINK_PATTERNS) {
    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(jsContent)) !== null) {
      const line = lineNumberAt(jsContent, m.index);
      const snippet = snippetAround(jsContent, m.index);
      results.push({
        type,
        severity,
        evidence: `line ${line}: ${snippet}`,
        line,
        snippet,
      });
      if (m.index === regex.lastIndex) regex.lastIndex++;
    }
  }

  return results;
}
