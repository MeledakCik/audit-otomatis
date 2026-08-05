/**
 * lib/vuln/domSink.ts
 *
 * Deteksi DOM XSS sink berbahaya di raw JS text pakai regex (bukan AST),
 * karena tujuannya cuma "cari lokasi yang wajib direview manual", bukan
 * membuktikan exploitability. Pure function, tanpa network call.
 */

import type { AuditFinding, AuditSeverity } from "./types";

export type SinkType =
  | "innerHTML"
  | "outerHTML"
  | "document.write"
  | "eval"
  | "setTimeout_string"
  | "location.hash"
  | "location.search";

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

// Catatan soal setTimeout(...string): kita cari setTimeout/setInterval yang argumen
// pertamanya STRING LITERAL (bukan function/arrow), karena itu yang sebenarnya
// jalan lewat implicit eval() di browser.
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
 * Cari sink DOM-XSS umum (innerHTML/outerHTML/document.write/eval/
 * setTimeout-with-string/location.hash/location.search) di raw JS text.
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
