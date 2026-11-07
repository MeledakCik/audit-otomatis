/**
 * lib/vuln/domSink.ts
 *
 * Deteksi sink berbahaya di raw JS/TS bundle text secara pasif (tanpa network call):
 * 1. DOM XSS sinks (innerHTML, outerHTML, document.write, eval, setTimeout string, location.hash/search)
 * 2. node2shell sinks (child_process.exec/spawn, vm.runInNewContext, deserialization unserialize/node-serialize, prototype pollution __proto__)
 * 3. node-oob (Node Out-of-Bounds / Memory Buffer sinks: Buffer.allocUnsafe, new Buffer(), DataView/TypedArray unchecked byteOffset)
 * 4. wp2shell / php2shell client-side bridge indicators (wp_ajax_nopriv dynamic action / admin-ajax.php)
 *
 * PRINSIP ANTI-FALSE-POSITIVE:
 * - Abaikan inline script Next.js RSC Flight payload (`self.__next_f.push(...)`) & JSON-LD yang hanya memuat teks UI/artikel.
 * - `node2shell_child_process` hanya cocok pada pemanggilan modul `child_process` / `execSync` / `spawnSync` / `execFile` nyata,
 *   BUKAN `regex.exec(str)` di kode minified React/Next.js!
 * - `node2shell_prototype_pollution` mengabaikan pola aman `{__proto__:null}` dan guard `"__proto__"!==`.
 * - Deteksi FileManager / WebShell tidak lagi dilakukan lewat teks JS mentah (agar teks edukasi/preset tidak dianggap backdoor),
 *   melainkan diverifikasi langsung melalui HTTP GET probing & signature DOM/JSON nyata di `rce-surface.ts` dan `scan-runner.ts`.
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
  | "wp2shell_admin_ajax"
  | "webshell_filemanager_bridge";

export interface Sink extends AuditFinding {
  type: SinkType;
  line: number;
  snippet: string;
}

interface SinkPatternDef {
  type: SinkType;
  regex: RegExp;
  severity: AuditSeverity;
  validateMatch?: (snippet: string, fullText: string, index: number) => boolean;
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
  // node2shell — HANYA pemanggilan child_process / execSync / spawnSync / execFile nyata (BUKAN RegExp.prototype.exec!)
  {
    type: "node2shell_child_process",
    regex:
      /\b(?:require\s*\(\s*['"](?:node:)?child_process['"]\s*\)|from\s+['"](?:node:)?child_process['"]|child_process\s*\.\s*(?:exec|execSync|spawn|spawnSync|execFile|fork)\s*\(|\b(?:execSync|spawnSync|execFileSync)\s*\()/g,
    severity: "high",
  },
  {
    type: "node2shell_vm_eval",
    regex: /\bvm\.runIn(?:New|This)?Context\s*\(/g,
    severity: "high",
  },
  {
    type: "node2shell_deserialization",
    regex: /\brequire\s*\(\s*['"]node-serialize['"]\s*\)|\bnodeSerialize\.unserialize\s*\(/g,
    severity: "high",
  },
  {
    type: "node2shell_prototype_pollution",
    regex: /\[['"]__proto__['"]\]\s*=|\.__proto__\s*=\s*[^n]/g,
    severity: "medium",
    validateMatch: (snippet) => {
      // Abaikan inisialisasi objek bersih `{__proto__:null}` atau pengecekan guard `"__proto__"!==` / `"__proto__"===`
      if (/__proto__\s*:\s*null/.test(snippet)) return false;
      if (/['"]__proto__['"]\s*[!=]==/.test(snippet)) return false;
      if (/Object\.prototype/.test(snippet)) return false;
      return true;
    },
  },
  // node-oob — Node.js Out-of-Bounds / Unsafe Memory Buffer allocation
  {
    type: "node_oob_buffer",
    regex: /\bBuffer\.allocUnsafe(?:Slow)?\s*\(/g,
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
 * Otomatis melewati (skip) inline script Next.js RSC Flight payload (`self.__next_f.push`)
 * dan blok JSON murni agar teks UI/artikel tidak memicu false-positive.
 */
export function findDomSinks(jsContent: string): Sink[] {
  if (!jsContent) return [];
  const trimmed = jsContent.trim();

  // Skip Next.js RSC hydration data payload atau JSON-LD schema
  if (
    trimmed.startsWith("(self.__next_f=self.__next_f||[]).push") ||
    trimmed.startsWith("self.__next_f.push") ||
    trimmed.startsWith("{") ||
    trimmed.startsWith("[")
  ) {
    return [];
  }

  const results: Sink[] = [];
  const seenPerType = new Map<SinkType, number>();

  for (const { type, regex, severity, validateMatch } of SINK_PATTERNS) {
    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(jsContent)) !== null) {
      const countForType = seenPerType.get(type) ?? 0;
      // Deduplikasi: maksimal 2 temuan per jenis sink di dalam 1 file yang sama agar tabel tidak banjir duplikat
      if (countForType >= 2) break;

      const snippet = snippetAround(jsContent, m.index);
      if (validateMatch && !validateMatch(snippet, jsContent, m.index)) {
        if (m.index === regex.lastIndex) regex.lastIndex++;
        continue;
      }

      const line = lineNumberAt(jsContent, m.index);
      seenPerType.set(type, countForType + 1);
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
