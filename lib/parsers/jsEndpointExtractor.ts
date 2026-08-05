/**
 * lib/parsers/jsEndpointExtractor.ts
 *
 * "AST-less tapi powerful" endpoint extractor.
 *
 * Project ini sebenarnya sudah punya AST-based extractor di lib/js-analyzer.ts
 * (pakai acorn). Modul ini SENGAJA regex-based sebagai layer kedua yang lebih
 * murah & lebih toleran terhadap JS yang gagal di-parse acorn (mis. syntax
 * baru, JSX mentah, atau file yang sudah rusak/terpotong saat di-fetch),
 * jadi bisa dipakai sebagai fallback atau untuk cross-check hasil AST.
 *
 * Pure function. Tidak ada dependency backend / Node.js API.
 */

export type JsEndpointSource =
  | "fetch"
  | "axios.method"
  | "axios.object"
  | "xhr.open"
  | "websocket"
  | "router.push"
  | "dynamic.import"
  | "jquery.ajax";

export interface JsEndpointMatch {
  url: string;
  source: JsEndpointSource;
  /** approx 1-based line number in jsContent, buat gampang ditelusuri manual */
  line: number;
}

// String literal: single, double, atau template literal, dengan escape char.
const STR = "(?:`(?:\\\\.|[^`\\\\])*`|'(?:\\\\.|[^'\\\\])*'|\"(?:\\\\.|[^\"\\\\])*\")";

interface PatternDef {
  source: JsEndpointSource;
  regex: RegExp;
  // index of the capture group (1-based within match) yang berisi URL string literal
  urlGroup: number;
}

const PATTERNS: PatternDef[] = [
  // fetch("/api/x") / fetch(`...`)
  { source: "fetch", regex: new RegExp(`\\bfetch\\(\\s*(${STR})`, "g"), urlGroup: 1 },

  // axios.get("...") / axios.post(...) / axios.put/delete/patch/head/options(...)
  {
    source: "axios.method",
    regex: new RegExp(`\\baxios\\.(?:get|post|put|delete|patch|head|options)\\(\\s*(${STR})`, "g"),
    urlGroup: 1,
  },

  // axios({ ..., url: "..." , ... }) and axios.request({ url: "..." })
  {
    source: "axios.object",
    regex: new RegExp(`\\baxios(?:\\.request)?\\(\\s*\\{[\\s\\S]{0,300}?\\burl\\s*:\\s*(${STR})`, "g"),
    urlGroup: 1,
  },

  // xhr.open("GET", "/api/x") -> we only want the 2nd arg (url)
  {
    source: "xhr.open",
    regex: new RegExp(`\\.open\\(\\s*${STR}\\s*,\\s*(${STR})`, "g"),
    urlGroup: 1,
  },

  // new WebSocket("wss://...")
  { source: "websocket", regex: new RegExp(`\\bnew\\s+WebSocket\\(\\s*(${STR})`, "g"), urlGroup: 1 },

  // router.push("...") / router.replace("...") / router.prefetch("...")
  {
    source: "router.push",
    regex: new RegExp(`\\brouter\\.(?:push|replace|prefetch)\\(\\s*(${STR})`, "g"),
    urlGroup: 1,
  },

  // import("...")  (dynamic import / code-split routes)
  { source: "dynamic.import", regex: new RegExp(`\\bimport\\(\\s*(${STR})`, "g"), urlGroup: 1 },

  // $.ajax({ ..., url: "..." })
  {
    source: "jquery.ajax",
    regex: new RegExp(`\\$\\.ajax\\(\\s*\\{[\\s\\S]{0,300}?\\burl\\s*:\\s*(${STR})`, "g"),
    urlGroup: 1,
  },
];

function unquote(raw: string): string {
  const quote = raw[0];
  let inner = raw.slice(1, -1);
  if (quote === "`") {
    // template literal: ganti ${expr} jadi placeholder {param} biar tetap kebaca sebagai pattern endpoint
    inner = inner.replace(/\$\{[^}]*\}/g, "{param}");
  }
  // un-escape backslash escapes sederhana (\' \" \` \\ dll)
  inner = inner.replace(/\\(.)/g, "$1");
  return inner.trim();
}

function lineNumberAt(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) {
    if (content.charCodeAt(i) === 10 /* \n */) line++;
  }
  return line;
}

/** Filter: harus URL absolut (http/https) atau path yang mulai dari /api. */
function isValidEndpoint(url: string): boolean {
  if (!url) return false;
  if (url.startsWith("/api")) return true;
  if (/^https?:\/\//i.test(url)) return true;
  return false;
}

/**
 * Ekstrak kandidat endpoint dari raw JS text memakai pola-pola call yang umum
 * dipakai untuk network request di frontend (fetch, axios, XHR, WebSocket,
 * next/router, dynamic import, jQuery.ajax).
 *
 * Return: array URL unik yang valid (mulai "/api" atau "http(s)://").
 */
export function extractEndpointsFromJs(jsContent: string): string[] {
  if (!jsContent) return [];
  const seen = new Set<string>();

  for (const { regex } of PATTERNS) {
    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(jsContent)) !== null) {
      const rawLiteral = m[1];
      if (!rawLiteral) continue;
      const url = unquote(rawLiteral);
      if (isValidEndpoint(url)) seen.add(url);
      // guard against zero-width matches causing infinite loop
      if (m.index === regex.lastIndex) regex.lastIndex++;
    }
  }

  return Array.from(seen);
}

/**
 * Variant yang mempertahankan metadata (source pattern + line number),
 * berguna untuk laporan / debugging tanpa mengubah signature utama di atas.
 */
export function extractEndpointMatchesFromJs(jsContent: string): JsEndpointMatch[] {
  if (!jsContent) return [];
  const results: JsEndpointMatch[] = [];
  const seenKey = new Set<string>();

  for (const { source, regex } of PATTERNS) {
    regex.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = regex.exec(jsContent)) !== null) {
      const rawLiteral = m[1];
      if (!rawLiteral) continue;
      const url = unquote(rawLiteral);
      if (isValidEndpoint(url)) {
        const key = `${source}:${url}:${m.index}`;
        if (!seenKey.has(key)) {
          seenKey.add(key);
          results.push({ url, source, line: lineNumberAt(jsContent, m.index) });
        }
      }
      if (m.index === regex.lastIndex) regex.lastIndex++;
    }
  }

  return results;
}
