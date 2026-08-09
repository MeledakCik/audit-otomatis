/**
 * lib/attack-map/extract-endpoints.ts
 *
 * Regex-based API-call extractor khusus buat Attack Surface Map — beda dari
 * lib/parsers/jsEndpointExtractor.ts karena modul ini JUGA mencoba menangkap
 * HTTP method (GET/POST/dst) di sekitar call-nya, supaya node API di graph
 * bisa menampilkan "Methods found". Read-only regex scan, tidak ada eval/require.
 */

export interface ApiCallMatch {
  url: string;
  method: string;
  line: number;
}

const STR = "(?:`(?:\\\\.|[^`\\\\])*`|'(?:\\\\.|[^'\\\\])*'|\"(?:\\\\.|[^\"\\\\])*\")";
const METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];

function unquote(raw: string): string {
  const quote = raw[0];
  let inner = raw.slice(1, -1);
  if (quote === "`") inner = inner.replace(/\$\{[^}]*\}/g, "{param}");
  return inner.replace(/\\(.)/g, "$1").trim();
}

function lineAt(content: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < content.length; i++) if (content.charCodeAt(i) === 10) line++;
  return line;
}

function isApiLikePath(url: string): boolean {
  if (!url) return false;
  if (url.startsWith("/api")) return true;
  if (/^https?:\/\//i.test(url)) return true;
  return false;
}

export function extractApiCallsFromJs(js: string): ApiCallMatch[] {
  if (!js) return [];
  const out: ApiCallMatch[] = [];
  const seen = new Set<string>();

  // fetch(url [, { ...method: 'POST'... }])
  const fetchRe = new RegExp(`\\bfetch\\(\\s*(${STR})\\s*(?:,\\s*\\{([\\s\\S]{0,300}?)\\})?`, "g");
  let m: RegExpExecArray | null;
  while ((m = fetchRe.exec(js)) !== null) {
    const url = unquote(m[1]);
    if (isApiLikePath(url)) {
      const methodMatch = m[2] ? /method\s*:\s*['"]([a-zA-Z]+)['"]/.exec(m[2]) : null;
      const method = methodMatch ? methodMatch[1].toUpperCase() : "GET";
      const key = `${url}:${method}:${m.index}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push({ url, method: METHODS.includes(method) ? method : "GET", line: lineAt(js, m.index) });
      }
    }
    if (m.index === fetchRe.lastIndex) fetchRe.lastIndex++;
  }

  // axios.get/post/put/delete/patch(url) — verb captured directly from the method name.
  const axiosVerbRe = new RegExp(`\\baxios\\.(get|post|put|delete|patch|head|options)\\(\\s*(${STR})`, "gi");
  while ((m = axiosVerbRe.exec(js)) !== null) {
    const url = unquote(m[2]);
    if (isApiLikePath(url)) {
      const key = `${url}:${m[1].toUpperCase()}:${m.index}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push({ url, method: m[1].toUpperCase(), line: lineAt(js, m.index) });
      }
    }
    if (m.index === axiosVerbRe.lastIndex) axiosVerbRe.lastIndex++;
  }

  // axios({ url: '...', method: '...' }) / axios.request({...})
  const axiosObjRe = new RegExp(`\\baxios(?:\\.request)?\\(\\s*\\{([\\s\\S]{0,300}?)\\}\\s*\\)`, "g");
  while ((m = axiosObjRe.exec(js)) !== null) {
    const block = m[1];
    const urlMatch = new RegExp(`\\burl\\s*:\\s*(${STR})`).exec(block);
    if (!urlMatch) continue;
    const url = unquote(urlMatch[1]);
    if (isApiLikePath(url)) {
      const methodMatch = /method\s*:\s*['"]([a-zA-Z]+)['"]/.exec(block);
      const method = methodMatch ? methodMatch[1].toUpperCase() : "GET";
      const key = `${url}:${method}:${m.index}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push({ url, method: METHODS.includes(method) ? method : "GET", line: lineAt(js, m.index) });
      }
    }
    if (m.index === axiosObjRe.lastIndex) axiosObjRe.lastIndex++;
  }

  // xhr.open("METHOD", url)
  const xhrRe = new RegExp(`\\.open\\(\\s*['"]([a-zA-Z]+)['"]\\s*,\\s*(${STR})`, "g");
  while ((m = xhrRe.exec(js)) !== null) {
    const url = unquote(m[2]);
    if (isApiLikePath(url)) {
      const method = m[1].toUpperCase();
      const key = `${url}:${method}:${m.index}`;
      if (!seen.has(key)) {
        seen.add(key);
        out.push({ url, method: METHODS.includes(method) ? method : "GET", line: lineAt(js, m.index) });
      }
    }
    if (m.index === xhrRe.lastIndex) xhrRe.lastIndex++;
  }

  return out;
}
