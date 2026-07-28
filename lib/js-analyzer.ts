import * as acorn from "acorn";
import * as walk from "acorn-walk";
import type { DiscoveredEndpoint } from "./types";
import { chromeHeaders } from "./crawler";

export const MAX_JS_FILES = 20;
export const MAX_JS_FILE_BYTES = 500 * 1024; // 500kb
const API_PATH_RE = /^\/(api|_api|graphql|rest|v[0-9]+)(\/[a-zA-Z0-9_\-/{}.:?=&%~+,]*)?$/;
const API_PATH_SCAN_RE = /\/(?:api|_api|graphql|rest|v[0-9]+)\/[a-zA-Z0-9_\-/{}.:?=&%~+,]*/;

interface AnalyzeOutput {
  endpoints: DiscoveredEndpoint[];
  usesLocalStorage: boolean;
  parseError?: string;
}
function templateLiteralToPattern(node: any): string | null {
  if (!node || node.type !== "TemplateLiteral") return null;
  let out = "";
  for (let i = 0; i < node.quasis.length; i++) {
    out += node.quasis[i].value.cooked ?? "";
    if (i < node.expressions.length) out += "{param}";
  }
  return out;
}

function methodFromCalleeName(name: string): "GET" | "POST" {
  if (name.toLowerCase().includes("post")) return "POST";
  return "GET";
}

const HTTP_METHODS = new Set(["GET", "POST", "PUT", "DELETE", "PATCH"]);
type HttpMethod = "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
function methodFromLiteral(value: string): HttpMethod | null {
  const upper = value.toUpperCase();
  return HTTP_METHODS.has(upper) ? (upper as HttpMethod) : null;
}
function methodHintFromName(name: string): HttpMethod | null {
  const lower = name.toLowerCase();
  if (lower.includes("delete")) return "DELETE";
  if (lower.includes("patch")) return "PATCH";
  if (lower.includes("put")) return "PUT";
  if (lower.includes("post")) return "POST";
  if (lower.includes("get")) return "GET";
  return null;
}
function urlFromArg(node: any): string | null {
  if (!node) return null;
  if (node.type === "Literal" && typeof node.value === "string") return node.value;
  if (node.type === "TemplateLiteral") return templateLiteralToPattern(node);
  return null;
}
function extractPayloadKeys(node: any): string[] | undefined {
  if (!node) return undefined;

  if (node.type === "ObjectExpression") {
    const keys: string[] = [];
    for (const prop of node.properties as any[]) {
      if (prop.type === "Property") {
        if (prop.key.type === "Identifier") keys.push(prop.key.name);
        else if (prop.key.type === "Literal" && typeof prop.key.value === "string") {
          keys.push(prop.key.value);
        }
      } else if (prop.type === "SpreadElement") {
        keys.push("...spread");
      }
    }
    return keys.length > 0 ? keys : undefined;
  }

  if (
    node.type === "CallExpression" &&
    node.callee.type === "MemberExpression" &&
    node.callee.object.type === "Identifier" &&
    node.callee.object.name === "JSON" &&
    node.callee.property.type === "Identifier" &&
    node.callee.property.name === "stringify"
  ) {
    return extractPayloadKeys(node.arguments[0]);
  }

  return undefined;
}
export function analyzeJsSource(source: string, sourceLabel: string): AnalyzeOutput {
  const endpoints: DiscoveredEndpoint[] = [];
  let usesLocalStorage = false;

  let ast: acorn.Node;
  try {
    ast = acorn.parse(source, {
      ecmaVersion: "latest",
      sourceType: "module",
      locations: true,
      allowImportExportEverywhere: true,
      allowAwaitOutsideFunction: true,
      allowReturnOutsideFunction: true,
    });
  } catch {
    const textEndpoints = scanTextForEndpoints(source, sourceLabel);
    return {
      endpoints: dedupe(textEndpoints),
      usesLocalStorage: /localStorage\.(get|set)Item/.test(source),
    };
  }

  function lineOf(node: { loc?: { start: { line: number } } | null }): number {
    return node.loc?.start.line ?? 0;
  }

  function pushEndpoint(url: string, method: HttpMethod, line: number, payload?: string[]) {
    if (!API_PATH_RE.test(url)) return;
    endpoints.push({
      url,
      method,
      source: `${sourceLabel}:${line}`,
      ...(payload && payload.length > 0 ? { payload } : {}),
    });
  }
  const stringConsts = new Map<string, string>();
  walk.simple(ast, {
    VariableDeclarator(node: any) {
      if (
        node.id?.type === "Identifier" &&
        node.init?.type === "Literal" &&
        typeof node.init.value === "string"
      ) {
        stringConsts.set(node.id.name, node.init.value);
      }
    },
  });

  function resolveUrl(node: any): string | null {
    const direct = urlFromArg(node);
    if (direct !== null) return direct;
    if (!node) return null;
    if (node.type === "Identifier") return stringConsts.get(node.name) ?? null;
    if (node.type === "BinaryExpression" && node.operator === "+") {
      const left = resolveUrl(node.left);
      const right = resolveUrl(node.right);
      if (left !== null && right !== null) return left + right;
    }
    return null;
  }

  walk.simple(ast, {
    CallExpression(node: any) {
      const callee = node.callee;
      const line = lineOf(node);
      if (callee.type === "Identifier" && callee.name === "fetch") {
        const arg0 = node.arguments[0];
        let method: "GET" | "POST" = "GET";
        let payload: string[] | undefined;
        const arg1 = node.arguments[1];
        if (arg1 && arg1.type === "ObjectExpression") {
          for (const prop of arg1.properties) {
            if (prop.type !== "Property" || prop.key.type !== "Identifier") continue;
            if (
              prop.key.name === "method" &&
              prop.value.type === "Literal" &&
              typeof prop.value.value === "string"
            ) {
              method = methodFromCalleeName(prop.value.value);
            }
            if (prop.key.name === "body") {
              payload = extractPayloadKeys(prop.value);
            }
          }
        }
        const url = resolveUrl(arg0);
        if (url) {
          pushEndpoint(url, method, line, method === "POST" ? payload : undefined);
        }
      }
      let memberMethodHandled = false;
      if (callee.type === "MemberExpression" && callee.property.type === "Identifier") {
        const hint = methodHintFromName(callee.property.name);
        if (hint) {
          memberMethodHandled = true;
          const arg0 = node.arguments[0];
          const payload =
            hint !== "GET" && hint !== "DELETE" ? extractPayloadKeys(node.arguments[1]) : undefined;
          const url = resolveUrl(arg0);
          if (url) {
            pushEndpoint(url, hint, line, payload);
          }
        }
      }

      if (
        callee.type === "MemberExpression" &&
        callee.object.type === "Identifier" &&
        callee.object.name === "localStorage" &&
        callee.property.type === "Identifier" &&
        ["getItem", "setItem"].includes(callee.property.name)
      ) {
        usesLocalStorage = true;
      }
      const isGenericIdentifierCall = callee.type === "Identifier" && callee.name !== "fetch";
      const isGenericMemberCall = callee.type === "MemberExpression" && !memberMethodHandled;
      if (isGenericIdentifierCall || isGenericMemberCall) {
        const url = resolveUrl(node.arguments[0]);
        if (url && API_PATH_RE.test(url)) {
          let method: HttpMethod = "GET";
          let payload: string[] | undefined;
          for (const arg of node.arguments.slice(1)) {
            if (arg.type === "Literal" && typeof arg.value === "string") {
              const fromLiteral = methodFromLiteral(arg.value);
              if (fromLiteral) method = fromLiteral;
            } else if (arg.type === "ObjectExpression") {
              let methodFromConfig: HttpMethod | null = null;
              let bodyNode: unknown = null;
              for (const prop of arg.properties as any[]) {
                if (prop.type !== "Property") continue;
                const keyName =
                  prop.key.type === "Identifier"
                    ? prop.key.name
                    : prop.key.type === "Literal" && typeof prop.key.value === "string"
                      ? prop.key.value
                      : null;
                if (
                  keyName === "method" &&
                  prop.value.type === "Literal" &&
                  typeof prop.value.value === "string"
                ) {
                  methodFromConfig = methodFromLiteral(prop.value.value);
                }
                if (keyName === "body" || keyName === "data") bodyNode = prop.value;
              }
              if (methodFromConfig) method = methodFromConfig;
              payload = extractPayloadKeys(bodyNode ?? arg) ?? payload;
            }
          }
          pushEndpoint(url, method, line, method !== "GET" ? payload : undefined);
        }
      }
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any -- same reason as above
    Literal(node: any) {
      // Tangkap string literal "/api/..." yang berdiri sendiri (bukan cuma
      // sebagai argumen call), misal disimpan di object config endpoint.
      if (typeof node.value === "string" && API_PATH_RE.test(node.value)) {
        pushEndpoint(node.value, "GET", lineOf(node));
      }
    },
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    BinaryExpression(node: any) {
      // Lengkapi resolveUrl() di atas (yang cuma jalan kalau concat-nya persis
      // argumen sebuah call) — di sini kita tangkep juga concat yang berdiri
      // sendiri, mis. `const url = BASE + "web/x"; someCall(url)`, di mana
      // `someCall(url)` sendiri gagal di-resolve (arg-nya cuma Identifier
      // biasa tanpa binary expression), tapi definisi concat-nya kelihatan
      // di titik lain di file yang sama.
      if (node.operator !== "+") return;
      const resolved = resolveUrl(node);
      if (resolved && API_PATH_RE.test(resolved)) {
        pushEndpoint(resolved, "GET", lineOf(node));
      }
    },
  });

  // Selalu jalankan text-scan juga, digabung dengan hasil AST — AST walk di
  // atas cuma nangkep pola yang secara struktural kita kenali (literal
  // langsung / template literal di argumen fetch/axios). Pola lain (string
  // concat, endpoint yang di-assign ke variable dulu, dst.) tetap kelewat
  // dari AST tapi kelihatan kalau di-search manual di source — text-scan
  // ini jadi jaring pengaman kedua.
  const astUrls = new Set(endpoints.map((e) => e.url));
  const textEndpoints = scanTextForEndpoints(source, sourceLabel).filter((e) => !astUrls.has(e.url));

  const merged = dedupe([...endpoints, ...textEndpoints]);

  // Bersihkan noise: kalau ada entry GET generik (dari visitor Literal, yang
  // ngecek semua string literal tanpa peduli konteks) yang persis di
  // file:line yang sama dengan entry POST hasil parsing call fetch/axios,
  // itu 99% cuma literal yang sama ke-visit dua kali — bukan dua endpoint
  // beda. Buang versi GET-nya, simpan yang POST (lebih presisi + ada payload).
  const nonGetSourceKeys = new Set(
    merged.filter((e) => e.method !== "GET").map((e) => `${e.url}@${e.source}`)
  );
  const cleaned = merged.filter(
    (e) => !(e.method === "GET" && !e.payload && nonGetSourceKeys.has(`${e.url}@${e.source}`))
  );

  return { endpoints: cleaned, usesLocalStorage };
}

function dedupe(list: DiscoveredEndpoint[]): DiscoveredEndpoint[] {
  const byKey = new Map<string, DiscoveredEndpoint>();
  for (const ep of list) {
    const key = `${ep.method} ${ep.url}`;
    const existing = byKey.get(key);
    // Kalau ada duplikat, prioritaskan yang bawa info payload supaya tidak
    // hilang cuma karena urutan kemunculan di source.
    if (!existing || (!existing.payload && ep.payload)) {
      byKey.set(key, ep);
    }
  }
  return Array.from(byKey.values());
}
function scanTextForEndpoints(source: string, sourceLabel: string): DiscoveredEndpoint[] {
  const endpoints: DiscoveredEndpoint[] = [];
  const re = new RegExp(`["'\`](${API_PATH_SCAN_RE.source})["'\`]`, "g");
  let match: RegExpExecArray | null;
  const lines = source.split("\n");
  const lineStarts: number[] = [];
  let offset = 0;
  for (const l of lines) {
    lineStarts.push(offset);
    offset += l.length + 1;
  }
  function lineForIndex(idx: number): number {
    let lo = 0,
      hi = lineStarts.length - 1,
      ans = 0;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (lineStarts[mid] <= idx) {
        ans = mid;
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return ans + 1;
  }
  while ((match = re.exec(source))) {
    endpoints.push({
      url: match[1],
      method: "GET",
      source: `${sourceLabel}:${lineForIndex(match.index)}`,
    });
  }
  return endpoints;
}

export function analyzeInlineScripts(
  inlineScripts: string[],
  onLog?: (msg: string) => void
): { endpoints: DiscoveredEndpoint[]; usesLocalStorage: boolean } {
  const allEndpoints: DiscoveredEndpoint[] = [];
  let usesLocalStorage = false;

  inlineScripts.forEach((src, i) => {
    const label = `inline-script[${i}]`;
    const { endpoints, usesLocalStorage: uls } = analyzeJsSource(src, label);
    if (endpoints.length > 0) {
      allEndpoints.push(...endpoints);
      onLog?.(`Parsed ${label} — ${endpoints.length} endpoint ditemukan`);
    }
    usesLocalStorage = usesLocalStorage || uls;
  });

  return { endpoints: dedupe(allEndpoints), usesLocalStorage };
}

export interface FetchedJsFile {
  url: string;
  label: string;
  text: string;
}

export async function fetchJsFiles(
  scriptUrls: string[],
  onLog?: (msg: string) => void
): Promise<FetchedJsFile[]> {
  const toFetch = scriptUrls.slice(0, MAX_JS_FILES);
  const out: FetchedJsFile[] = [];

  for (const url of toFetch) {
    try {
      const res = await fetch(url, { headers: chromeHeaders(), method: "GET" });
      if (!res.ok) continue;
      const contentLength = res.headers.get("content-length");
      if (contentLength && parseInt(contentLength, 10) > MAX_JS_FILE_BYTES) {
        onLog?.(`Lewati ${url} (>500kb)`);
        continue;
      }
      const text = await res.text();
      if (text.length > MAX_JS_FILE_BYTES) {
        onLog?.(`Lewati ${url} (>500kb setelah download)`);
        continue;
      }
      const label = (() => {
        try {
          return new URL(url).pathname;
        } catch {
          return url;
        }
      })();
      out.push({ url, label, text });
    } catch (err) {
      onLog?.(`Gagal fetch ${url}: ${(err as Error).message}`);
    }
  }

  return out;
}

export async function analyzeJsFiles(
  scriptUrls: string[],
  onLog?: (msg: string) => void
): Promise<{ endpoints: DiscoveredEndpoint[]; usesLocalStorage: boolean; filesAnalyzed: number }> {
  const toFetch = scriptUrls.slice(0, MAX_JS_FILES);
  const allEndpoints: DiscoveredEndpoint[] = [];
  let usesLocalStorage = false;
  let filesAnalyzed = 0;

  for (const url of toFetch) {
    try {
      const res = await fetch(url, { headers: chromeHeaders(), method: "GET" });
      if (!res.ok) continue;
      const contentLength = res.headers.get("content-length");
      if (contentLength && parseInt(contentLength, 10) > MAX_JS_FILE_BYTES) {
        onLog?.(`Lewati ${url} (>500kb)`);
        continue;
      }
      const text = await res.text();
      if (text.length > MAX_JS_FILE_BYTES) {
        onLog?.(`Lewati ${url} (>500kb setelah download)`);
        continue;
      }
      const label = (() => {
        try {
          return new URL(url).pathname;
        } catch {
          return url;
        }
      })();
      const { endpoints, usesLocalStorage: uls } = analyzeJsSource(text, label);
      allEndpoints.push(...endpoints);
      usesLocalStorage = usesLocalStorage || uls;
      filesAnalyzed++;
      onLog?.(`Parsed ${label} — ${endpoints.length} endpoint ditemukan`);
    } catch (err) {
      onLog?.(`Gagal fetch ${url}: ${(err as Error).message}`);
    }
  }

  return { endpoints: dedupe(allEndpoints), usesLocalStorage, filesAnalyzed };
}
