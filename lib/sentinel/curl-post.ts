import { normalizeDomainCheckTarget } from "./domain-check";

export interface ParsedCurlPost {
  url: URL;
  contentType: string;
  body: Buffer;
  authorization?: string;
  cookie?: string;
  origin?: string;
  referer?: string;
  accept?: string;
}

function tokenize(command: string) {
  const tokens: string[] = [];
  let token = "";
  let quote: "'" | '"' | null = null;
  let escape = false;
  for (const char of command) {
    if (escape) {
      token += char;
      escape = false;
      continue;
    }
    if (char === "\\" && quote !== "'") {
      escape = true;
      continue;
    }
    if (quote) {
      if (char === quote) quote = null;
      else token += char;
      continue;
    }
    if (char === "'" || char === '"') {
      quote = char;
      continue;
    }
    if (/[\r\n;&|<>`]/.test(char)) throw new Error("Shell operators are not accepted.");
    if (/\s/.test(char)) {
      if (token) tokens.push(token);
      token = "";
    } else {
      token += char;
    }
  }
  if (escape || quote) throw new Error("Unclosed quote or escape in cURL command.");
  if (token) tokens.push(token);
  return tokens;
}

export function parseCurlPost(command: unknown, rootInput: unknown): ParsedCurlPost {
  if (typeof command !== "string" || command.length > 8192) throw new Error("cURL command maksimal 8 KB.");
  const rootDomain = normalizeDomainCheckTarget(rootInput);
  if (!rootDomain) throw new Error("Domain scope tidak valid.");

  const tokens = tokenize(command.trim());
  const program = tokens.shift()?.toLowerCase();
  if (program !== "curl" && program !== "curl.exe") throw new Error("Awali perintah dengan curl.");

  let method = "";
  let contentType = "application/x-www-form-urlencoded";
  let bodyText: string | null = null;
  const headers: Record<string, string> = {};
  const urls: string[] = [];

  while (tokens.length) {
    const token = tokens.shift()!;
    if (token === "-X" || token === "--request") {
      method = (tokens.shift() ?? "").toUpperCase();
      continue;
    }
    if (token === "-H" || token === "--header") {
      const header = tokens.shift() ?? "";
      const colon = header.indexOf(":");
      if (colon < 1 || /[\r\n\u0000]/.test(header)) throw new Error("Format header cURL tidak valid.");
      const name = header.slice(0, colon).trim().toLowerCase();
      const value = header.slice(colon + 1).trim();
      if (!value || value.length > 4096 || headers[name]) throw new Error("Header kosong, terlalu panjang, atau duplikat.");
      if (name === "content-type") {
        const candidate = value.toLowerCase();
        const baseType = candidate.split(";", 1)[0].trim();
        if (!["application/json", "text/plain", "application/x-www-form-urlencoded"].includes(baseType)) {
          throw new Error("Content-Type yang didukung: JSON, text/plain, atau form-urlencoded.");
        }
        contentType = candidate;
        headers[name] = value;
      } else if (name === "authorization") {
        if (!/^(?:bearer|basic)\s+\S+$/i.test(value)) throw new Error("Authorization hanya mendukung Bearer atau Basic.");
        headers[name] = value;
      } else if (name === "cookie") {
        if (!/^[!#$%&'*+.^_`|~0-9A-Za-z=-]+(?:\s*;\s*[!#$%&'*+.^_`|~0-9A-Za-z=-]+)*$/.test(value)) {
          throw new Error("Cookie header tidak valid.");
        }
        headers[name] = value;
      } else if (["origin", "referer", "accept"].includes(name)) {
        headers[name] = value;
      } else {
        throw new Error(`Header cURL tidak didukung: ${name}`);
      }
      continue;
    }
    if (["-d", "--data", "--data-raw"].includes(token)) {
      if (bodyText !== null) throw new Error("Gunakan satu opsi data saja.");
      bodyText = tokens.shift() ?? "";
      if (bodyText.startsWith("@")) throw new Error("Membaca file lokal dari cURL tidak didukung.");
      continue;
    }
    if (token === "--url") {
      const value = tokens.shift();
      if (!value) throw new Error("URL cURL wajib diisi.");
      urls.push(value);
      continue;
    }
    if (token.startsWith("-")) throw new Error(`Opsi cURL tidak didukung: ${token}`);
    urls.push(token);
  }

  if (method !== "POST") throw new Error("Metode wajib dinyatakan eksplisit sebagai POST.");
  if (urls.length !== 1) throw new Error("cURL harus memiliki tepat satu URL target.");
  if (bodyText === null) throw new Error("Tambahkan body dengan -d atau --data-raw.");
  const body = Buffer.from(bodyText, "utf8");
  if (!body.length || body.length > 8192) throw new Error("Body POST harus 1 byte hingga 8 KB.");
  if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/.test(bodyText)) {
    throw new Error("Body hanya boleh berisi teks UTF-8 tanpa karakter kontrol.");
  }
  if (contentType.startsWith("application/json")) {
    try { JSON.parse(bodyText); } catch { throw new Error("Body JSON tidak valid."); }
  }

  let url: URL;
  try { url = new URL(urls[0]); } catch { throw new Error("URL target tidak valid."); }
  const domain = url.hostname.toLowerCase().replace(/\.$/, "");
  if (
    url.protocol !== "https:"
    || url.username
    || url.password
    || url.port
    || url.hash
    || (domain !== rootDomain && !domain.endsWith(`.${rootDomain}`))
  ) {
    throw new Error("URL harus HTTPS pada domain scope atau subdomainnya, tanpa kredensial/port kustom.");
  }

  for (const headerName of ["origin", "referer"] as const) {
    const headerValue = headers[headerName];
    if (!headerValue) continue;
    let headerUrl: URL;
    try { headerUrl = new URL(headerValue); } catch { throw new Error(`${headerName} harus berupa URL HTTPS yang valid.`); }
    const headerDomain = headerUrl.hostname.toLowerCase().replace(/\.$/, "");
    if (
      headerUrl.protocol !== "https:"
      || headerUrl.username
      || headerUrl.password
      || headerUrl.port
      || (headerDomain !== rootDomain && !headerDomain.endsWith(`.${rootDomain}`))
    ) throw new Error(`${headerName} harus tetap dalam domain scope HTTPS.`);
  }

  return {
    url,
    contentType,
    body,
    ...(headers.authorization ? { authorization: headers.authorization } : {}),
    ...(headers.cookie ? { cookie: headers.cookie } : {}),
    ...(headers.origin ? { origin: headers.origin } : {}),
    ...(headers.referer ? { referer: headers.referer } : {}),
    ...(headers.accept ? { accept: headers.accept } : {}),
  };
}
