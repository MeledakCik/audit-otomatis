import { isIP } from "node:net";
import { runHeaderChecks } from "@/lib/header-scan/checks";
import { requestPublicHttps } from "@/lib/public-https";
import { DOMAIN_RE } from "./store";

export function normalizeDomainCheckTarget(input: unknown): string | null {
  if (typeof input !== "string" || input.length > 2048) return null;
  const value = input.trim();
  if (!value || /[\s\\]/.test(value)) return null;

  try {
    const url = new URL(/^[a-z][a-z\d+.-]*:\/\//i.test(value) ? value : `https://${value}`);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    if (url.username || url.password || url.port) return null;
    const domain = url.hostname.replace(/\.$/, "");
    return DOMAIN_RE.test(domain) && !isIP(domain) ? domain : null;
  } catch {
    return null;
  }
}

export function normalizeUploadEndpoint(domain: string, endpointInput: unknown): URL | null {
  if (typeof endpointInput !== "string" || endpointInput.length > 2048) return null;
  const value = endpointInput.trim();
  if (!value || /[\s\\]/.test(value)) return null;

  try {
    const absolute = /^[a-z][a-z\d+.-]*:\/\//i.test(value);
    if (!absolute && !value.startsWith("/")) return null;
    const url = new URL(value, `https://${domain}/`);
    if (
      url.protocol !== "https:"
      || url.hostname.replace(/\.$/, "") !== domain
      || url.port
      || url.username
      || url.password
      || url.hash
    ) return null;
    return url;
  } catch {
    return null;
  }
}

export async function checkDomain(domain: string, signal: AbortSignal) {
  const url = `https://${domain}/`;
  const options = { signal, userAgent: "Sentinel-ID Domain Check/1.0", accept: "text/html,application/xhtml+xml" };
  let method: "HEAD" | "GET" = "HEAD";
  let response = await requestPublicHttps(url, { ...options, method });
  if (response.statusCode === 405 || response.statusCode === 501) {
    method = "GET";
    response = await requestPublicHttps(url, { ...options, method });
  }

  const { headers, statusCode, responseTimeMs, tlsVersion, certificateExpiresAt } = response;
  const contentType = headers.get("content-type")?.split(";")[0]?.trim().toLowerCase();
  const mitigated = headers.get("cf-mitigated") === "challenge"
    || /challenge|deny/i.test(headers.get("x-vercel-mitigated") ?? "");
  const pageAssessed = statusCode >= 200 && statusCode < 300 && !mitigated
    && (contentType === "text/html" || contentType === "application/xhtml+xml");
  const checks = runHeaderChecks(Object.fromEntries(headers))
    .filter((check) => pageAssessed || check.value !== null)
    .map(({ headerName, pass }) => ({ name: headerName, pass }));

  return { domain, method, statusCode, responseTimeMs, tlsVersion, certificateExpiresAt, pageAssessed, checks };
}

function safeUploadLinks(body: string, contentType: string, endpoint: URL, location?: string) {
  const candidates: string[] = [];
  if (location) candidates.push(location);
  if (/json/i.test(contentType)) {
    try {
      const data: unknown = JSON.parse(body);
      const visit = (value: unknown, depth: number) => {
        if (!value || typeof value !== "object" || depth > 4 || candidates.length >= 20) return;
        for (const [key, child] of Object.entries(value)) {
          const normalizedKey = key.replace(/[_-]/g, "").toLowerCase();
          if (
            typeof child === "string"
            && ["url", "href", "link", "location", "download", "downloadurl", "fileurl", "publicurl", "path", "filepath"].includes(normalizedKey)
          ) {
            candidates.push(child);
          } else {
            visit(child, depth + 1);
          }
        }
      };
      visit(data, 0);
    } catch {
      // Non-JSON response body is only used to look for returned links below.
    }
  }
  if (/html/i.test(contentType)) {
    for (const match of body.slice(0, 16_384).matchAll(/<a\b[^>]*\bhref\s*=\s*["']([^"']+)["']/gi)) {
      candidates.push(match[1]);
    }
  }

  const links = new Map<string, { url: string; sameOrigin: boolean }>();
  for (const candidate of candidates) {
    if (links.size >= 8) break;
    try {
      const url = new URL(candidate, endpoint);
      if (url.protocol !== "https:" || url.username || url.password) continue;
      links.set(url.href, { url: url.href, sameOrigin: url.origin === endpoint.origin });
    } catch {
      // Ignore values that are not links.
    }
  }
  return Array.from(links.values());
}

export async function testFileUpload(input: {
  domain: string;
  endpoint: URL;
  fieldName: string;
  filename: string;
  file: Buffer;
  signal: AbortSignal;
}) {
  if (!/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(input.fieldName)) throw new Error("Invalid upload field name");
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\.txt$/i.test(input.filename) || input.filename.includes("..")) {
    throw new Error("Invalid upload sample filename");
  }
  const boundary = `----SentinelID${crypto.randomUUID().replace(/-/g, "")}`;
  const prefix = Buffer.from(
    `--${boundary}\r\nContent-Disposition: form-data; name="${input.fieldName}"; filename="${input.filename}"\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n`,
    "utf8",
  );
  const suffix = Buffer.from(`\r\n--${boundary}--\r\n`, "ascii");
  const body = Buffer.concat([prefix, input.file, suffix]);
  const result = await requestPublicHttps(input.endpoint.href, {
    method: "POST",
    signal: input.signal,
    userAgent: "Sentinel-ID Admin Upload Check/1.0",
    accept: "application/json,text/html,text/plain;q=0.9,*/*;q=0.8",
    contentType: `multipart/form-data; boundary=${boundary}`,
    origin: input.endpoint.origin,
    referer: `${input.endpoint.origin}/`,
    body,
    maxBodyBytes: 8192,
  });
  const contentType = result.headers.get("content-type") ?? "";
  const preview = result.bodyPrefix
    .replace(/<[^>]*>/g, " ")
    .replace(/(?:bearer\s+)[A-Za-z0-9._~+/-]+=*/gi, "Bearer [redacted]")
    .replace(/((?:token|password|secret|api[_-]?key)\s*["':= ]\s*)[^\s,"'}&<]+/gi, "$1[redacted]")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 360);
  const links = safeUploadLinks(result.bodyPrefix, contentType, input.endpoint, result.headers.get("location") ?? undefined);
  const storedLink = links.find((link) => link.sameOrigin);
  let publicRetrieval: { statusCode: number; contentMatchesSample: boolean } | null = null;

  if (result.statusCode >= 200 && result.statusCode < 300 && storedLink) {
    try {
      const retrieved = await requestPublicHttps(storedLink.url, {
        method: "GET",
        signal: input.signal,
        userAgent: "Sentinel-ID Admin Upload Check/1.0",
        accept: "text/plain",
        maxBodyBytes: input.file.length + 1,
      });
      publicRetrieval = {
        statusCode: retrieved.statusCode,
        contentMatchesSample: retrieved.statusCode === 200
          && !retrieved.bodyTruncated
          && retrieved.bodyPrefix === input.file.toString("utf8"),
      };
    } catch {
      publicRetrieval = null;
    }
  }

  return {
    domain: input.domain,
    endpoint: input.endpoint.href,
    method: "POST" as const,
    statusCode: result.statusCode,
    accepted: result.statusCode >= 200 && result.statusCode < 300,
    responseTimeMs: result.responseTimeMs,
    responseContentType: contentType || "unknown",
    responsePreview: preview,
    responseTruncated: result.bodyTruncated,
    links,
    publicRetrieval,
  };
}
