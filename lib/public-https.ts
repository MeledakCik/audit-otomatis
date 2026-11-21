import { request } from "node:https";
import { TLSSocket } from "node:tls";
import { assertPublicHttpsTarget } from "./ssrf-guard";

export interface PublicHttpsResponse {
  url: URL;
  statusCode: number;
  headers: Headers;
  bodyPrefix: string;
  bodyTruncated: boolean;
  responseTimeMs: number;
  tlsVersion: string | null;
  certificateExpiresAt: number | null;
}

interface RequestOptions {
  method: "GET" | "HEAD" | "POST";
  signal: AbortSignal;
  userAgent: string;
  accept?: string;
  maxBodyBytes?: number;
  body?: Buffer;
  contentType?: string;
  origin?: string;
  referer?: string;
  authorization?: string;
  cookie?: string;
}

export async function requestPublicHttps(rawUrl: string, options: RequestOptions): Promise<PublicHttpsResponse> {
  const started = performance.now();
  const { url, resolvedIp } = await assertPublicHttpsTarget(rawUrl, options.signal);
  options.signal.throwIfAborted();
  const { method, signal, userAgent, accept = "*/*", maxBodyBytes = 0, body, contentType, origin, referer, authorization, cookie } = options;

  return new Promise((resolve, reject) => {
    // Pakai IP hasil validasi untuk soket dan hostname asli untuk Host serta TLS.
    const req = request({
      hostname: resolvedIp,
      servername: url.hostname.replace(/\.$/, ""),
      port: 443,
      path: url.pathname + url.search,
      method,
      agent: false,
      rejectUnauthorized: true,
      signal,
      headers: {
        Host: url.host,
        "User-Agent": userAgent,
        "Accept": accept,
        "Accept-Encoding": "identity",
        ...(contentType ? { "Content-Type": contentType } : {}),
        ...(body ? { "Content-Length": String(body.length) } : {}),
        ...(origin ? { Origin: origin } : {}),
        ...(referer ? { Referer: referer } : {}),
        ...(authorization ? { Authorization: authorization } : {}),
        ...(cookie ? { Cookie: cookie } : {}),
      },
    }, (res) => {
      const headers = new Headers();
      for (const [name, value] of Object.entries(res.headers)) {
        if (typeof value === "string") headers.set(name, value);
      }
      const socket = res.socket;
      const expiry = socket instanceof TLSSocket ? socket.getPeerCertificate()?.valid_to : undefined;
      const expiresAt = expiry ? Date.parse(expiry) : NaN;
      const statusCode = res.statusCode ?? 0;
      const response = {
        url,
        statusCode,
        headers,
        responseTimeMs: Math.round(performance.now() - started),
        tlsVersion: socket instanceof TLSSocket ? socket.getProtocol() : null,
        certificateExpiresAt: Number.isFinite(expiresAt) ? expiresAt : null,
      };

      res.once("error", reject);
      if (method === "HEAD" || !maxBodyBytes || (statusCode >= 300 && statusCode < 400)) {
        resolve({ ...response, bodyPrefix: "", bodyTruncated: false });
        res.destroy();
        return;
      }

      const chunks: Buffer[] = [];
      let bytes = 0;
      const finish = (bodyTruncated: boolean) => resolve({
        ...response,
        bodyPrefix: Buffer.concat(chunks, bytes).toString("utf8"),
        bodyTruncated,
      });
      res.on("data", (chunk: Buffer) => {
        const remaining = maxBodyBytes - bytes;
        const received = chunk.subarray(0, remaining);
        if (received.length) chunks.push(received);
        bytes += received.length;
        if (chunk.length > remaining) {
          finish(true);
          res.destroy();
        }
      });
      res.once("end", () => finish(false));
    });
    req.once("error", reject);
    req.end(body);
  });
}
