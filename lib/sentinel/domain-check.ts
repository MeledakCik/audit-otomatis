import { runHeaderChecks } from "@/lib/header-scan/checks";
import { requestPublicHttps } from "@/lib/public-https";
import { SsrfBlockedError } from "@/lib/ssrf-guard";
import { TTL } from "./redis";
import { DOMAIN_RE, type AuthRecord } from "./store";

export function hasCurrentDomainProof(record: AuthRecord, now = Date.now()) {
  const proof = record.proof;
  return DOMAIN_RE.test(record.domain)
    && (record.status === "PENDING" || record.status === "APPROVED" || record.status === "VIEWED")
    && (proof?.method === "dns" || proof?.method === "file")
    && proof.verifiedAt >= record.createdAt
    && proof.verifiedAt <= now
    && now - record.createdAt < TTL.auth * 1000;
}

export async function checkDomain(domain: string, signal: AbortSignal) {
  const url = new URL(`https://${domain}/`);
  if (!DOMAIN_RE.test(domain) || url.hostname !== domain) throw new SsrfBlockedError("Domain tidak didukung.");

  const options = { signal, userAgent: "Sentinel-ID Domain Check/1.0", accept: "text/html,application/xhtml+xml" };
  let method: "HEAD" | "GET" = "HEAD";
  let response = await requestPublicHttps(url.href, { ...options, method });
  if (response.statusCode === 405 || response.statusCode === 501) {
    method = "GET";
    response = await requestPublicHttps(url.href, { ...options, method });
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
