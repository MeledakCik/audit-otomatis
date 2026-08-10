import { NextRequest, NextResponse } from "next/server";
import { assertPublicHttpsTarget, isSameOrigin, SsrfBlockedError } from "@/lib/ssrf-guard";
import { findHeaderLeaks, findSourcePatterns, Finding, severityRank } from "@/lib/findings";

export const runtime = "nodejs";

const USER_AGENT = "Sentinel-ID Scanner/2.0 (+https://sentinel-id.net/scan/exposure)";
const FETCH_TIMEOUT_MS = 10000;
const MAX_BODY_BYTES = 3_000_000;
const MAX_REDIRECTS = 3;

const SECRET_PATTERNS: RegExp[] = [
  /\bDB_PASSWORD\s*[:=]\s*\S+/i,
  /\bAPP_KEY\s*[:=]\s*\S+/i,
  /\bDATABASE_URL\s*[:=]\s*\S+/i,
  /\bSECRET_KEY\s*[:=]\s*\S+/i,
  /\bAWS_SECRET_ACCESS_KEY\s*[:=]\s*\S+/i,
  /\bAPI_KEY\s*[:=]\s*\S+/i,
  /\bcore\.repositoryformatversion/i,
  /\bPASSWORD\s*[:=]\s*\S+/i,
  /\bTOKEN\s*[:=]\s*\S+/i,
  /\bJWT_SECRET\s*[:=]\s*\S+/i,
  /\bREDIS_PASSWORD\s*[:=]\s*\S+/i,
  /\bMONGODB_URI\s*[:=]\s*\S+/i,
  /\bPOSTGRES_PASSWORD\s*[:=]\s*\S+/i,
  /\bMYSQL_PASSWORD\s*[:=]\s*\S+/i,
  /\bSTRIPE_SECRET\s*[:=]\s*\S+/i,
  /\bGITHUB_TOKEN\s*[:=]\s*\S+/i,
  /\bSLACK_WEBHOOK\s*[:=]\s*\S+/i,
  /\bSENDGRID_API_KEY\s*[:=]\s*\S+/i,
];

interface ScanRequestBody {
  url?: string;
  sensitivePath?: string;
  ownershipConfirmed?: boolean;
}

function jsonError(message: string, status = 400) {
  return NextResponse.json({ error: message }, { status });
}

async function timedFetch(url: string, init: RequestInit = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, {
      ...init,
      redirect: "manual",
      signal: controller.signal,
      headers: {
        "User-Agent": USER_AGENT,
        Accept: "text/html,application/json,text/plain,*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
        "Pragma": "no-cache",
        ...(init.headers ?? {}),
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

async function readCappedText(res: Response): Promise<string> {
  const reader = res.body?.getReader();
  if (!reader) return await res.text();
  const decoder = new TextDecoder();
  let out = "";
  let bytes = 0;
  while (bytes < MAX_BODY_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    out += decoder.decode(value, { stream: true });
    if (bytes >= MAX_BODY_BYTES) break;
  }
  reader.cancel().catch(() => {});
  return out;
}

async function followRedirects(url: URL, maxRedirects: number = MAX_REDIRECTS): Promise<{ finalUrl: string; redirected: boolean; redirectChain: string[] }> {
  let currentUrl = url;
  let redirectCount = 0;
  const redirectChain: string[] = [currentUrl.toString()];
  let redirected = false;

  while (redirectCount < maxRedirects) {
    const res = await timedFetch(currentUrl.toString(), { method: "GET" });
    
    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const location = res.headers.get("location");
      if (!location) break;
      
      const redirectTarget = new URL(location, currentUrl);
      const revalidated = await assertPublicHttpsTarget(redirectTarget.toString());
      
      if (!isSameOrigin(revalidated.url, currentUrl)) {
        break;
      }
      
      currentUrl = revalidated.url;
      redirectChain.push(currentUrl.toString());
      redirectCount++;
      redirected = true;
    } else {
      return { finalUrl: currentUrl.toString(), redirected, redirectChain };
    }
  }

  return { finalUrl: currentUrl.toString(), redirected, redirectChain };
}

export async function POST(req: NextRequest) {
  let body: ScanRequestBody;
  try {
    body = await req.json();
  } catch {
    return jsonError("Invalid JSON body.");
  }

  if (!body.url || typeof body.url !== "string") {
    return jsonError("`url` is required.");
  }

  let target;
  try {
    target = await assertPublicHttpsTarget(body.url);
  } catch (err) {
    const status = err instanceof SsrfBlockedError ? 403 : 400;
    return jsonError(err instanceof Error ? err.message : "Invalid target.", status);
  }
  const originUrl = target.url;

  const findings: Finding[] = [];
  let headersOut: Record<string, string> = {};
  let homepageHtml = "";
  let finalUrl = originUrl.toString();
  let redirected = false;

  try {
    const { finalUrl: final, redirected: redir, redirectChain } = await followRedirects(originUrl);
    finalUrl = final;
    redirected = redir;

    const res = await timedFetch(finalUrl, { method: "GET" });
    
    res.headers.forEach((value, key) => {
      headersOut[key] = value;
    });
    homepageHtml = await readCappedText(res);

    if (redirectChain.length > 1) {
      findings.push({
        type: "REDIRECT_CHAIN",
        severity: "info",
        evidence: `Redirect chain: ${redirectChain.join(" -> ")}`,
        location: originUrl.toString(),
        recommendation: "Review redirect chain for security implications and performance impact.",
      });
    }

    if (homepageHtml.includes('http://') && finalUrl.startsWith('https://')) {
      findings.push({
        type: "MIXED_CONTENT",
        severity: "medium",
        evidence: "Mixed content detected (HTTP resources on HTTPS page)",
        location: finalUrl,
        recommendation: "Update all resources to use HTTPS to prevent mixed content warnings.",
      });
    }

  } catch (err) {
    const aborted = err instanceof Error && err.name === "AbortError";
    return jsonError(
      aborted ? "Homepage request timed out after 10s." : "Couldn't fetch the homepage.",
      502
    );
  }

  findings.push(...findHeaderLeaks(new Headers(headersOut)));
  findings.push(...findSourcePatterns(homepageHtml, finalUrl));

  if (!headersOut['strict-transport-security']) {
    findings.push({
      type: "MISSING_HSTS",
      severity: "medium",
      evidence: "Strict-Transport-Security header not found",
      location: finalUrl,
      recommendation: "Implement HSTS to enforce HTTPS connections.",
    });
  }

  if (!headersOut['content-security-policy']) {
    findings.push({
      type: "MISSING_CSP",
      severity: "medium",
      evidence: "Content-Security-Policy header not found",
      location: finalUrl,
      recommendation: "Implement CSP to prevent XSS attacks.",
    });
  }

  if (!headersOut['x-frame-options']) {
    findings.push({
      type: "MISSING_XFO",
      severity: "low",
      evidence: "X-Frame-Options header not found",
      location: finalUrl,
      recommendation: "Add X-Frame-Options to prevent clickjacking.",
    });
  }

  try {
    const securityTxtUrl = new URL("/.well-known/security.txt", originUrl);
    const res = await timedFetch(securityTxtUrl.toString(), { method: "GET" });
    if (res.status === 200) {
      const content = await readCappedText(res);
      findings.push({
        type: "SECURITY_TXT_PRESENT",
        severity: "info",
        evidence: `security.txt found with ${content.length} bytes`,
        location: securityTxtUrl.toString(),
        recommendation: "Keep the contact/expiry fields current.",
      });
    }
  } catch {
    // Silent fail
  }

  try {
    const robotsUrl = new URL("/robots.txt", originUrl);
    const res = await timedFetch(robotsUrl.toString(), { method: "GET" });
    if (res.status === 200) {
      const content = await readCappedText(res);
      if (content.includes('Disallow: /')) {
        findings.push({
          type: "ROBOTS_TXT_PRESENT",
          severity: "info",
          evidence: "robots.txt found with disallow rules",
          location: robotsUrl.toString(),
          recommendation: "Review robots.txt to ensure sensitive paths are properly disallowed.",
        });
      }
    }
  } catch {
    // Silent fail
  }

  let sensitivePathResult: {
    checked: string;
    allowed: boolean;
    exposed: boolean;
    statusCode?: number;
    contentType?: string;
    preview?: string;
    reason?: string;
    matchedPatterns?: string[];
  } | null = null;

  if (body.sensitivePath) {
    if (!body.ownershipConfirmed) {
      sensitivePathResult = {
        checked: body.sensitivePath,
        allowed: false,
        exposed: false,
        reason: "Ownership checkbox was not confirmed — path was not checked.",
      };
    } else {
      try {
        const pathUrl = new URL(body.sensitivePath);
        const revalidated = await assertPublicHttpsTarget(pathUrl.toString());

        if (!isSameOrigin(revalidated.url, originUrl)) {
          sensitivePathResult = {
            checked: body.sensitivePath,
            allowed: false,
            exposed: false,
            reason: "The path must be on the same origin as the scanned URL.",
          };
        } else {
          const res = await timedFetch(revalidated.url.toString(), { 
            method: "GET",
            headers: {
              "Cache-Control": "no-cache",
              "Pragma": "no-cache"
            }
          });
          const contentType = res.headers.get("content-type") ?? "";
          const text = res.status === 200 ? await readCappedText(res) : "";
          
          const matchedPatterns: string[] = [];
          SECRET_PATTERNS.forEach((pattern) => {
            if (pattern.test(text)) {
              matchedPatterns.push(pattern.source);
            }
          });

          const exposed = res.status === 200 && matchedPatterns.length > 0;

          sensitivePathResult = {
            checked: revalidated.url.toString(),
            allowed: true,
            exposed,
            statusCode: res.status,
            contentType,
            matchedPatterns: matchedPatterns.length > 0 ? matchedPatterns : undefined,
            preview: exposed ? text.slice(0, 200) : undefined,
          };

          if (exposed) {
            findings.push({
              type: "SENSITIVE_PATH_EXPOSED",
              severity: "critical",
              evidence: `${revalidated.url.pathname} returned 200 with ${matchedPatterns.length} credential pattern(s)`,
              location: revalidated.url.toString(),
              recommendation:
                "Immediately remove this file from public access, rotate ALL exposed credentials, and implement proper access controls.",
            });

            if (matchedPatterns.length >= 3) {
              findings.push({
                type: "MULTIPLE_CREDENTIALS_EXPOSED",
                severity: "critical",
                evidence: `Multiple credential patterns (${matchedPatterns.length}) found in single file`,
                location: revalidated.url.toString(),
                recommendation: "This indicates a comprehensive configuration file exposure - audit all configuration files immediately.",
              });
            }
          }
        }
      } catch (err) {
        sensitivePathResult = {
          checked: body.sensitivePath,
          allowed: false,
          exposed: false,
          reason: err instanceof Error ? err.message : "Couldn't check that path.",
        };
      }
    }
  }

  // Group findings by severity for summary
  const criticalFindings = findings.filter(f => f.severity === "critical");
  const mediumFindings = findings.filter(f => f.severity === "medium");
  const lowFindings = findings.filter(f => f.severity === "low");
  const infoFindings = findings.filter(f => f.severity === "info");

  findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  return NextResponse.json({
    url: originUrl.toString(),
    finalUrl,
    redirected,
    headers: headersOut,
    findings,
    sensitivePathCheck: sensitivePathResult,
    summary: {
      totalFindings: findings.length,
      critical: criticalFindings.length,
      medium: mediumFindings.length,
      low: lowFindings.length,
      info: infoFindings.length,
      secure: findings.length === 0,
      hasExposedCredentials: criticalFindings.some(f => f.type === "SENSITIVE_PATH_EXPOSED"),
    },
    disclaimer: "Passive check only. No exploitation performed.",
    timestamp: new Date().toISOString(),
  });
}