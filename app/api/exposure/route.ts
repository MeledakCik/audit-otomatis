import { NextRequest, NextResponse } from "next/server";
import { assertPublicHttpsTarget, isSameOrigin, SsrfBlockedError } from "@/lib/ssrf-guard";
import { findHeaderLeaks, findSourcePatterns, Finding, severityRank } from "@/lib/findings";

export const runtime = "nodejs"; // needs dns.lookup, not available on edge

const USER_AGENT = "Sentinel-ID Scanner/1.0 (+https://sentinel-id.net/scan/exposure)";
const FETCH_TIMEOUT_MS = 8000;
const MAX_BODY_BYTES = 2_000_000; // 2MB cap when reading homepage HTML

// Secret-looking key=value patterns we check for INSIDE a confirmed
// sensitive-path response. We only ever return whether these patterns
// matched (boolean) plus a short truncated preview — never the file body.
const SECRET_PATTERNS: RegExp[] = [
  /\bDB_PASSWORD\s*=/i,
  /\bAPP_KEY\s*=/i,
  /\bDATABASE_URL\s*=/i,
  /\bSECRET_KEY\s*=/i,
  /\bAWS_SECRET_ACCESS_KEY\s*=/i,
  /\bAPI_KEY\s*=/i,
  /\bcore\.repositoryformatversion/i, // .git/config signature
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
      redirect: "manual", // we handle redirects ourselves, capped at 1
      signal: controller.signal,
      headers: {
        "User-Agent": USER_AGENT,
        Accept: "text/html,application/json,*/*",
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
  }
  reader.cancel().catch(() => {});
  return out;
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

  // ---- Rule 1: validate + resolve the homepage target (SSRF-safe) ----
  let target;
  try {
    target = await assertPublicHttpsTarget(body.url);
  } catch (err) {
    const status = err instanceof SsrfBlockedError ? 403 : 400;
    return jsonError(err instanceof Error ? err.message : "Invalid target.", status);
  }
  const originUrl = target.url;

  const findings: Finding[] = [];
  let finalUrl = originUrl.toString();
  let redirected = false;
  let headersOut: Record<string, string> = {};
  let homepageHtml = "";

  // ---- Rule 1: single GET to homepage, follow at most 1 redirect ----
  try {
    let res = await timedFetch(originUrl.toString(), { method: "GET" });

    if ([301, 302, 303, 307, 308].includes(res.status)) {
      const location = res.headers.get("location");
      if (location) {
        const redirectTarget = new URL(location, originUrl);
        // Re-validate the redirect target through the same SSRF guard,
        // and refuse to hop to a different origin — this scanner reports
        // on the origin the user gave us, not wherever it redirects to.
        const revalidated = await assertPublicHttpsTarget(redirectTarget.toString());
        if (!isSameOrigin(revalidated.url, originUrl)) {
          findings.push({
            type: "CROSS_ORIGIN_REDIRECT",
            severity: "info",
            evidence: `Homepage redirected off-origin to ${revalidated.url.origin} — not followed`,
            location: originUrl.toString(),
            recommendation:
              "Informational only. If this redirect is unexpected, confirm it's intentional (e.g. a canonical domain move) and not a misconfigured DNS/CDN entry.",
          });
        } else {
          redirected = true;
          finalUrl = revalidated.url.toString();
          res = await timedFetch(finalUrl, { method: "GET" });
        }
      }
    }

    finalUrl = res.url || finalUrl;
    res.headers.forEach((value, key) => {
      headersOut[key] = value;
    });
    homepageHtml = await readCappedText(res);
  } catch (err) {
    const aborted = err instanceof Error && err.name === "AbortError";
    return jsonError(
      aborted ? "Homepage request timed out after 8s." : "Couldn't fetch the homepage.",
      502
    );
  }

  // ---- Rule 2: passive header + source analysis (no extra requests) ----
  findings.push(...findHeaderLeaks(new Headers(headersOut)));
  findings.push(...findSourcePatterns(homepageHtml, finalUrl));

  // ---- Rule 2: /.well-known/security.txt is standard + explicitly allowed ----
  try {
    const securityTxtUrl = new URL("/.well-known/security.txt", originUrl);
    const res = await timedFetch(securityTxtUrl.toString(), { method: "GET" });
    if (res.status === 200) {
      findings.push({
        type: "SECURITY_TXT_PRESENT",
        severity: "info",
        evidence: "security.txt found at /.well-known/security.txt",
        location: securityTxtUrl.toString(),
        recommendation:
          "Good practice — no action needed. Keep the contact/expiry fields current.",
      });
    }
  } catch {
    // best-effort, non-fatal
  }

  // ---- Rule 3: optional single sensitive-path check, gated hard ----
  let sensitivePathResult: {
    checked: string;
    allowed: boolean;
    exposed: boolean;
    statusCode?: number;
    contentType?: string;
    preview?: string;
    reason?: string;
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
          const res = await timedFetch(revalidated.url.toString(), { method: "GET" });
          const contentType = res.headers.get("content-type") ?? "";
          const text = res.status === 200 ? await readCappedText(res) : "";
          const matched = SECRET_PATTERNS.some((p) => p.test(text));

          sensitivePathResult = {
            checked: revalidated.url.toString(),
            allowed: true,
            exposed: res.status === 200 && matched,
            statusCode: res.status,
            contentType,
            // Never store/return the full body — 100-char preview only,
            // and only when something actually matched.
            preview: res.status === 200 && matched ? text.slice(0, 100) : undefined,
          };

          if (sensitivePathResult.exposed) {
            findings.push({
              type: "SENSITIVE_PATH_EXPOSED",
              severity: "critical",
              evidence: `${revalidated.url.pathname} returned 200 with credential-shaped content`,
              location: revalidated.url.toString(),
              recommendation:
                "Take this offline immediately: remove the file from the public web root (e.g. public_html), rotate any credentials it contained, and block the path at the web server (nginx: `location ~ /\\.(env|git) { deny all; }`).",
            });
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

  findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  return NextResponse.json({
    url: originUrl.toString(),
    finalUrl,
    redirected,
    headers: headersOut,
    findings,
    sensitivePathCheck: sensitivePathResult,
    disclaimer: "Passive check only. No exploitation performed.",
  });
}
