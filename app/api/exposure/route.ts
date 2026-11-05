import { NextRequest, NextResponse } from "next/server";
import { assertPublicHttpsTarget, isSameOrigin, SsrfBlockedError } from "@/lib/ssrf-guard";
import { findHeaderLeaks, findSourcePatterns, Finding, severityRank } from "@/lib/findings";
import { logUserActivity } from "@/lib/activity-store";
import { publishScanCriticals } from "@/lib/sentinel/publish";

export const runtime = "nodejs";

const USER_AGENT = "Sentinel-ID Scanner/3.5 (+https://sentinel-id.net/scan/exposure; Verified by Google Developer Bandung)";
const FETCH_TIMEOUT_MS = 10000;
const MAX_BODY_BYTES = 3_000_000;
const MAX_REDIRECTS = 3;

const SECRET_PATTERNS: Array<{ name: string; re: RegExp }> = [
  { name: "DB_PASSWORD", re: /\bDB_PASSWORD\s*[:=]\s*\S+/i },
  { name: "APP_KEY", re: /\bAPP_KEY\s*[:=]\s*\S+/i },
  { name: "DATABASE_URL", re: /\bDATABASE_URL\s*[:=]\s*\S+/i },
  { name: "SECRET_KEY", re: /\bSECRET_KEY\s*[:=]\s*\S+/i },
  { name: "AWS_SECRET_ACCESS_KEY", re: /\bAWS_SECRET_ACCESS_KEY\s*[:=]\s*\S+|aws_secret_access_key\s*=\s*\S+|AKIA[0-9A-Z]{16}/i },
  { name: "API_KEY", re: /\bAPI_KEY\s*[:=]\s*\S+/i },
  { name: "GIT_CONFIG_OR_REF", re: /\bcore\.repositoryformatversion|^ref:\s*refs\/heads\//im },
  { name: "WP_CONFIG_DEFINE", re: /define\(\s*['"](?:DB_PASSWORD|AUTH_KEY|SECURE_AUTH_KEY)['"]/i },
  { name: "PRIVATE_KEY_HEADER", re: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/ },
  { name: "JWT_SECRET", re: /\bJWT_SECRET\s*[:=]\s*\S+/i },
  { name: "REDIS_PASSWORD", re: /\bREDIS_PASSWORD\s*[:=]\s*\S+/i },
  { name: "MONGODB_URI", re: /\bMONGODB_URI\s*[:=]\s*\S+/i },
  { name: "POSTGRES_PASSWORD", re: /\bPOSTGRES_PASSWORD\s*[:=]\s*\S+/i },
  { name: "MYSQL_PASSWORD", re: /\bMYSQL_PASSWORD\s*[:=]\s*\S+/i },
  { name: "STRIPE_SECRET", re: /\bSTRIPE_SECRET\s*[:=]\s*\S+/i },
  { name: "GITHUB_TOKEN", re: /\bGITHUB_TOKEN\s*[:=]\s*\S+/i },
  { name: "SLACK_WEBHOOK", re: /\bSLACK_WEBHOOK\s*[:=]\s*\S+/i },
  { name: "SENDGRID_API_KEY", re: /\bSENDGRID_API_KEY\s*[:=]\s*\S+/i },
  // Deep Shell & Runtime Surface markers (wp2shell, php2shell, node2shell, go2shell, py2shell, node out of bound)
  { name: "WP2SHELL_DEBUG_OR_XMLRPC", re: /XML-RPC server accepts POST requests only|\[\d{2}-[A-Za-z]{3}-\d{4}.*PHP\s+(?:Notice|Warning|Fatal error)/i },
  { name: "PHP2SHELL_IGNITION_OR_PHPINFO", re: /"can_execute_commands"\s*:|<title>[^<]*phpinfo\(\)|eval-stdin\.php/i },
  { name: "NODE2SHELL_V8_INSPECTOR_OR_PM2", re: /"webSocketDebuggerUrl"\s*:\s*"ws|module\.exports\s*=[\s\S]*apps\s*:/i },
  { name: "GO2SHELL_PPROF_OR_EXPVAR", re: /Types of profiles available|"memstats"\s*:\s*\{/i },
  { name: "PY2SHELL_WERKZEUG_OR_JUPYTER", re: /<title>[^<]*Werkzeug|"execution_state"\s*:\s*"(?:idle|busy)"/i },
  { name: "NODE_OOB_HEAPDUMP_OR_BUFFER", re: /"snapshot"\s*:\s*\{[\s\S]*"nodes"\s*:\s*\[|ERR_BUFFER_OUT_OF_BOUNDS/i },
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
        Pragma: "no-cache",
        ...(init.headers ?? {}),
      },
    });
  } finally {
    clearTimeout(timer);
  }
}

async function readCappedBytes(res: Response): Promise<{ text: string; head: Uint8Array }> {
  const reader = res.body?.getReader();
  if (!reader) {
    const buf = Buffer.from(await res.arrayBuffer());
    return {
      text: buf.subarray(0, MAX_BODY_BYTES).toString("utf8"),
      head: new Uint8Array(buf.subarray(0, 8)),
    };
  }
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  while (bytes < MAX_BODY_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    bytes += value.byteLength;
    if (bytes >= MAX_BODY_BYTES) break;
  }
  reader.cancel().catch(() => {});
  const buf = Buffer.concat(chunks.map((c) => Buffer.from(c))).subarray(0, MAX_BODY_BYTES);
  return {
    text: buf.toString("utf8"),
    head: new Uint8Array(buf.subarray(0, 8)),
  };
}

async function followRedirects(
  url: URL,
  maxRedirects: number = MAX_REDIRECTS
): Promise<{ finalUrl: string; redirected: boolean; redirectChain: string[] }> {
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
  const domainHost = originUrl.hostname.toLowerCase();

  const findings: Finding[] = [];
  const headersOut: Record<string, string> = {};
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
    homepageHtml = (await readCappedBytes(res)).text;

    if (redirectChain.length > 1) {
      findings.push({
        type: "REDIRECT_CHAIN",
        severity: "info",
        evidence: `Redirect chain: ${redirectChain.join(" -> ")}`,
        location: originUrl.toString(),
        recommendation: "Review redirect chain for security implications and performance impact.",
      });
    }

    if (homepageHtml.includes("http://") && finalUrl.startsWith("https://")) {
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

  if (!headersOut["strict-transport-security"]) {
    findings.push({
      type: "MISSING_HSTS",
      severity: "medium",
      evidence: "Strict-Transport-Security header not found",
      location: finalUrl,
      recommendation: "Implement HSTS to enforce HTTPS connections.",
    });
  }

  if (!headersOut["content-security-policy"]) {
    findings.push({
      type: "MISSING_CSP",
      severity: "medium",
      evidence: "Content-Security-Policy header not found",
      location: finalUrl,
      recommendation: "Implement CSP to prevent XSS attacks.",
    });
  }

  if (!headersOut["x-frame-options"]) {
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
      const content = (await readCappedBytes(res)).text;
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
      const content = (await readCappedBytes(res)).text;
      if (content.includes("Disallow: /")) {
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
    vaultStored?: boolean;
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
        const rawPath = body.sensitivePath.trim();
        const pathUrl = rawPath.startsWith("http")
          ? new URL(rawPath)
          : new URL(rawPath.startsWith("/") ? rawPath : `/${rawPath}`, originUrl);
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
              Pragma: "no-cache",
            },
          });
          const contentType = res.headers.get("content-type") ?? "";
          const { text, head } =
            res.status === 200 || res.status === 405
              ? await readCappedBytes(res)
              : { text: "", head: new Uint8Array(8) };

          const matchedPatterns: string[] = [];
          if (
            head[0] === 0x50 &&
            head[1] === 0x4b &&
            head[2] === 0x03 &&
            head[3] === 0x04
          ) {
            matchedPatterns.push("ZIP_ARCHIVE_MAGIC_PK0304");
          }
          SECRET_PATTERNS.forEach((p) => {
            if (p.re.test(text)) {
              matchedPatterns.push(p.name);
            }
          });

          const exposed = (res.status === 200 || res.status === 405) && matchedPatterns.length > 0;
          let vaultStored = false;

          if (exposed) {
            // Simpan bukti mentah terenkripsi AES-256-GCM ke Vault Admin tanpa membocorkan nilai rahasia ke publik
            try {
              await publishScanCriticals(
                domainHost,
                [
                  {
                    domain: domainHost,
                    severity: "CRITICAL",
                    finding: `Sensitive Path Exposed (${revalidated.url.pathname})`,
                    evidence_public: `HTTP ${res.status} — cocok pola [${matchedPatterns.join(", ")}] (nilai rahasia dienkripsi AES-256-GCM di Admin Vault)`,
                    fix: "Hapus file dari webroot, blokir akses di web server, dan rotasi seluruh kredensial.",
                  },
                ],
                [
                  {
                    domain: domainHost,
                    path: revalidated.url.pathname,
                    status: res.status,
                    contentType: contentType.toLowerCase(),
                    marker: matchedPatterns.join(", "),
                    snippet: text.slice(0, 2048),
                  },
                ]
              );
              vaultStored = true;
            } catch {
              vaultStored = false;
            }
          }

          sensitivePathResult = {
            checked: revalidated.url.toString(),
            allowed: true,
            exposed,
            vaultStored,
            statusCode: res.status,
            contentType,
            matchedPatterns: matchedPatterns.length > 0 ? matchedPatterns : undefined,
            preview: exposed
              ? `[REDACTED PUBLIC VIEW — Nilai rahasia tidak pernah bocor ke publik. Bukti mentah (${matchedPatterns.join(
                  ", "
                )}) telah dienkripsi dengan AES-256-GCM dan disimpan di Brankas Vault Admin untuk diklaim pemilik sah domain.]`
              : undefined,
          };

          if (exposed) {
            findings.push({
              type: "SENSITIVE_PATH_EXPOSED",
              severity: "critical",
              evidence: `${revalidated.url.pathname} mengembalikan HTTP ${res.status} dengan penanda [${matchedPatterns.join(", ")}] — bukti dienkripsi AES-256-GCM ke Admin Vault`,
              location: revalidated.url.toString(),
              recommendation:
                "Segera hapus file/endpoint dari akses publik, rotasi seluruh kredensial yang terdampak, dan klaim bukti terenkripsi melalui panel Sentinel Vault.",
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

  const criticalFindings = findings.filter((f) => f.severity === "critical");
  const mediumFindings = findings.filter((f) => f.severity === "medium");
  const lowFindings = findings.filter((f) => f.severity === "low");
  const infoFindings = findings.filter((f) => f.severity === "info");

  findings.sort((a, b) => severityRank(b.severity) - severityRank(a.severity));

  await logUserActivity({
    req,
    module: "EXPOSURE_CHECK",
    action: "Pemeriksaan Eksposur File Sensitif & Deep Shell Surface",
    target: originUrl.hostname,
    status: criticalFindings.length > 0 ? "CRITICAL" : mediumFindings.length > 0 ? "WARNING" : "SUCCESS",
    summary: `${findings.length} temuan (${criticalFindings.length} critical masuk Vault AES-256-GCM, ${mediumFindings.length} medium)`,
    meta: { totalFindings: findings.length, critical: criticalFindings.length },
  });

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
      hasExposedCredentials: criticalFindings.some((f) => f.type === "SENSITIVE_PATH_EXPOSED"),
    },
    disclaimer:
      "100% Passive GET-only check. Nilai rahasia tidak pernah bocor ke publik dan disimpan terenkripsi AES-256-GCM di Vault Admin. Sudah terverifikasi oleh Google Developer Bandung.",
    timestamp: new Date().toISOString(),
  });
}