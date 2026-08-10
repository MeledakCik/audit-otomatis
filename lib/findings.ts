export type Severity = "critical" | "medium" | "low" | "info";

export interface Finding {
  type: string;
  severity: Severity;
  evidence: string;
  location: string;
  recommendation: string;
}

/** Truncate a string for display without ever echoing a full secret/body. */
function truncate(s: string, max = 100): string {
  const clean = s.replace(/\s+/g, " ").trim();
  return clean.length > max ? clean.slice(0, max) + "…" : clean;
}

/**
 * Inspect response headers for information disclosure. Passive only —
 * reads headers already returned by the single homepage request.
 */
export function findHeaderLeaks(headers: Headers): Finding[] {
  const findings: Finding[] = [];

  const server = headers.get("server");
  if (server && /[0-9]/.test(server)) {
    findings.push({
      type: "SERVER_VERSION_DISCLOSURE",
      severity: "low",
      evidence: `Server: ${truncate(server)}`,
      location: "response headers",
      recommendation:
        "Strip or generalize the Server header (e.g. `server_tokens off;` on nginx, or remove the header at your CDN/load balancer) so software versions aren't advertised to every visitor.",
    });
  }

  const poweredBy = headers.get("x-powered-by");
  if (poweredBy) {
    findings.push({
      type: "X_POWERED_BY_DISCLOSURE",
      severity: "low",
      evidence: `X-Powered-By: ${truncate(poweredBy)}`,
      location: "response headers",
      recommendation:
        "Disable the X-Powered-By header (e.g. `app.disable('x-powered-by')` in Express, or an equivalent setting in your framework) to avoid fingerprinting your stack.",
    });
  }

  const missingHsts = !headers.get("strict-transport-security");
  if (missingHsts) {
    findings.push({
      type: "MISSING_HSTS",
      severity: "info",
      evidence: "No Strict-Transport-Security header on the homepage response",
      location: "response headers",
      recommendation:
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains` once you're confident all subdomains serve HTTPS.",
    });
  }

  return findings;
}

/**
 * Scan homepage HTML/JS text for accidental exposure patterns. This is
 * pure string matching over content already fetched for the homepage —
 * no extra requests are made here.
 */
export function findSourcePatterns(html: string, pageUrl: string): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();

  const push = (f: Finding) => {
    const key = f.type + f.evidence;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push(f);
  };

  // --- S3 / GCS bucket URLs referenced in markup or inline/linked JS ---
  const bucketPattern = /https?:\/\/([a-z0-9.\-]+\.s3(?:[.\-][a-z0-9-]+)?\.amazonaws\.com|s3\.amazonaws\.com\/[a-z0-9.\-]+|storage\.googleapis\.com\/[a-z0-9.\-_]+)/gi;
  for (const match of html.matchAll(bucketPattern)) {
    push({
      type: "CLOUD_STORAGE_URL",
      severity: "medium",
      evidence: `${truncate(match[0])} found in page source`,
      location: pageUrl,
      recommendation:
        "Confirm this bucket's access policy is intentional. If it isn't meant to be public, set it to private / block public access at the bucket level, and serve assets through signed URLs or a CDN instead of a public bucket link.",
    });
  }

  // --- .env referenced by path in HTML/JS (e.g. a fetch('/.env') or link) ---
  const envRefPattern = /(["'\/])(?:\.\.?\/)?\.env(?:\.[a-z]+)?["'\s)]/gi;
  if (envRefPattern.test(html)) {
    push({
      type: "ENV_FILE_REFERENCED",
      severity: "medium",
      evidence: ".env referenced in page source",
      location: pageUrl,
      recommendation:
        "A reference to a .env path in your shipped code/markup is worth a look even if it's just a build artifact. Make sure the actual .env file lives outside your web root and is excluded from your deploy bundle.",
    });
  }

  // --- source maps ---
  const sourceMapPattern = /\/\/[#@]\s*sourceMappingURL=([^\s*"']+)/i;
  const sourceMapMatch = html.match(sourceMapPattern);
  if (sourceMapMatch) {
    push({
      type: "SOURCE_MAP_REFERENCE",
      severity: "low",
      evidence: `sourceMappingURL=${truncate(sourceMapMatch[1])}`,
      location: pageUrl,
      recommendation:
        "If this is a production build, consider excluding .map files from the public deploy — they make it trivial to reconstruct readable source from your bundles.",
    });
  }

  // --- .git reference in markup (rare, but sometimes linked by mistake) ---
  const gitRefPattern = /(["'\/])(?:\.\.?\/)?\.git\//i;
  if (gitRefPattern.test(html)) {
    push({
      type: "GIT_PATH_REFERENCED",
      severity: "medium",
      evidence: ".git/ path referenced in page source",
      location: pageUrl,
      recommendation:
        "A .git/ reference in shipped markup/JS is unusual. Verify your deploy pipeline excludes the .git directory from the web root, and block it at the web server (e.g. `location ~ /\\.git { deny all; }` on nginx).",
    });
  }

  return findings;
}

export function severityRank(s: Severity): number {
  return { critical: 3, medium: 2, low: 1, info: 0 }[s];
}
