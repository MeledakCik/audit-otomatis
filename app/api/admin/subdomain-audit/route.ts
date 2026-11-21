import { NextResponse } from "next/server";
import { guardAdmin, noStore } from "@/lib/sentinel/admin-auth";
import { normalizeDomainCheckTarget } from "@/lib/sentinel/domain-check";
import { lookupSubdomainsFromCrtSh } from "@/lib/subdomain-watch/crt";
import { checkSubdomainTakeover } from "@/lib/subdomain-watch/takeover-check";
import type { TakeoverRisk } from "@/lib/subdomain-watch/types";
import { requestPublicHttps } from "@/lib/public-https";
import { assertPublicHttpsTarget, SsrfBlockedError } from "@/lib/ssrf-guard";
import { rateLimit } from "@/lib/sentinel/redis";
import { extractRequestIdentity, logUserActivity } from "@/lib/activity-store";

export const runtime = "nodejs";
export const maxDuration = 300;

type LiveSubdomainResult = {
  host: string;
  statusCode: number | null;
  responseTimeMs: number | null;
  title: string | null;
  server: string | null;
  tlsVersion: string | null;
  csp: boolean;
  hsts: boolean;
  frameProtection: boolean;
  nosniff: boolean;
  fileForms: Array<{ endpoint: string; fields: string[] }>;
  cname: string | null;
  takeoverRisk: TakeoverRisk;
  takeoverReason: string | null;
  edgeChallenge: boolean;
  honeypotSignal: boolean;
  error?: "unreachable" | "non_public";
};

function attribute(attrs: string, name: string) {
  return new RegExp(`(?:^|\\s)${name}\\s*=\\s*(["'])(.*?)\\1`, "i").exec(attrs)?.[2] ?? "";
}

function findFileForms(html: string, origin: string): LiveSubdomainResult["fileForms"] {
  const forms: LiveSubdomainResult["fileForms"] = [];
  for (const match of html.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form\s*>/gi)) {
    const attrs = match[1] ?? "";
    if ((attribute(attrs, "method") || "GET").toUpperCase() !== "POST") continue;
    const fields: string[] = [];
    for (const input of (match[2] ?? "").matchAll(/<input\b([^>]*)>/gi)) {
      const inputAttrs = input[1] ?? "";
      if (attribute(inputAttrs, "type").toLowerCase() !== "file") continue;
      const name = attribute(inputAttrs, "name");
      if (/^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(name)) fields.push(name);
    }
    if (!fields.length) continue;

    const action = (attribute(attrs, "action") || "/").replace(/&amp;/g, "&");
    try {
      const endpoint = new URL(action, origin);
      if (endpoint.origin === origin && endpoint.protocol === "https:" && !endpoint.username && !endpoint.password) {
        forms.push({ endpoint: endpoint.href, fields: [...new Set(fields)] });
      }
    } catch {
      // Skip malformed form actions.
    }
  }
  return forms.slice(0, 20);
}

async function inspectHost(host: string, rootDomain: string): Promise<LiveSubdomainResult> {
  const base: LiveSubdomainResult = {
    host,
    statusCode: null,
    responseTimeMs: null,
    title: null,
    server: null,
    tlsVersion: null,
    csp: false,
    hsts: false,
    frameProtection: false,
    nosniff: false,
    fileForms: [],
    cname: null,
    takeoverRisk: "UNKNOWN",
    takeoverReason: null,
    edgeChallenge: false,
    honeypotSignal: false,
  };
  if (host !== rootDomain && !host.endsWith(`.${rootDomain}`)) return { ...base, error: "unreachable" };

  try {
    const result = await requestPublicHttps(`https://${host}/`, {
      method: "GET",
      signal: AbortSignal.timeout(10_000),
      userAgent: "Sentinel-ID Admin Subdomain Audit/1.0",
      accept: "text/html,application/xhtml+xml,application/json;q=0.8,*/*;q=0.5",
      maxBodyBytes: 16_384,
    });
    const headers = result.headers;
    const body = result.bodyPrefix;
    const title = /<title\b[^>]*>([\s\S]*?)<\/title\s*>/i.exec(body)?.[1]
      ?.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 160) ?? null;
    const origin = `https://${host}`;
    const contentType = headers.get("content-type") ?? "";
    const fileForms = /html/i.test(contentType) ? findFileForms(body, origin) : [];
    const challenge = headers.get("cf-mitigated") === "challenge"
      || /challenge|captcha/i.test(headers.get("x-vercel-mitigated") ?? "")
      || /checking your browser|verify you are human|attention required|cf-chl-/i.test(body);
    const honeypotSignal = headers.has("x-honeypot")
      || headers.has("x-canary-trap")
      || /(?:explicit|known|active) honeypot|honeypot endpoint|canary trap/i.test(body);

    return {
      ...base,
      statusCode: result.statusCode,
      responseTimeMs: result.responseTimeMs,
      title,
      server: headers.get("server"),
      tlsVersion: result.tlsVersion,
      csp: headers.has("content-security-policy"),
      hsts: headers.has("strict-transport-security"),
      frameProtection: headers.has("x-frame-options") || /frame-ancestors/i.test(headers.get("content-security-policy") ?? ""),
      nosniff: /nosniff/i.test(headers.get("x-content-type-options") ?? ""),
      fileForms,
      edgeChallenge: challenge,
      honeypotSignal,
    };
  } catch (error) {
    const nonPublic = error instanceof Error && error.name === "SsrfBlockedError";
    return { ...base, error: nonPublic ? "non_public" : "unreachable" };
  }
}

export async function POST(req: Request) {
  const denied = await guardAdmin(req);
  if (denied) return denied;
  const body = await req.json().catch(() => null) as { domain?: unknown } | null;
  const rootDomain = normalizeDomainCheckTarget(body?.domain);
  if (!rootDomain) {
    return NextResponse.json({ error: "Masukkan domain publik atau URL HTTPS yang valid." }, { status: 400, headers: noStore });
  }
  const scanDomain = rootDomain;

  const identity = extractRequestIdentity(req);
  if (!(await rateLimit("admin-subdomain-audit", identity.ip, 2, 60))) {
    return NextResponse.json({ error: "Batas audit subdomain tercapai. Coba lagi dalam satu menit." }, { status: 429, headers: noStore });
  }

  try {
    await assertPublicHttpsTarget(`https://${rootDomain}/`, AbortSignal.timeout(5000));
  } catch (error) {
    const status = error instanceof SsrfBlockedError ? 422 : 502;
    return NextResponse.json({ error: status === 422 ? "Domain harus mengarah ke alamat publik." : "DNS domain tidak dapat diverifikasi." }, { status, headers: noStore });
  }

  const discovery = await lookupSubdomainsFromCrtSh(rootDomain);
  if (!discovery.ok) {
    return NextResponse.json({ error: discovery.error ?? "Subdomain tidak dapat ditemukan." }, { status: 502, headers: noStore });
  }

  const hosts = [...new Set([rootDomain, ...discovery.subdomains])]
    .filter((host) => host === rootDomain || host.endsWith(`.${rootDomain}`))
    .slice(0, 101);
  const rows: LiveSubdomainResult[] = new Array(hosts.length);
  let cursor = 0;
  async function worker() {
    while (cursor < hosts.length) {
      const index = cursor++;
      const [live, takeover] = await Promise.all([
        inspectHost(hosts[index], scanDomain),
        checkSubdomainTakeover(hosts[index], scanDomain),
      ]);
      rows[index] = {
        ...live,
        cname: takeover.cname,
        takeoverRisk: takeover.risk,
        takeoverReason: takeover.reason,
      };
    }
  }
  await Promise.all(Array.from({ length: Math.min(5, hosts.length) }, () => worker()));

  const liveCount = rows.filter((row) => row.statusCode !== null).length;
  await logUserActivity({
    req,
    ip: identity.ip,
    userAgent: identity.userAgent,
    userId: identity.userId,
    module: "SUBDOMAIN_WATCH",
    action: "Audit live semua subdomain CT oleh admin",
    target: rootDomain,
    status: "SUCCESS",
    summary: `${liveCount}/${rows.length} host merespons; sumber ${discovery.source ?? "CT"}.`,
    meta: { found: discovery.totalBeforeLimit, checked: rows.length, live: liveCount, source: discovery.source },
  }).catch(() => {});

  return NextResponse.json({
    ok: true,
    domain: rootDomain,
    source: discovery.source ?? "CT",
    totalFound: discovery.totalBeforeLimit,
    checked: rows.length,
    truncated: discovery.truncated,
    rows,
  }, { headers: noStore });
}
