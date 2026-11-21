import { NextResponse } from "next/server";
import { guardAdmin, noStore } from "@/lib/sentinel/admin-auth";
import { getAdminAuditTarget } from "@/lib/sentinel/authorized-targets";
import { parseCurlPost, type ParsedCurlPost } from "@/lib/sentinel/curl-post";
import { requestPublicHttps } from "@/lib/public-https";
import { rateLimit } from "@/lib/sentinel/redis";
import { extractRequestIdentity, logUserActivity } from "@/lib/activity-store";
import { SsrfBlockedError } from "@/lib/ssrf-guard";

export const runtime = "nodejs";
export const maxDuration = 15;

function displaySafeUrl(url: URL) {
  const safe = new URL(url.href);
  for (const key of safe.searchParams.keys()) safe.searchParams.set(key, "[redacted]");
  safe.pathname = safe.pathname.replace(/\/[A-Za-z0-9_-]{32,}(?=\/|$)/g, "/[redacted]");
  return safe.href;
}

export async function POST(req: Request) {
  const denied = await guardAdmin(req);
  if (denied) return denied;
  if (!/^application\/json\b/i.test(req.headers.get("content-type") ?? "")) {
    return NextResponse.json({ error: "Kirim data cURL dalam JSON." }, { status: 415, headers: noStore });
  }

  const body = await req.json().catch(() => null) as { domain?: unknown; command?: unknown } | null;
  const target = getAdminAuditTarget(body?.domain);
  if (!target) return NextResponse.json({ error: "Domain scope tidak valid." }, { status: 400, headers: noStore });

  let parsedRequest: ParsedCurlPost;
  try {
    parsedRequest = parseCurlPost(body?.command, target.domain);
  } catch (error) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "Perintah cURL tidak valid." }, { status: 400, headers: noStore });
  }

  const identity = extractRequestIdentity(req);
  if (!(await rateLimit("admin-curl-post", identity.ip, 5, 60))) {
    return NextResponse.json({ error: "Batas POST live tercapai. Maksimal 5 per menit." }, { status: 429, headers: noStore });
  }

  const timeout = AbortSignal.timeout(8000);
  try {
    const result = await requestPublicHttps(parsedRequest.url.href, {
      method: "POST",
      signal: AbortSignal.any([timeout, req.signal]),
      userAgent: "Sentinel-ID Admin POST Replay/1.0",
      accept: "application/json,text/plain,text/html;q=0.8,*/*;q=0.5",
      contentType: parsedRequest.contentType,
      ...(parsedRequest.accept ? { accept: parsedRequest.accept } : {}),
      ...(parsedRequest.authorization ? { authorization: parsedRequest.authorization } : {}),
      ...(parsedRequest.cookie ? { cookie: parsedRequest.cookie } : {}),
      ...(parsedRequest.origin ? { origin: parsedRequest.origin } : {}),
      ...(parsedRequest.referer ? { referer: parsedRequest.referer } : {}),
      body: parsedRequest.body,
      maxBodyBytes: 4096,
    });
    const contentType = result.headers.get("content-type") ?? "unknown";
    const preview = result.bodyPrefix
      .replace(/<[^>]*>/g, " ")
      .replace(/(?:bearer\s+)[A-Za-z0-9._~+/-]+=*/gi, "Bearer [redacted]")
      .replace(/((?:token|password|secret|api[_-]?key)\s*["':= ]\s*)[^\s,"'}&<]+/gi, "$1[redacted]")
      .replace(/\s+/g, " ")
      .trim()
      .slice(0, 320);
    const honeypotSignal = result.headers.has("x-honeypot")
      || result.headers.has("x-canary-trap")
      || /(?:explicit|known|active) honeypot|honeypot endpoint|canary trap/i.test(result.bodyPrefix);
    const edgeChallenge = result.headers.get("cf-mitigated") === "challenge"
      || /challenge|captcha/i.test(result.headers.get("x-vercel-mitigated") ?? "")
      || /checking your browser|verify you are human|attention required|cf-chl-/i.test(result.bodyPrefix);
    const statusAccepted = result.statusCode >= 200 && result.statusCode < 300;
    const classification = honeypotSignal
      ? "honeypot_signal"
      : edgeChallenge
        ? "edge_challenge"
        : statusAccepted
          ? "application_response"
          : "rejected_or_error";

    await logUserActivity({
      req,
      ip: identity.ip,
      userAgent: identity.userAgent,
      userId: identity.userId,
      module: "FULL_SCAN",
      action: "Admin live POST replay",
      target: parsedRequest.url.hostname,
      status: statusAccepted ? "SUCCESS" : "WARNING",
      summary: `POST ${parsedRequest.url.hostname}${parsedRequest.url.pathname} → HTTP ${result.statusCode} (${classification}).`,
      meta: { method: "POST", statusCode: result.statusCode, classification },
    }).catch(() => {});

    return NextResponse.json({
      method: "POST",
      url: displaySafeUrl(parsedRequest.url),
      statusCode: result.statusCode,
      accepted: statusAccepted,
      responseTimeMs: result.responseTimeMs,
      responseContentType: contentType,
      responsePreview: preview,
      responseTruncated: result.bodyTruncated,
      bodyEchoed: parsedRequest.body.length > 0 && result.bodyPrefix.includes(parsedRequest.body.toString("utf8")),
      honeypotSignal,
      edgeChallenge,
      classification,
      note: "Indikator honeypot bersifat heuristik. Respons 2xx hanya membuktikan server menjawab POST, bukan bahwa kerentanan berhasil dieksploitasi.",
    }, { headers: noStore });
  } catch (error) {
    if (error instanceof SsrfBlockedError) {
      return NextResponse.json({ error: "Target POST harus mengarah ke alamat publik." }, { status: 422, headers: noStore });
    }
    if (timeout.aborted) {
      return NextResponse.json({ error: "Target POST tidak merespons dalam 8 detik." }, { status: 504, headers: noStore });
    }
    return NextResponse.json({ error: "Gagal membuat koneksi HTTPS ke target POST." }, { status: 502, headers: noStore });
  }
}
