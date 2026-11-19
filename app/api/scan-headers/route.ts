import { detectWafAndEdgeInfo } from "@/lib/crawler";
import { isAssessablePage } from "@/lib/tester";
import { validateDomainInput } from "@/lib/validate-domain";
import { runHeaderChecks, scoreFromChecks, gradeFromScore } from "@/lib/header-scan/checks";
import { logUserActivity } from "@/lib/activity-store";
import { requestPublicHttps } from "@/lib/public-https";
import { SsrfBlockedError } from "@/lib/ssrf-guard";

export const runtime = "nodejs";
export const maxDuration = 15;
const FETCH_TIMEOUT_MS = 10_000;
const MAX_REDIRECTS = 4;
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

async function readPage(url: string, signal: AbortSignal) {
  let response = await requestPublicHttps(url, requestOptions(signal));
  let redirects = 0;
  while (REDIRECT_STATUSES.has(response.statusCode)) {
    const location = response.headers.get("location");
    if (!location) break;
    if (redirects === MAX_REDIRECTS) throw new Error("Terlalu banyak pengalihan.");
    response = await requestPublicHttps(new URL(location, response.url).href, requestOptions(signal));
    redirects += 1;
  }
  return response;
}

function requestOptions(signal: AbortSignal) {
  return {
    method: "GET" as const,
    userAgent: "Sentinel-ID-HeaderArmorChecker/1.0 (+https://www.sentinel-id.net)",
    accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    maxBodyBytes: 2000,
    signal,
  };
}

interface ScanBody {
  domain?: string;
}

export async function POST(req: Request) {
  const body = await req.json().catch(() => null) as ScanBody | null;
  if (!body || typeof body.domain !== "string") {
    return Response.json({ ok: false, error: "Body request tidak valid (harus JSON)." }, { status: 400 });
  }

  const raw = body.domain;
  const validation = validateDomainInput(raw);
  if (!validation.ok || !validation.normalizedUrl) {
    return Response.json({ ok: false, error: validation.error ?? "Domain tidak valid." }, { status: 400 });
  }

  const timeout = AbortSignal.timeout(FETCH_TIMEOUT_MS);
  const signal = AbortSignal.any([timeout, req.signal]);

  try {
    const res = await readPage(validation.normalizedUrl, signal);
    const rawHeaders = Object.fromEntries(res.headers);

    // Jangan memberi nilai dari halaman blokir/challenge WAF: header-nya milik platform, bukan situs.
    const waf = detectWafAndEdgeInfo(res.statusCode, res.headers, res.bodyPrefix);
    if (!isAssessablePage(res.statusCode, res.headers.get("content-type") ?? "", waf.challenged)) {
      return Response.json(
        {
          ok: false,
          error: `Target membalas HTTP ${res.statusCode}${waf.challenged ? ` (diblokir/challenge ${waf.provider})` : ""}. Header respons tersedia untuk inspeksi. Penilaian memerlukan halaman HTML utama.`,
          statusCode: res.statusCode,
          rawHeaders,
        },
        { status: 422 }
      );
    }

    const checks = runHeaderChecks(rawHeaders);
    const score = scoreFromChecks(checks);
    const grade = gradeFromScore(score);
    const hostname = validation.hostname ?? new URL(validation.normalizedUrl).hostname;

    const report = {
      id: cryptoRandomId(),
      createdAt: Date.now(),
      targetUrl: validation.normalizedUrl,
      hostname,
      finalUrl: res.url.href,
      statusCode: res.statusCode,
      score,
      grade,
      checks,
      rawHeaders,
    };

    await logUserActivity({
      req,
      module: "HEADER_ARMOR",
      action: "Audit HTTP Security Headers",
      target: hostname,
      status: score < 50 ? "WARNING" : "SUCCESS",
      summary: `Skor Header: ${score}/100 (Grade ${grade}) · HTTP ${res.statusCode}`,
      meta: { score, grade, statusCode: res.statusCode },
    });

    return Response.json({ ok: true, report });
  } catch (err) {
    if (err instanceof SsrfBlockedError) {
      return Response.json({ ok: false, error: "Target atau tujuan pengalihan harus menggunakan HTTPS dan alamat publik." }, { status: 422 });
    }
    const aborted = timeout.aborted;
    await logUserActivity({
      req,
      module: "HEADER_ARMOR",
      action: "Audit HTTP Security Headers Gagal",
      target: validation.hostname ?? raw,
      status: "ERROR",
      summary: aborted ? "Timeout 10s" : "Gagal menghubungi target",
    });
    return Response.json(
      {
        ok: false,
        error: aborted
          ? "Timeout — target tidak merespons dalam 10 detik."
          : "Gagal menghubungi target. Pastikan domain aktif dan dapat diakses publik.",
      },
      { status: aborted ? 504 : 502 }
    );
  }
}

function cryptoRandomId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}
