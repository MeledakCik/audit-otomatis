import { detectWafAndEdgeInfo } from "@/lib/crawler";
import { isAssessablePage } from "@/lib/tester";
import { validateDomainInput } from "@/lib/validate-domain";
import { runHeaderChecks, scoreFromChecks, gradeFromScore } from "@/lib/header-scan/checks";
import { logUserActivity } from "@/lib/activity-store";

const FETCH_TIMEOUT_MS = 10_000;

interface ScanBody {
  domain?: string;
}

export async function POST(req: Request) {
  let body: ScanBody;
  try {
    body = (await req.json()) as ScanBody;
  } catch {
    return Response.json({ ok: false, error: "Body request tidak valid (harus JSON)." }, { status: 400 });
  }

  const raw = (body.domain ?? "").toString();
  const validation = validateDomainInput(raw);
  if (!validation.ok || !validation.normalizedUrl) {
    return Response.json({ ok: false, error: validation.error ?? "Domain tidak valid." }, { status: 400 });
  }

  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const res = await fetch(validation.normalizedUrl, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": "Sentinel-ID-HeaderArmorChecker/1.0 (+https://www.sentinel-id.net)",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "id-ID,id;q=0.9,en;q=0.8",
      },
    });
    clearTimeout(timeout);

    const rawHeaders: Record<string, string> = {};
    res.headers.forEach((value, key) => {
      rawHeaders[key] = value;
    });

    // Jangan memberi nilai dari halaman blokir/challenge WAF: header-nya milik platform, bukan situs.
    const snippet = (await res.text().catch(() => "")).slice(0, 2000);
    const waf = detectWafAndEdgeInfo(res.status, res.headers, snippet);
    if (!isAssessablePage(res.status, res.headers.get("content-type") ?? "", waf.challenged)) {
      return Response.json(
        {
          ok: false,
          error: `Target membalas HTTP ${res.status}${waf.challenged ? ` (diblokir/challenge ${waf.provider})` : ""}, bukan halaman HTML asli. Header pada respons ini tidak mewakili situs, jadi tidak dinilai. Coba lagi nanti atau cek header dari browser.`,
          statusCode: res.status,
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
      finalUrl: res.url || validation.normalizedUrl,
      statusCode: res.status,
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
      summary: `Skor Header: ${score}/100 (Grade ${grade}) · HTTP ${res.status}`,
      meta: { score, grade, statusCode: res.status },
    });

    return Response.json({ ok: true, report });
  } catch (err) {
    clearTimeout(timeout);
    const aborted = err instanceof Error && err.name === "AbortError";
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
      { status: 502 }
    );
  }
}

function cryptoRandomId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}
