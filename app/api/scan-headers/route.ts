import { validateDomainInput } from "@/lib/validate-domain";
import { runHeaderChecks, scoreFromChecks, gradeFromScore } from "@/lib/header-scan/checks";

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
    // 100% pasif: satu request GET, tidak ada payload/body, tidak ada follow-up
    // request lain. Ini murni membaca response header, sama seperti browser
    // biasa membuka halaman tersebut.
    const res = await fetch(validation.normalizedUrl, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent": "Sentinel-ID-HeaderArmorChecker/1.0 (+https://www.sentinel-id.net)",
      },
    });
    clearTimeout(timeout);

    const rawHeaders: Record<string, string> = {};
    res.headers.forEach((value, key) => {
      rawHeaders[key] = value;
    });

    const checks = runHeaderChecks(rawHeaders);
    const score = scoreFromChecks(checks);
    const grade = gradeFromScore(score);

    const report = {
      id: cryptoRandomId(),
      createdAt: Date.now(),
      targetUrl: validation.normalizedUrl,
      hostname: validation.hostname ?? new URL(validation.normalizedUrl).hostname,
      finalUrl: res.url || validation.normalizedUrl,
      statusCode: res.status,
      score,
      grade,
      checks,
      rawHeaders,
    };

    return Response.json({ ok: true, report });
  } catch (err) {
    clearTimeout(timeout);
    const aborted = err instanceof Error && err.name === "AbortError";
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
