import { validateDomainInput } from "@/lib/validate-domain";

const FETCH_TIMEOUT_MS = 10_000;
const HTML_SNIPPET_LIMIT = 10_000;

/**
 * Proxy homepage fetch untuk menghindari CORS di browser. 100% pasif: satu
 * request GET ke homepage saja (tanpa payload, tanpa file JS terpisah),
 * sama seperti browser biasa membuka halaman tersebut.
 */
export async function GET(req: Request) {
  const { searchParams } = new URL(req.url);
  const raw = searchParams.get("domain") ?? "";

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
        "User-Agent": "Sentinel-ID-StackFingerprint/1.0 (+https://www.sentinel-id.net)",
      },
    });
    clearTimeout(timeout);

    const headers: Record<string, string> = {};
    res.headers.forEach((value, key) => {
      headers[key] = value;
    });

    const fullHtml = await res.text();
    const htmlSnippet = fullHtml.slice(0, HTML_SNIPPET_LIMIT);

    return Response.json({
      ok: true,
      domain: validation.hostname,
      targetUrl: validation.normalizedUrl,
      finalUrl: res.url || validation.normalizedUrl,
      statusCode: res.status,
      headers,
      htmlSnippet,
    });
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
