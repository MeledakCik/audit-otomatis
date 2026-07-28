import { getScan } from "@/lib/scan-store";
import { chromeHeaders } from "@/lib/crawler";
import { isPrivateOrReservedHost } from "@/lib/validate-domain";

export const runtime = "nodejs";

const TIMEOUT_MS = 8000;
const MAX_BODY_PREVIEW = 4000;

const SAFE_RESPONSE_HEADERS = [
  "content-type",
  "content-length",
  "server",
  "cache-control",
  "x-powered-by",
  "x-frame-options",
  "content-security-policy",
  "strict-transport-security",
  "access-control-allow-origin",
  "etag",
  "last-modified",
  "date",
  "cf-ray",
  "cf-cache-status",
  "cf-mitigated",
];

export async function POST(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const scan = await getScan(id);
  if (!scan) {
    return Response.json({ error: "Scan tidak ditemukan atau sudah kedaluwarsa." }, { status: 404 });
  }

  let body: { url?: string };
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "Body request tidak valid." }, { status: 400 });
  }

  const rawUrl = body.url;
  if (!rawUrl || typeof rawUrl !== "string") {
    return Response.json({ error: "Field 'url' wajib diisi." }, { status: 400 });
  }

  let target: URL;
  try {
    target = new URL(rawUrl);
  } catch {
    return Response.json({ error: "URL tidak valid." }, { status: 400 });
  }

  let scanOrigin: URL;
  try {
    scanOrigin = new URL(scan.origin);
  } catch {
    return Response.json({ error: "Origin scan tidak valid." }, { status: 400 });
  }

  if (target.origin !== scanOrigin.origin) {
    return Response.json(
      { error: "Cuma boleh uji endpoint same-origin dengan target scan ini (kebijakan same-origin only)." },
      { status: 403 }
    );
  }

  if (target.protocol !== "https:" && target.protocol !== "http:") {
    return Response.json({ error: "Skema URL tidak didukung." }, { status: 400 });
  }

  if (isPrivateOrReservedHost(target.hostname)) {
    return Response.json({ error: "Host ini diblokir (SSRF guard)." }, { status: 403 });
  }

  const started = Date.now();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    // GET-only, selalu — walaupun endpoint yang dipilih terdeteksi sebagai
    // POST/PUT/dst di daftar, request nyata yang dikirim tetap GET supaya
    // tidak pernah memicu efek samping (create/update/delete) di server
    // target secara otomatis.
    const res = await fetch(target.toString(), {
      method: "GET",
      headers: chromeHeaders(),
      redirect: "follow",
      signal: controller.signal,
    });

    const text = await res.text();
    const timeMs = Date.now() - started;

    const headers: Record<string, string> = {};
    for (const key of SAFE_RESPONSE_HEADERS) {
      const v = res.headers.get(key);
      if (v) headers[key] = v;
    }

    const truncated = text.length > MAX_BODY_PREVIEW;
    const bodyPreview = truncated ? text.slice(0, MAX_BODY_PREVIEW) : text;

    return Response.json({
      ok: true,
      status: res.status,
      statusText: res.statusText,
      timeMs,
      headers,
      bodyPreview,
      truncated,
      bodyLength: text.length,
      finalUrl: res.url,
    });
  } catch (err) {
    const timeMs = Date.now() - started;
    const aborted = err instanceof Error && err.name === "AbortError";
    return Response.json({
      ok: false,
      error: aborted ? `Timeout setelah ${TIMEOUT_MS}ms.` : err instanceof Error ? err.message : "Request gagal.",
      timeMs,
    });
  } finally {
    clearTimeout(timer);
  }
}