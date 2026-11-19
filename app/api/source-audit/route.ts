/**
 * POST /api/source-audit — audit kode sumber dari arsip ZIP (multipart, field "file").
 *
 * Keamanan endpoint:
 * - Ukuran dicek dari Content-Length SEBELUM body dibaca, lalu dicek ulang dari isi.
 * - Validasi magic bytes ZIP (PK\x03\x04), bukan hanya ekstensi.
 * - Rate limit per IP (sliding window) + batas waktu analisis.
 * - Arsip diproses di memori lalu dibuang; tidak ada berkas/kode yang disimpan.
 */
import { analyzeSourceZip } from "@/lib/source-audit/analyze";
import { ZipError } from "@/lib/source-audit/zip";
import { logUserActivity, extractRequestIdentity } from "@/lib/activity-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 60;

// Vercel Functions menolak body > 4.5 MB; sisakan ruang untuk overhead multipart.
const MAX_UPLOAD_BYTES = 4 * 1024 * 1024;
const ANALYSIS_TIMEOUT_MS = 50_000;
const WINDOW_MS = 10 * 60_000;
const MAX_PER_WINDOW = 8;

const hits = new Map<string, number[]>();
function rateLimited(ip: string): { limited: boolean; retryAfter: number; remaining: number } {
  const now = Date.now();
  const list = (hits.get(ip) ?? []).filter((t) => now - t < WINDOW_MS);
  if (hits.size > 5000) hits.clear();
  if (list.length >= MAX_PER_WINDOW) {
    return { limited: true, retryAfter: Math.ceil((WINDOW_MS - (now - list[0])) / 1000), remaining: 0 };
  }
  list.push(now);
  hits.set(ip, list);
  return { limited: false, retryAfter: 0, remaining: MAX_PER_WINDOW - list.length };
}

function json(body: unknown, status = 200, extra: Record<string, string> = {}) {
  return Response.json(body, {
    status,
    headers: { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", ...extra },
  });
}

export async function POST(req: Request) {
  const { ip } = extractRequestIdentity(req);
  const rl = rateLimited(ip);
  const rlHeaders = {
    "RateLimit-Policy": `${MAX_PER_WINDOW};w=${WINDOW_MS / 1000}`,
    RateLimit: `limit=${MAX_PER_WINDOW}, remaining=${rl.remaining}, reset=${rl.retryAfter || WINDOW_MS / 1000}`,
  };
  if (rl.limited) {
    return json({ ok: false, error: `Terlalu banyak audit. Coba lagi dalam ${Math.ceil(rl.retryAfter / 60)} menit.` }, 429, {
      ...rlHeaders,
      "Retry-After": String(rl.retryAfter),
    });
  }

  const declared = Number(req.headers.get("content-length") ?? "0");
  if (declared > MAX_UPLOAD_BYTES + 64 * 1024) {
    return json({ ok: false, error: "Arsip terlalu besar (maks 4 MB). Buang node_modules, .git, dan folder build sebelum mengompres." }, 413, rlHeaders);
  }
  if (!/multipart\/form-data/i.test(req.headers.get("content-type") ?? "")) {
    return json({ ok: false, error: "Kirim sebagai multipart/form-data dengan field \"file\"." }, 415, rlHeaders);
  }

  let file: File | null = null;
  try {
    const form = await req.formData();
    const f = form.get("file");
    file = f instanceof File ? f : null;
  } catch {
    return json({ ok: false, error: "Form upload tidak valid." }, 400, rlHeaders);
  }
  if (!file) return json({ ok: false, error: "Berkas ZIP tidak ditemukan pada field \"file\"." }, 400, rlHeaders);
  if (file.size === 0 || file.size > MAX_UPLOAD_BYTES) {
    return json({ ok: false, error: "Ukuran arsip harus antara 1 byte dan 4 MB." }, 413, rlHeaders);
  }

  const buf = Buffer.from(await file.arrayBuffer());
  if (buf.length < 4 || buf.readUInt32LE(0) !== 0x04034b50) {
    return json({ ok: false, error: "Berkas bukan ZIP (signature PK tidak ditemukan)." }, 400, rlHeaders);
  }
  const safeName = (file.name || "source.zip").replace(/[^\w.\- ]+/g, "_").slice(0, 120);

  try {
    const report = await Promise.race([
      analyzeSourceZip(buf, safeName),
      new Promise<never>((_, reject) => setTimeout(() => reject(new Error("TIMEOUT")), ANALYSIS_TIMEOUT_MS)),
    ]);

    await logUserActivity({
      req,
      module: "SOURCE_AUDIT",
      action: "Audit Kode Sumber (ZIP)",
      target: safeName,
      status: report.counts.CRITICAL > 0 ? "CRITICAL" : report.counts.HIGH > 0 ? "WARNING" : "SUCCESS",
      summary: `Skor ${report.score}/100 (${report.grade}) · ${report.stats.filesScanned} berkas · ${report.findings.length} temuan · ${report.dependencies.vulnerable.length} dependensi rentan`,
      meta: { score: report.score, critical: report.counts.CRITICAL, high: report.counts.HIGH },
    }).catch(() => {});

    return json({ ok: true, report }, 200, rlHeaders);
  } catch (e) {
    if (e instanceof ZipError) return json({ ok: false, error: e.message }, 400, rlHeaders);
    if ((e as Error).message === "TIMEOUT") {
      return json({ ok: false, error: "Analisis melebihi batas waktu. Kecilkan arsip (hanya folder kode sumber)." }, 504, rlHeaders);
    }
    console.error("[source-audit]", (e as Error).name);
    return json({ ok: false, error: "Gagal menganalisis arsip." }, 500, rlHeaders);
  }
}
