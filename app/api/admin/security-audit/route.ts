import { after, NextResponse } from "next/server";
import { nanoid } from "nanoid";
import { guardAdmin, noStore } from "@/lib/sentinel/admin-auth";
import { getAdminAuditTarget } from "@/lib/sentinel/authorized-targets";
import { assertPublicHttpsTarget, SsrfBlockedError } from "@/lib/ssrf-guard";
import { checkAndRegisterCooldown } from "@/lib/rate-limit";
import { rateLimit } from "@/lib/sentinel/redis";
import { createScan } from "@/lib/scan-store";
import { runScan } from "@/lib/scan-runner";
import { extractRequestIdentity, logUserActivity } from "@/lib/activity-store";

export const runtime = "nodejs";
export const maxDuration = 300;
const MAX_BODY_BYTES = 4096;

async function readSmallJson(req: Request): Promise<{ body: unknown; tooLarge: boolean }> {
  const contentLength = Number(req.headers.get("content-length"));
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) return { body: null, tooLarge: true };
  if (!req.body) return { body: null, tooLarge: false };

  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY_BYTES) {
        await reader.cancel();
        return { body: null, tooLarge: true };
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }

  try {
    return { body: JSON.parse(Buffer.concat(chunks, total).toString("utf8")), tooLarge: false };
  } catch {
    return { body: null, tooLarge: false };
  }
}

export async function POST(req: Request) {
  const denied = await guardAdmin(req);
  if (denied) return denied;

  if (!/^application\/json\b/i.test(req.headers.get("content-type") ?? "")) {
    return NextResponse.json({ error: "Kirim domain dalam format JSON." }, { status: 415, headers: noStore });
  }

  const parsed = await readSmallJson(req);
  if (parsed.tooLarge) {
    return NextResponse.json({ error: "Request terlalu besar." }, { status: 413, headers: noStore });
  }
  const body = parsed.body as { domain?: unknown } | null;
  const target = getAdminAuditTarget(body?.domain);
  if (!target) {
    return NextResponse.json({ error: "Masukkan domain publik atau URL HTTPS yang valid." }, { status: 400, headers: noStore });
  }

  const origin = target.origin;
  const identity = extractRequestIdentity(req);
  try {
    if (!(await rateLimit("admin-security-audit", identity.ip, 5, 60))) {
      return NextResponse.json({ error: "Batas audit tercapai. Maksimal 5 audit per menit." }, { status: 429, headers: noStore });
    }
    await assertPublicHttpsTarget(origin, AbortSignal.timeout(5000));
    const cooldown = await checkAndRegisterCooldown(identity.ip, target.domain);
    if (!cooldown.allowed) {
      return NextResponse.json(
        { error: `Target baru saja diaudit. Coba lagi dalam ${Math.ceil(cooldown.retryAfterMs / 1000)} detik.` },
        { status: 429, headers: noStore },
      );
    }

    const scanId = nanoid(10);
    await createScan(scanId, target.domain, origin, { adminOnly: true });
    await logUserActivity({
      req,
      ip: identity.ip,
      userAgent: identity.userAgent,
      userId: identity.userId,
      module: "FULL_SCAN",
      action: "Audit keamanan bertahap oleh admin",
      target: target.domain,
      status: "RUNNING",
      summary: `Audit aman dimulai untuk ${origin}; Scan ID ${scanId}.`,
      meta: { scanId, origin, adminOnly: true },
    }).catch(() => {});

    const runner = () => runScan(scanId, origin, identity);
    try {
      after(runner);
    } catch {
      void runner();
    }

    return NextResponse.json({ ok: true, scanId, domain: target.domain }, { headers: noStore });
  } catch (error) {
    const status = error instanceof SsrfBlockedError ? 422 : 502;
    return NextResponse.json(
      { error: status === 422 ? "Target tidak mengarah ke alamat publik." : "Target gagal diverifikasi atau DNS tidak tersedia." },
      { status, headers: noStore },
    );
  }
}
