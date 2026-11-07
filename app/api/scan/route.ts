import { after } from "next/server";
import { NextResponse } from "next/server";
import { nanoid } from "nanoid";
import { validateDomainInput } from "@/lib/validate-domain";
import { sanitizeCfClearance } from "@/lib/crawler";
import { checkAndRegisterCooldown } from "@/lib/rate-limit";
import { createScan } from "@/lib/scan-store";
import { runScan } from "@/lib/scan-runner";
import { logUserActivity, extractRequestIdentity } from "@/lib/activity-store";

export const runtime = "nodejs";
export const maxDuration = 300;

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({}));
    const domainInput = typeof body.domain === "string" ? body.domain.trim() : "";
    const hasPermission = body.permission === true || body.permission === "on";
    const cfClearance = sanitizeCfClearance(
      typeof body.cfClearance === "string" ? body.cfClearance : undefined
    );

    if (!hasPermission) {
      return NextResponse.json(
        {
          ok: false,
          error: "Anda harus mencentang konfirmasi kepemilikan/izin sebelum scan dimulai.",
        },
        { status: 400 }
      );
    }

    const validation = validateDomainInput(domainInput);
    if (!validation.ok || !validation.normalizedUrl || !validation.hostname) {
      return NextResponse.json(
        { ok: false, error: validation.error ?? "Domain tidak valid." },
        { status: 400 }
      );
    }

    const identity = extractRequestIdentity(req);

    try {
      const cooldown = await checkAndRegisterCooldown(identity.ip, validation.hostname);
      if (!cooldown.allowed) {
        const seconds = Math.ceil(cooldown.retryAfterMs / 1000);
        return NextResponse.json(
          {
            ok: false,
            error: `Domain ini baru saja di-scan. Coba lagi dalam ${seconds} detik (limit: 1 scan/domain/5 menit).`,
          },
          { status: 429 }
        );
      }
    } catch {
      // Jangan blokir apabila Redis cooldown gagal dihubungi
    }

    const scanId = nanoid(10);
    await createScan(scanId, validation.hostname, validation.normalizedUrl);

    await logUserActivity({
      req,
      ip: identity.ip,
      userAgent: identity.userAgent,
      userId: identity.userId,
      module: "FULL_SCAN",
      action: "Memulai Full Passive Audit + Deep Shell/OOB + Sentinel Vault Scan",
      target: validation.hostname,
      status: "RUNNING",
      summary: `Scan ID: ${scanId} dimulai pada ${validation.normalizedUrl}${cfClearance ? " (dengan CF Clearance Owner Token)" : ""}`,
      meta: { scanId, origin: validation.normalizedUrl, hasCfClearance: Boolean(cfClearance) },
    }).catch(() => {});

    try {
      after(async () => {
        await runScan(
          scanId,
          validation.normalizedUrl!,
          { ip: identity.ip, userAgent: identity.userAgent, userId: identity.userId },
          cfClearance
        );
      });
    } catch {
      void runScan(
        scanId,
        validation.normalizedUrl!,
        { ip: identity.ip, userAgent: identity.userAgent, userId: identity.userId },
        cfClearance
      );
    }

    return NextResponse.json({
      ok: true,
      scanId,
      domain: validation.hostname,
      origin: validation.normalizedUrl,
    });
  } catch (err) {
    return NextResponse.json(
      {
        ok: false,
        error: err instanceof Error ? err.message : "Gagal memulai pemindaian di server.",
      },
      { status: 500 }
    );
  }
}
