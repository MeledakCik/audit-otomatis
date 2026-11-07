"use server";

import { after } from "next/server";
import { headers, cookies } from "next/headers";
import { nanoid } from "nanoid";
import { validateDomainInput } from "./validate-domain";
import { sanitizeCfClearance } from "./crawler";
import { checkAndRegisterCooldown } from "./rate-limit";
import { createScan } from "./scan-store";
import { runScan } from "./scan-runner";
import { logUserActivity } from "./activity-store";

export interface StartScanResult {
  ok: boolean;
  error?: string;
  scanId?: string;
  domain?: string;
}

export async function startScanAction(formData: FormData): Promise<StartScanResult> {
  try {
    const domainInput = String(formData.get("domain") || "");
    const hasPermission = formData.get("permission") === "on";
    const cfClearanceRaw = String(formData.get("cfClearance") || "");
    const cfClearance = sanitizeCfClearance(cfClearanceRaw);

    if (!hasPermission) {
      return {
        ok: false,
        error: "Anda harus mencentang konfirmasi kepemilikan/izin sebelum scan dimulai.",
      };
    }

    const validation = validateDomainInput(domainInput);
    if (!validation.ok || !validation.normalizedUrl || !validation.hostname) {
      return { ok: false, error: validation.error };
    }

    const h = await headers();
    const jar = await cookies();
    const userKey = (h.get("x-forwarded-for")?.split(",")[0] || h.get("x-real-ip") || "anonymous").trim();
    const ua = h.get("user-agent") || "Unknown Browser";
    const uid =
      jar.get("sentinel_uid")?.value ||
      `usr_${Buffer.from(`${userKey}:${ua.slice(0, 32)}`).toString("base64url").slice(0, 10)}`;

    try {
      const cooldown = await checkAndRegisterCooldown(userKey, validation.hostname);
      if (!cooldown.allowed) {
        const seconds = Math.ceil(cooldown.retryAfterMs / 1000);
        return {
          ok: false,
          error: `Domain ini baru saja di-scan. Coba lagi dalam ${seconds} detik (limit: 1 scan/domain/5 menit).`,
        };
      }
    } catch {
      // Jangan blokir user bila Redis cooldown sedang gangguan
    }

    const scanId = nanoid(10);
    await createScan(scanId, validation.hostname, validation.normalizedUrl);

    await logUserActivity({
      ip: userKey,
      userAgent: ua,
      userId: uid,
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
          { ip: userKey, userAgent: ua, userId: uid },
          cfClearance
        );
      });
    } catch {
      // Fallback bila `after()` dipanggil di luar konteks yang mendukung
      void runScan(
        scanId,
        validation.normalizedUrl!,
        { ip: userKey, userAgent: ua, userId: uid },
        cfClearance
      );
    }

    return { ok: true, scanId, domain: validation.hostname };
  } catch (err) {
    return {
      ok: false,
      error: err instanceof Error ? err.message : "Gagal memulai pemindaian di server.",
    };
  }
}
