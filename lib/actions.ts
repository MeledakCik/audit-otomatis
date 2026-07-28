"use server";

import { after } from "next/server";
import { headers } from "next/headers";
import { nanoid } from "nanoid";
import { validateDomainInput } from "./validate-domain";
import { checkAndRegisterCooldown } from "./rate-limit";
import { createScan } from "./scan-store";
import { runScan } from "./scan-runner";

export interface StartScanResult {
  ok: boolean;
  error?: string;
  scanId?: string;
}

export async function startScanAction(formData: FormData): Promise<StartScanResult> {
  const domainInput = String(formData.get("domain") || "");
  const hasPermission = formData.get("permission") === "on";

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
  const userKey = h.get("x-forwarded-for") || h.get("x-real-ip") || "anonymous";

  const cooldown = await checkAndRegisterCooldown(userKey, validation.hostname);
  if (!cooldown.allowed) {
    const seconds = Math.ceil(cooldown.retryAfterMs / 1000);
    return {
      ok: false,
      error: `Domain ini baru saja di-scan. Coba lagi dalam ${seconds} detik (limit: 1 scan/domain/5 menit).`,
    };
  }

  const scanId = nanoid(10);
  // WAJIB di-await: harus tersimpan di Redis sebelum response balik ke
  // client, karena client langsung connect ke /api/scan/[id]/stream begitu
  // dapat scanId — kalau belum ke-persist, stream route akan 404.
  await createScan(scanId, validation.hostname, validation.normalizedUrl);
  after(async () => {
    await runScan(scanId, validation.normalizedUrl!);
  });

  return { ok: true, scanId };
}
