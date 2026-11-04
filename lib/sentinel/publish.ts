import { saveVault, getPublic, type PublicRecord } from "./store";
import { redis, K, TTL } from "./redis";
import type { PublicFinding, RawEvidence } from "./audit";

export const sentinelConfigured = () => true;

/**
 * Dipanggil scanner (/scan) untuk temuan CRITICAL/HIGH yang sudah LOLOS validasi true-positive:
 * raw evidence → vault terenkripsi (24j), versi aman → public record (7h, di-merge).
 */
export async function publishScanCriticals(domain: string, findings: PublicFinding[], raw: RawEvidence[]) {
  if (findings.length === 0 && raw.length === 0) return;
  try {
    if (raw.length > 0) {
      await saveVault(raw);
    }
    const prev = await getPublic(domain);
    const seen = new Set((prev?.findings ?? []).map((f) => f.finding));
    const merged: PublicRecord = {
      domain,
      scannedAt: Date.now(),
      findings: [...findings.filter((f) => !seen.has(f.finding)), ...(prev?.findings ?? [])],
    };
    await redis().set(K.public(domain), JSON.stringify(merged), { ex: TTL.public });
  } catch (e) {
    console.error("[sentinel] publishScanCriticals gagal:", e instanceof Error ? e.message : e);
  }
}
