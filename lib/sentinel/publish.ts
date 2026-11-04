import { saveVault, getPublic, type PublicRecord } from "./store";
import { redis } from "./redis";
import { K, TTL } from "./redis";
import type { PublicFinding, RawEvidence } from "./audit";

export const sentinelConfigured = () =>
  Boolean(
    (process.env.UPSTASH_REDIS_REST_URL ?? process.env.KV_REST_API_URL) &&
      (process.env.UPSTASH_REDIS_REST_TOKEN ?? process.env.KV_REST_API_TOKEN) &&
      process.env.ADMIN_VAULT_KEY
  );

/**
 * Dipanggil scanner lama (/scan) untuk temuan CRITICAL yang sudah LOLOS validasi true-positive:
 * raw evidence → vault terenkripsi (24j), versi aman → public record (7h, di-merge).
 * Gagal diam-diam: scan lama tidak boleh error hanya karena vault belum dikonfigurasi.
 */
export async function publishScanCriticals(domain: string, findings: PublicFinding[], raw: RawEvidence[]) {
  if (!sentinelConfigured() || findings.length === 0) return;
  try {
    await saveVault(raw);
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
