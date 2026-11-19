import dns from "node:dns/promises";
import { requestPublicHttps } from "@/lib/public-https";
import { randomBytes } from "node:crypto";

export const newChallenge = () => `sentinel-verify-${randomBytes(12).toString("hex")}`;

/** TXT di _sentinel-verify.<domain> atau di apex berisi challenge. */
export async function verifyDns(domain: string, challenge: string): Promise<boolean> {
  const resolver = new dns.Resolver({ timeout: 2000, tries: 1 });
  try {
    await Promise.any([`_sentinel-verify.${domain}`, domain].map(async (name) => {
      const records = await resolver.resolveTxt(name);
      if (!records.some((chunks) => chunks.join("").trim() === challenge)) throw new Error("Bukti TXT tidak ditemukan.");
    }));
    return true;
  } catch {
    return false;
  } finally {
    resolver.cancel();
  }
}

/** https://<domain>/<challenge>.txt harus 200 dan berisi challenge. Tanpa redirect, SSRF-guarded. */
export async function verifyFile(domain: string, challenge: string): Promise<boolean> {
  if (!/^sentinel-verify-[0-9a-f]{24}$/.test(challenge)) return false;
  try {
    const response = await requestPublicHttps(`https://${domain}/${challenge}.txt`, {
      method: "GET",
      signal: AbortSignal.timeout(8000),
      userAgent: "Sentinel-ID Verifier/1.0",
      accept: "text/plain,application/octet-stream",
      maxBodyBytes: 4096,
    });
    return response.statusCode === 200 && !response.bodyTruncated && response.bodyPrefix.trim() === challenge;
  } catch {
    return false;
  }
}
