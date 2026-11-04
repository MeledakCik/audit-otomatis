import dns from "node:dns/promises";
import { assertPublicHttpsTarget } from "@/lib/ssrf-guard";
import { randomBytes } from "node:crypto";

export const newChallenge = () => `sentinel-verify-${randomBytes(12).toString("hex")}`;

/** TXT di _sentinel-verify.<domain> atau di apex berisi challenge. */
export async function verifyDns(domain: string, challenge: string): Promise<boolean> {
  for (const name of [`_sentinel-verify.${domain}`, domain]) {
    try {
      const recs = await dns.resolveTxt(name);
      if (recs.some((chunks) => chunks.join("").trim() === challenge)) return true;
    } catch { /* NXDOMAIN / no data → lanjut */ }
  }
  return false;
}

/** https://<domain>/<challenge>.txt harus 200 dan berisi challenge. Tanpa redirect, SSRF-guarded. */
export async function verifyFile(domain: string, challenge: string): Promise<boolean> {
  try {
    const { url } = await assertPublicHttpsTarget(`https://${domain}/${challenge}.txt`);
    const ctl = new AbortController();
    const t = setTimeout(() => ctl.abort(), 8000);
    try {
      const res = await fetch(url, { redirect: "manual", signal: ctl.signal, headers: { "User-Agent": "Sentinel-ID Verifier/1.0" } });
      if (res.status !== 200) return false;
      const body = (await res.text()).slice(0, 4096);
      return body.includes(challenge);
    } finally { clearTimeout(t); }
  } catch { return false; }
}
