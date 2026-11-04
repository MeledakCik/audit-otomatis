import { NextResponse } from "next/server";
import { auditDomain } from "@/lib/sentinel/audit";
import { clientIp, rateLimit } from "@/lib/sentinel/redis";
import { getPublic, savePublic, saveVault } from "@/lib/sentinel/store";
import { SsrfBlockedError } from "@/lib/ssrf-guard";

export const runtime = "nodejs";
export const maxDuration = 60;

const FRESH_MS = 10 * 60 * 1000; // hindari menghajar target berulang

export async function POST(req: Request) {
  const body = await req.json().catch(() => null);
  const input = typeof body?.domain === "string" ? body.domain : "";
  if (!input) return NextResponse.json({ error: "domain wajib diisi" }, { status: 400 });

  if (!(await rateLimit("audit", clientIp(req), 10, 3600)))
    return NextResponse.json({ error: "Rate limit: maks 10 audit/jam." }, { status: 429 });

  try {
    const result = await auditDomain(input);
    const cached = await getPublic(result.domain);
    // hasil terbaru < 10 menit dan sama → jangan tulis vault ganda
    if (cached && Date.now() - cached.scannedAt < FRESH_MS) return NextResponse.json(cached);

    await saveVault(result.raw);           // terenkripsi, TTL 24 jam
    const pub = await savePublic(result);  // tanpa secret, TTL 7 hari
    return NextResponse.json(pub);         // raw TIDAK pernah ikut keluar
  } catch (e) {
    const status = e instanceof SsrfBlockedError ? 403 : 400;
    return NextResponse.json({ error: e instanceof Error ? e.message : "Audit gagal" }, { status });
  }
}
