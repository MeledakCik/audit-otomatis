import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { consumeTempView, decryptItem, getAuth, peekTempView, putAuth, TOKEN_RE } from "@/lib/sentinel/store";
import { clientIp, rateLimit } from "@/lib/sentinel/redis";

export const runtime = "nodejs";

const NO_STORE = { "Cache-Control": "no-store, max-age=0" };

/** One-time view: GETDEL atomik. Hanya pemilik klaim (cookie userId sama) yang boleh membuka. */
export async function GET(req: Request, ctx: { params: Promise<{ token: string }> }) {
  const { token } = await ctx.params;
  if (!TOKEN_RE.test(token)) return NextResponse.json({ error: "Token tidak valid" }, { status: 400 });
  if (!(await rateLimit("view", clientIp(req), 30, 600)))
    return NextResponse.json({ error: "Terlalu banyak request." }, { status: 429 });

  const uid = (await cookies()).get("sentinel_uid")?.value;
  const peek = await peekTempView(token);
  if (!peek || !uid || peek.userId !== uid)
    return NextResponse.json({ error: "Token kedaluwarsa atau sudah dipakai" }, { status: 404, headers: NO_STORE });

  const t = await consumeTempView(token); // setelah ini key hilang
  if (!t) return NextResponse.json({ error: "Token kedaluwarsa atau sudah dipakai" }, { status: 404, headers: NO_STORE });

  const rec = await getAuth(t.domain, t.userId);
  if (rec) await putAuth({ ...rec, status: "VIEWED", viewToken: undefined, viewTokenExp: undefined });

  const items = t.items.map((i) => {
    try { return decryptItem(i); } catch { return null; } // data korup/diubah → GCM menolak
  }).filter(Boolean);
  return NextResponse.json({ domain: t.domain, evidence: items }, { headers: NO_STORE });
}
