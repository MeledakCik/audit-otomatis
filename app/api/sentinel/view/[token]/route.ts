import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { consumeTempView, decryptItem, getAuth, peekTempView, putAuth, TOKEN_RE } from "@/lib/sentinel/store";
import { clientIp, rateLimit } from "@/lib/sentinel/redis";
import { logUserActivity } from "@/lib/activity-store";

export const runtime = "nodejs";

const NO_STORE = { "Cache-Control": "no-store, max-age=0" };
const unavailable = () => NextResponse.json({ error: "Token kedaluwarsa atau sudah dipakai" }, { status: 404, headers: NO_STORE });

export function HEAD() {
  return new Response(null, { status: 405, headers: { ...NO_STORE, Allow: "GET" } });
}

export async function GET(req: Request, ctx: { params: Promise<{ token: string }> }) {
  const { token } = await ctx.params;
  if (!TOKEN_RE.test(token)) return NextResponse.json({ error: "Token tidak valid" }, { status: 400, headers: NO_STORE });
  if (!(await rateLimit("view", clientIp(req), 30, 600)))
    return NextResponse.json({ error: "Terlalu banyak request." }, { status: 429, headers: NO_STORE });

  const uid = (await cookies()).get("sentinel_uid")?.value;
  if (!uid) return unavailable();
  const peek = await peekTempView(token);
  if (!peek || peek.userId !== uid) return unavailable();

  const approval = await getAuth(peek.domain, uid);
  if (approval?.status !== "APPROVED" || approval.viewToken !== token || (approval.viewTokenExp ?? 0) <= Date.now()) {
    return unavailable();
  }

  let t;
  try {
    t = await consumeTempView(token);
  } catch {
    return NextResponse.json({ error: "Penyimpanan bukti belum tersedia." }, { status: 503, headers: NO_STORE });
  }
  if (!t || t.userId !== uid || t.domain !== peek.domain) return unavailable();

  const current = await getAuth(t.domain, uid);
  if (current?.status !== "APPROVED" || current.viewToken !== token || (current.viewTokenExp ?? 0) <= Date.now()) {
    return unavailable();
  }
  await putAuth({ ...current, status: "VIEWED", viewToken: undefined, viewTokenExp: undefined });

  const items = t.items
    .map((i) => {
      try {
        return decryptItem(i);
      } catch {
        return null;
      }
    })
    .filter(Boolean);

  await logUserActivity({
    req,
    userId: uid,
    module: "SENTINEL_VIEW",
    action: "Membuka Evidence Rahasia (One-Time Token)",
    target: t.domain,
    status: "SUCCESS",
    summary: `Pemilik domain membuka ${items.length} item evidence dari Vault (token hangus otomatis)`,
    meta: { evidenceCount: items.length },
  });

  return NextResponse.json({ domain: t.domain, evidence: items }, { headers: NO_STORE });
}
