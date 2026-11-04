import { NextResponse } from "next/server";
import { cookies } from "next/headers";
import { randomToken } from "@/lib/sentinel/crypto";
import { clientIp, rateLimit } from "@/lib/sentinel/redis";
import { DOMAIN_RE, getAuth, putAuth, type AuthRecord } from "@/lib/sentinel/store";
import { newChallenge, verifyDns, verifyFile } from "@/lib/sentinel/claim";
import { logUserActivity } from "@/lib/activity-store";

export const runtime = "nodejs";
export const maxDuration = 30;

const UID = "sentinel_uid";

const view = (r: AuthRecord) => ({
  domain: r.domain,
  status: r.status,
  challenge: r.challenge,
  instructions: {
    dns: { type: "TXT", name: `_sentinel-verify.${r.domain}`, value: r.challenge },
    file: { url: `https://${r.domain}/${r.challenge}.txt`, content: r.challenge },
  },
  proof: r.proof,
  viewToken: r.status === "APPROVED" && (r.viewTokenExp ?? 0) > Date.now() ? r.viewToken : undefined,
  viewTokenExp: r.status === "APPROVED" ? r.viewTokenExp : undefined,
});

export async function GET(req: Request) {
  const domain = new URL(req.url).searchParams.get("domain")?.toLowerCase() ?? "";
  const uid = (await cookies()).get(UID)?.value;
  if (!DOMAIN_RE.test(domain) || !uid) return NextResponse.json({ status: "NONE" });
  const rec = await getAuth(domain, uid);
  return NextResponse.json(rec ? view(rec) : { status: "NONE" }, { headers: { "Cache-Control": "no-store" } });
}

export async function POST(req: Request) {
  const body = await req.json().catch(() => null);
  const domain = typeof body?.domain === "string" ? body.domain.toLowerCase().trim() : "";
  const action = body?.action;
  if (!DOMAIN_RE.test(domain) || !["start", "submit"].includes(action))
    return NextResponse.json({ error: "Request tidak valid" }, { status: 400 });

  if (!(await rateLimit("claim", clientIp(req), 20, 3600)))
    return NextResponse.json({ error: "Terlalu banyak request." }, { status: 429 });

  const jar = await cookies();
  let uid = jar.get(UID)?.value;
  if (!uid || !/^[A-Za-z0-9_-]{16,64}$/.test(uid)) {
    uid = randomToken(18);
    jar.set(UID, uid, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      path: "/",
      maxAge: 30 * 24 * 3600,
    });
  }

  let rec = await getAuth(domain, uid);

  if (action === "start") {
    if (!rec) {
      rec = { domain, userId: uid, status: "AWAITING_PROOF", challenge: newChallenge(), createdAt: Date.now() };
      await putAuth(rec, { create: true });
    }
    await logUserActivity({
      req,
      userId: uid,
      module: "SENTINEL_CLAIM",
      action: "Memulai Klaim Kepemilikan Domain",
      target: domain,
      status: "RUNNING",
      summary: `Challenge diterbitkan (${rec.challenge.slice(0, 22)}…)`,
      meta: { claimStatus: rec.status },
    });
    return NextResponse.json(view(rec));
  }

  if (!rec) return NextResponse.json({ error: "Mulai klaim dulu." }, { status: 400 });
  if (rec.status !== "AWAITING_PROOF") return NextResponse.json(view(rec));

  const [dnsOk, fileOk] = await Promise.all([verifyDns(domain, rec.challenge), verifyFile(domain, rec.challenge)]);
  if (!dnsOk && !fileOk) {
    await logUserActivity({
      req,
      userId: uid,
      module: "SENTINEL_CLAIM",
      action: "Verifikasi Bukti Kepemilikan Gagal",
      target: domain,
      status: "WARNING",
      summary: "Bukti DNS TXT / File HTTP belum ditemukan",
    });
    return NextResponse.json(
      { error: "Bukti belum ditemukan (DNS TXT / file). DNS bisa butuh beberapa menit." },
      { status: 422 }
    );
  }

  const method = dnsOk ? "dns" : "file";
  rec = { ...rec, status: "PENDING", proof: { method, verifiedAt: Date.now() } };
  await putAuth(rec);

  await logUserActivity({
    req,
    userId: uid,
    module: "SENTINEL_CLAIM",
    action: "Bukti Kepemilikan Terverifikasi (Menunggu ACC Admin)",
    target: domain,
    status: "SUCCESS",
    summary: `Terverifikasi via ${method.toUpperCase()} — menunggu persetujuan Admin`,
    meta: { proofMethod: method, claimStatus: "PENDING" },
  });

  return NextResponse.json(view(rec));
}
