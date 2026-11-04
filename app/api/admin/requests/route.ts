import { NextResponse } from "next/server";
import { guardAdmin, noStore } from "@/lib/sentinel/admin-auth";
import { randomToken } from "@/lib/sentinel/crypto";
import { redis } from "@/lib/sentinel/redis";
import {
  AUTH_KEY_RE, createTempView, getAuth, listAuth, putAuth, vaultKeysForDomain, type TempView,
} from "@/lib/sentinel/store";
import { decrypt } from "@/lib/sentinel/crypto";

export const runtime = "nodejs";
const VIEW_TTL_MS = 10 * 60 * 1000;

export async function GET(req: Request) {
  const denied = await guardAdmin(req);
  if (denied) return denied;
  const items = (await listAuth()).map(({ key, ttl, rec }) => ({
    key, ttl, domain: rec.domain, status: rec.status, proof: rec.proof, createdAt: rec.createdAt, decidedAt: rec.decidedAt,
  }));
  return NextResponse.json({ items }, { headers: noStore });
}

export async function POST(req: Request) {
  const denied = await guardAdmin(req);
  if (denied) return denied;

  const body = await req.json().catch(() => null);
  const key = String(body?.key ?? "");
  const action = body?.action;
  const m = AUTH_KEY_RE.exec(key);
  if (!m || !["ACC", "REJECT"].includes(action))
    return NextResponse.json({ error: "Request tidak valid" }, { status: 400 });

  const rec = await getAuth(m[1], m[2]);
  if (!rec) return NextResponse.json({ error: "Request sudah kedaluwarsa" }, { status: 404 });
  // Hanya bukti yang sudah diverifikasi server (PENDING) yang boleh di-ACC. APPROVED boleh di-ACC ulang (token habis).
  if (!["PENDING", "APPROVED"].includes(rec.status))
    return NextResponse.json({ error: `Status ${rec.status} tidak bisa diproses` }, { status: 409 });

  if (action === "REJECT") {
    await putAuth({ ...rec, status: "REJECTED", decidedAt: Date.now(), viewToken: undefined, viewTokenExp: undefined });
    return NextResponse.json({ ok: true, status: "REJECTED" }, { headers: noStore });
  }

  // ACC: ambil ciphertext vault domain ini, VERIFIKASI bisa didecrypt (integritas), lalu
  // salin ciphertext (tetap terenkripsi) ke key sekali-pakai. Plaintext tidak pernah ditulis ke Redis.
  const keys = await vaultKeysForDomain(rec.domain);
  const cts = keys.length ? await redis().mget<(string | null)[]>(...keys) : [];
  const items: TempView["items"] = [];
  keys.forEach((k, i) => {
    const ct = cts[i];
    if (!ct) return;
    try { decrypt(ct, k); items.push({ key: k, ct }); } catch { /* korup → lewati */ }
  });
  if (!items.length)
    return NextResponse.json({ error: "Tidak ada evidence di vault (TTL 24 jam sudah lewat). Minta user audit ulang." }, { status: 410 });

  const token = randomToken(32); // 43 char
  await createTempView(token, { userId: rec.userId, domain: rec.domain, items }); // TTL 10 menit
  await putAuth({ ...rec, status: "APPROVED", decidedAt: Date.now(), viewToken: token, viewTokenExp: Date.now() + VIEW_TTL_MS });
  return NextResponse.json({ ok: true, status: "APPROVED", evidenceCount: items.length }, { headers: noStore });
}
