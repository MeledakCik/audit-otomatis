import { NextResponse } from "next/server";
import { guardAdmin, noStore } from "@/lib/sentinel/admin-auth";
import { checkDomain, hasCurrentDomainProof } from "@/lib/sentinel/domain-check";
import { rateLimit } from "@/lib/sentinel/redis";
import { AUTH_KEY_RE, getAuth, listAuth } from "@/lib/sentinel/store";
import { SsrfBlockedError } from "@/lib/ssrf-guard";

export const runtime = "nodejs";
export const maxDuration = 15;

export async function GET(req: Request) {
  const denied = await guardAdmin(req);
  if (denied) return denied;

  const domains = new Map<string, { key: string; domain: string }>();
  for (const { key, rec } of await listAuth()) {
    if (hasCurrentDomainProof(rec) && !domains.has(rec.domain)) {
      domains.set(rec.domain, { key, domain: rec.domain });
    }
  }
  const items = Array.from(domains.values()).sort((a, b) => a.domain.localeCompare(b.domain));
  return NextResponse.json({ items }, { headers: noStore });
}

export async function POST(req: Request) {
  const denied = await guardAdmin(req);
  if (denied) return denied;

  const body = await req.json().catch(() => null);
  const match = typeof body?.key === "string" && body.key.length <= 332 && AUTH_KEY_RE.exec(body.key);
  if (!match) {
    return NextResponse.json({ error: "Pilih domain terverifikasi." }, { status: 400, headers: noStore });
  }

  const [, domain, userId] = match;
  const record = await getAuth(domain, userId);
  if (!record || record.domain !== domain || record.userId !== userId || !hasCurrentDomainProof(record)) {
    return NextResponse.json({ error: "Bukti kepemilikan domain sudah tidak berlaku." }, { status: 409, headers: noStore });
  }

  if (!(await rateLimit("admin-domain-check", "admin", 8, 60))) {
    return NextResponse.json({ error: "Batas uji tercapai. Coba lagi dalam satu menit." }, { status: 429, headers: noStore });
  }

  const timeout = AbortSignal.timeout(8000);
  try {
    const result = await checkDomain(domain, AbortSignal.any([timeout, req.signal]));
    return NextResponse.json(result, { headers: noStore });
  } catch (error) {
    if (error instanceof SsrfBlockedError) {
      return NextResponse.json({ error: "Domain tidak mengarah ke alamat publik yang didukung." }, { status: 422, headers: noStore });
    }
    if (timeout.aborted) {
      return NextResponse.json({ error: "Domain tidak merespons dalam 8 detik." }, { status: 504, headers: noStore });
    }
    return NextResponse.json({ error: "Gagal membuat koneksi HTTPS yang valid ke domain." }, { status: 502, headers: noStore });
  }
}
