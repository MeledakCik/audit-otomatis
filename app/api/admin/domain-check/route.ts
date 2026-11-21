import { NextResponse } from "next/server";
import { guardAdmin, noStore } from "@/lib/sentinel/admin-auth";
import { checkDomain, normalizeDomainCheckTarget } from "@/lib/sentinel/domain-check";
import { rateLimit } from "@/lib/sentinel/redis";
import { SsrfBlockedError } from "@/lib/ssrf-guard";

export const runtime = "nodejs";
export const maxDuration = 15;

export async function POST(req: Request) {
  const denied = await guardAdmin(req);
  if (denied) return denied;

  const body = await req.json().catch(() => null);
  const domain = normalizeDomainCheckTarget(body?.domain);
  if (!domain) {
    return NextResponse.json({ error: "Masukkan domain atau URL web yang valid." }, { status: 400, headers: noStore });
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
