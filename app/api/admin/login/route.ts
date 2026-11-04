import { NextResponse } from "next/server";
import { cookieOpts, login, noStore } from "@/lib/sentinel/admin-auth";
import { clientIp } from "@/lib/sentinel/redis";
import { COOKIE } from "@/lib/sentinel/session";

export const runtime = "nodejs";

export async function POST(req: Request) {
  const body = await req.json().catch(() => null);
  const r = await login(clientIp(req), req.headers.get("user-agent") ?? "", body?.user, body?.pass);

  if (!r.ok) {
    const headers: Record<string, string> = { ...noStore };
    if (r.retryAfter) headers["Retry-After"] = String(r.retryAfter);
    return NextResponse.json({ error: r.error }, { status: r.status, headers });
  }
  const res = NextResponse.json({ ok: true }, { headers: noStore });
  res.cookies.set(COOKIE, r.token, cookieOpts(12 * 3600));
  return res;
}
