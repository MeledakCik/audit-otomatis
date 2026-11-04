import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { cookieOpts, guardAdmin } from "@/lib/sentinel/admin-auth";
import { COOKIE, destroySession } from "@/lib/sentinel/session";

export const runtime = "nodejs";

export async function POST(req: Request) {
  const denied = await guardAdmin(req);
  if (denied) return denied;
  await destroySession((await cookies()).get(COOKIE)?.value);
  const res = NextResponse.json({ ok: true });
  res.cookies.set(COOKIE, "", cookieOpts(0));
  return res;
}
