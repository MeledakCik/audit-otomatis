import { NextResponse, type NextRequest } from "next/server";
import { COOKIE, verifySession } from "@/lib/sentinel/session";

// Lapis 1: gerbang /admin/* & /api/admin/*. Cek JWT + session di Redis.
// (Lapis 2 & 3: layout admin + guardAdmin() di tiap route handler.)
const PUBLIC = new Set(["/admin/login", "/api/admin/login"]);

export async function proxy(req: NextRequest) {
  const { pathname } = req.nextUrl;
  if (PUBLIC.has(pathname)) return NextResponse.next();

  const ok = await verifySession(req.cookies.get(COOKIE)?.value);
  if (!ok) {
    if (pathname.startsWith("/api/")) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    const url = req.nextUrl.clone();
    url.pathname = "/admin/login";
    url.search = "";
    return NextResponse.redirect(url);
  }

  const res = NextResponse.next();
  res.headers.set("Cache-Control", "no-store");
  res.headers.set("X-Robots-Tag", "noindex, nofollow");
  return res;
}

export const config = { matcher: ["/admin/:path*", "/api/admin/:path*"] };
