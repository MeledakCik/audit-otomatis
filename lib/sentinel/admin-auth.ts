import bcrypt from "bcryptjs";
import { timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";
import { NextResponse } from "next/server";
import { K, TTL, redis } from "./redis";
import { COOKIE, createSession, verifySession } from "./session";

const MAX_FAILS = 5;

const safeEq = (a: string, b: string) => {
  const x = Buffer.from(a), y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

export type LoginResult =
  | { ok: true; token: string }
  | { ok: false; status: 401 | 429 | 500; error: string; retryAfter?: number };

export async function login(ip: string, ua: string, user: unknown, pass: unknown): Promise<LoginResult> {
  const { ADMIN_USER, ADMIN_PASS_HASH } = process.env;
  if (!ADMIN_USER || !ADMIN_PASS_HASH) return { ok: false, status: 500, error: "Admin belum dikonfigurasi." };

  const r = redis();
  const blockTtl = await r.ttl(K.block(ip));
  if (blockTtl > 0) return { ok: false, status: 429, error: "Terlalu banyak percobaan. Coba lagi nanti.", retryAfter: blockTtl };

  const u = typeof user === "string" ? user.slice(0, 128) : "";
  const p = typeof pass === "string" ? pass.slice(0, 256) : "";

  // Selalu jalankan bcrypt (tanpa short-circuit) → tidak bocor via timing apakah username benar.
  let hashOk = false;
  try { hashOk = await bcrypt.compare(p, ADMIN_PASS_HASH); } catch { hashOk = false; }
  const userOk = safeEq(u, ADMIN_USER);

  if (!(userOk && hashOk)) {
    const n = await r.incr(K.fail(ip));
    if (n === 1) await r.expire(K.fail(ip), TTL.block);
    if (n >= MAX_FAILS) {
      await r.set(K.block(ip), "1", { ex: TTL.block });
      await r.del(K.fail(ip));
      return { ok: false, status: 429, error: "Terlalu banyak percobaan. IP diblokir 15 menit.", retryAfter: TTL.block };
    }
    return { ok: false, status: 401, error: "Username atau password salah." };
  }

  await r.del(K.fail(ip));
  return { ok: true, token: await createSession({ ip, ua: ua.slice(0, 200) }) };
}

export const cookieOpts = (maxAge: number) => ({
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: "strict" as const,
  path: "/",
  maxAge,
});

/** Untuk route handler admin. Return Response kalau DITOLAK, null kalau lolos. */
export async function guardAdmin(req: Request): Promise<NextResponse | null> {
  const token = (await cookies()).get(COOKIE)?.value;
  if (!(await verifySession(token))) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });

  if (!["GET", "HEAD"].includes(req.method)) {
    // CSRF: cookie sudah SameSite=Strict; ini lapis kedua (Origin harus sama host).
    const origin = req.headers.get("origin");
    const host = req.headers.get("host");
    let ok = false;
    try { ok = !!origin && !!host && new URL(origin).host === host; } catch { ok = false; }
    if (!ok) return NextResponse.json({ error: "Bad origin" }, { status: 403 });
  }
  return null;
}

export const noStore = { "Cache-Control": "no-store, max-age=0" };
