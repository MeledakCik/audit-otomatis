// Ringan: hanya jose + Upstash REST → aman dipakai di proxy.ts maupun route/page.
import { jwtVerify, SignJWT } from "jose";
import { K, TTL, redis } from "./redis";

export const COOKIE = "sentinel_admin";

const secret = () => {
  const s = process.env.JWT_SECRET;
  if (!s || s.length < 32) throw new Error("JWT_SECRET wajib diset (≥32 karakter).");
  return new TextEncoder().encode(s);
};

export async function createSession(meta: { ip: string; ua: string }) {
  const jti = crypto.randomUUID() + crypto.randomUUID().replace(/-/g, "");
  const jwt = await new SignJWT({ sub: "admin" })
    .setProtectedHeader({ alg: "HS256" })
    .setJti(jti)
    .setIssuedAt()
    .setExpirationTime(`${TTL.session}s`)
    .sign(secret());
  await redis().set(K.session(jti), JSON.stringify({ ...meta, at: Date.now() }), { ex: TTL.session });
  return jwt;
}

/** Valid hanya jika JWT sah DAN session masih ada di Redis (bisa di-revoke). */
export async function verifySession(token: string | undefined | null): Promise<string | null> {
  if (!token) return null;
  try {
    const { payload } = await jwtVerify(token, secret(), { algorithms: ["HS256"] });
    if (!payload.jti || payload.sub !== "admin") return null;
    const exists = await redis().exists(K.session(payload.jti));
    return exists ? payload.jti : null;
  } catch {
    return null;
  }
}

export async function destroySession(token: string | undefined | null) {
  const jti = await verifySession(token);
  if (jti) await redis().del(K.session(jti));
}
