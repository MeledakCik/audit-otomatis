import { Redis } from "@upstash/redis";

let client: Redis | null = null;

/** Upstash REST client (fetch-based → aman di Node maupun Edge/proxy). */
export function redis(): Redis {
  if (!client) {
    const url = process.env.UPSTASH_REDIS_REST_URL ?? process.env.KV_REST_API_URL;
    const token = process.env.UPSTASH_REDIS_REST_TOKEN ?? process.env.KV_REST_API_TOKEN;
    if (!url || !token) throw new Error("Upstash Redis env belum diset.");
    // automaticDeserialization=false → kita kontrol sendiri string/JSON,
    // supaya ciphertext tidak pernah "dipintarkan" oleh client.
    client = new Redis({ url, token, automaticDeserialization: false });
  }
  return client;
}

export const K = {
  public: (domain: string) => `sentinel:public:${domain}`,
  vault: (domain: string, id: string) => `sentinel:vault:admin:${domain}:${id}`,
  vaultPattern: (domain?: string) => `sentinel:vault:admin:${domain ?? "*"}${domain ? ":*" : ""}`,
  auth: (domain: string, userId: string) => `sentinel:auth:${domain}:${userId}`,
  authPattern: "sentinel:auth:*",
  tempView: (token: string) => `sentinel:temp:view:${token}`,
  block: (ip: string) => `block:${ip}`,
  fail: (ip: string) => `fail:${ip}`,
  session: (jti: string) => `session:admin:${jti}`,
  rl: (scope: string, ip: string) => `sentinel:rl:${scope}:${ip}`,
};

export const TTL = {
  public: 7 * 24 * 3600,
  vault: 24 * 3600,
  auth: 48 * 3600,
  tempView: 10 * 60,
  session: 12 * 3600,
  block: 15 * 60,
};

/** SCAN cursor-based (bukan KEYS) supaya tidak blocking. */
export async function scanKeys(pattern: string, cap = 500): Promise<string[]> {
  const r = redis();
  const out: string[] = [];
  let cursor: string | number = "0";
  do {
    const res: [string, string[]] = await r.scan(cursor, { match: pattern, count: 200 });
    cursor = res[0];
    out.push(...res[1]);
  } while (String(cursor) !== "0" && out.length < cap);
  return out.slice(0, cap);
}

/** Fixed-window rate limit sederhana. true = lolos. */
export async function rateLimit(scope: string, ip: string, max: number, windowSec: number) {
  const key = K.rl(scope, ip);
  const n = await redis().incr(key);
  if (n === 1) await redis().expire(key, windowSec);
  return n <= max;
}

export function clientIp(req: Request): string {
  const xff = req.headers.get("x-forwarded-for");
  // Di Vercel, XFF dipasang platform. Kalau self-host di belakang proxy lain,
  // pastikan proxy kamu menimpa header ini.
  return (xff?.split(",")[0] ?? req.headers.get("x-real-ip") ?? "unknown").trim();
}
