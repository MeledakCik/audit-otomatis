import { Redis as UpstashRedis } from "@upstash/redis";
import { createClient, type RedisClientType } from "redis";

/**
 * PENTING — kenapa file ini ada:
 *
 * Di Vercel, tiap request (Server Action maupun Route Handler) bisa
 * dieksekusi di instance serverless yang BERBEDA. Data yang cuma disimpan
 * di memory proses Node (module-level `Map`, `globalThis`, dst) TIDAK
 * dijamin sama antar instance — ini penyebab endpoint seperti
 * `/api/scan/[id]/stream` mengembalikan 404 "Scan tidak ditemukan" padahal
 * scan-nya baru saja dibuat di instance lain.
 *
 * File ini menyediakan satu abstraksi `Kv` kecil yang dipakai oleh
 * scan-store.ts & rate-limit.ts, dengan DUA kemungkinan backend nyata
 * (dipilih otomatis dari env var yang tersedia) + 1 fallback dev:
 *
 *   1. Upstash Redis via REST API — kalau env `UPSTASH_REDIS_REST_URL` +
 *      `UPSTASH_REDIS_REST_TOKEN` (atau alias lama `KV_REST_API_URL` /
 *      `KV_REST_API_TOKEN`) ada. Ini didapat kalau integrasi yang dipasang
 *      di Vercel Marketplace adalah produk "Upstash Redis".
 *
 *   2. Redis biasa via koneksi TCP (`redis` / node-redis) — kalau env
 *      `REDIS_URL` (atau alias `KV_URL`) ada. Ini yang dipakai kalau
 *      integrasi yang dipasang adalah produk "Redis" native Vercel
 *      Marketplace (yang cuma expose `REDIS_URL`, bukan REST API).
 *
 *   3. In-memory Map — fallback KHUSUS dev lokal (`next dev`) tanpa Redis
 *      sama sekali. TIDAK dipakai kalau salah satu dari dua env di atas
 *      ada, dan sengaja bikin warning keras di production kalau keduanya
 *      tidak ada supaya tidak diam-diam balik ke bug 404 yang lama.
 */

export interface Kv {
  getJSON<T>(key: string): Promise<T | null>;
  setJSON(key: string, value: unknown, ttlSeconds: number): Promise<void>;
  /** SET ... NX EX — return true kalau berhasil di-set (key belum ada sebelumnya). */
  setNX(key: string, ttlSeconds: number): Promise<boolean>;
  ttl(key: string): Promise<number>;
  /** RPUSH + LTRIM (batasi panjang list) + EXPIRE, idealnya 1 round-trip. */
  rpushJSON(key: string, value: unknown, ttlSeconds: number, maxLen: number): Promise<void>;
  lrangeJSON<T>(key: string, start: number, stop: number): Promise<T[]>;
}

function hasUpstashEnv(): boolean {
  return Boolean(
    (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) ||
      (process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN)
  );
}

function hasTcpRedisEnv(): boolean {
  return Boolean(process.env.REDIS_URL || process.env.KV_URL);
}

export type RedisMode = "upstash" | "node-redis" | "memory";

export function getRedisMode(): RedisMode {
  if (hasUpstashEnv()) return "upstash";
  if (hasTcpRedisEnv()) return "node-redis";
  return "memory";
}

export const REDIS_CONFIGURED = getRedisMode() !== "memory";

if (!REDIS_CONFIGURED && process.env.NODE_ENV !== "test") {
  const isProd = process.env.VERCEL === "1" || process.env.NODE_ENV === "production";
  const msg =
    "[redis] Tidak ada env Redis yang terdeteksi (UPSTASH_REDIS_REST_URL/TOKEN, KV_REST_API_URL/TOKEN, atau REDIS_URL) — " +
    (isProd
      ? "scan-store & rate-limit TIDAK akan berfungsi benar di Vercel tanpa ini " +
        "(tiap serverless instance akan punya state sendiri-sendiri). " +
        "Pasang produk Redis apa pun dari Vercel Marketplace lalu redeploy."
      : "pakai in-memory fallback (OK untuk `next dev` lokal, tidak untuk production).");
  // eslint-disable-next-line no-console
  console.warn(msg);
}

// ---------------- Upstash (REST) adapter ----------------

let upstashClient: UpstashRedis | null = null;
function getUpstashClient(): UpstashRedis {
  if (!upstashClient) upstashClient = UpstashRedis.fromEnv();
  return upstashClient;
}

class UpstashKv implements Kv {
  async getJSON<T>(key: string): Promise<T | null> {
    const redis = getUpstashClient();
    return (await redis.get<T>(key)) ?? null;
  }

  async setJSON(key: string, value: unknown, ttlSeconds: number): Promise<void> {
    const redis = getUpstashClient();
    await redis.set(key, value, { ex: ttlSeconds });
  }

  async setNX(key: string, ttlSeconds: number): Promise<boolean> {
    const redis = getUpstashClient();
    const ok = await redis.set(key, Date.now(), { nx: true, ex: ttlSeconds });
    return ok === "OK";
  }

  async ttl(key: string): Promise<number> {
    const redis = getUpstashClient();
    return await redis.ttl(key);
  }

  async rpushJSON(key: string, value: unknown, ttlSeconds: number, maxLen: number): Promise<void> {
    const redis = getUpstashClient();
    const pipeline = redis.pipeline();
    pipeline.rpush(key, value);
    pipeline.ltrim(key, -maxLen, -1);
    pipeline.expire(key, ttlSeconds);
    await pipeline.exec();
  }

  async lrangeJSON<T>(key: string, start: number, stop: number): Promise<T[]> {
    const redis = getUpstashClient();
    const raw = await redis.lrange<T>(key, start, stop);
    return raw ?? [];
  }
}

// ---------------- node-redis (TCP, REDIS_URL) adapter ----------------

const globalForNodeRedis = globalThis as unknown as {
  __troutNodeRedisClient?: RedisClientType;
  __troutNodeRedisConnecting?: Promise<RedisClientType>;
};

/**
 * node-redis butuh koneksi TCP persisten (bukan REST seperti Upstash), jadi
 * di lingkungan serverless kita cache client di globalThis supaya instance
 * yang "warm" (dipakai ulang oleh Fluid Compute) tidak buka koneksi baru
 * tiap request. WAJIB pasang listener 'error' — kalau tidak, error koneksi
 * yang tidak tertangani bisa mematikan proses Node.
 */
async function getNodeRedisClient(): Promise<RedisClientType> {
  if (globalForNodeRedis.__troutNodeRedisClient?.isOpen) {
    return globalForNodeRedis.__troutNodeRedisClient;
  }
  if (globalForNodeRedis.__troutNodeRedisConnecting) {
    return globalForNodeRedis.__troutNodeRedisConnecting;
  }

  const url = process.env.REDIS_URL || process.env.KV_URL;
  const client = createClient({ url }) as RedisClientType;
  client.on("error", (err) => {
    // eslint-disable-next-line no-console
    console.error("[redis] node-redis client error:", err);
  });

  const connecting = client.connect().then(() => {
    globalForNodeRedis.__troutNodeRedisClient = client;
    globalForNodeRedis.__troutNodeRedisConnecting = undefined;
    return client;
  });
  globalForNodeRedis.__troutNodeRedisConnecting = connecting;

  return connecting;
}

class NodeRedisKv implements Kv {
  async getJSON<T>(key: string): Promise<T | null> {
    const client = await getNodeRedisClient();
    const raw = await client.get(key);
    if (raw === null || raw === undefined) return null;
    return JSON.parse(raw) as T;
  }

  async setJSON(key: string, value: unknown, ttlSeconds: number): Promise<void> {
    const client = await getNodeRedisClient();
    await client.set(key, JSON.stringify(value), { EX: ttlSeconds });
  }

  async setNX(key: string, ttlSeconds: number): Promise<boolean> {
    const client = await getNodeRedisClient();
    const ok = await client.set(key, String(Date.now()), { NX: true, EX: ttlSeconds });
    return ok === "OK";
  }

  async ttl(key: string): Promise<number> {
    const client = await getNodeRedisClient();
    return await client.ttl(key);
  }

  async rpushJSON(key: string, value: unknown, ttlSeconds: number, maxLen: number): Promise<void> {
    const client = await getNodeRedisClient();
    const multi = client.multi();
    multi.rPush(key, JSON.stringify(value));
    multi.lTrim(key, -maxLen, -1);
    multi.expire(key, ttlSeconds);
    await multi.exec();
  }

  async lrangeJSON<T>(key: string, start: number, stop: number): Promise<T[]> {
    const client = await getNodeRedisClient();
    const raw = await client.lRange(key, start, stop);
    return raw.map((s) => JSON.parse(s) as T);
  }
}

// ---------------- In-memory (dev fallback) adapter ----------------
// Tidak diimplementasikan di sini — scan-store.ts & rate-limit.ts punya
// jalur in-memory sendiri (lebih simpel & sudah cocok dengan bentuk data
// aslinya) yang dipakai kalau REDIS_CONFIGURED === false. `getKv()` di bawah
// hanya dipanggil kalau REDIS_CONFIGURED true, jadi tidak perlu adapter
// memory di sini.

let cachedKv: Kv | null = null;

export function getKv(): Kv {
  if (!REDIS_CONFIGURED) {
    throw new Error(
      "getKv() dipanggil padahal Redis belum dikonfigurasi. Ini bug internal — " +
        "seharusnya dicek REDIS_CONFIGURED dulu sebelum memanggil ini."
    );
  }
  if (!cachedKv) {
    cachedKv = getRedisMode() === "upstash" ? new UpstashKv() : new NodeRedisKv();
  }
  return cachedKv;
}
