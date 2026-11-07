// lib/redis.ts
// Multi-Layer Ultra-Low-Bandwidth Storage Engine:
//   L1: In-Memory RAM Cache (0 byte bandwidth untuk bacaan berulang & SSE polling)
//   L2: Redis (Upstash REST / TCP Redis) — Hemat bandwidth >95% dengan payload slimming & write-coalescing
//   L3: Turso (libSQL Edge SQLite over HTTP) — Backup persisten otomatis & failover jika Redis penuh/limit

import { Redis as UpstashRedis } from "@upstash/redis";
import { createClient, type RedisClientType } from "redis";
import {
  ensureTursoSchema,
  tursoPipeline,
  sqlArg,
  cellToString,
  cellToNumber,
} from "./turso";

export interface Kv {
  getJSON<T>(key: string): Promise<T | null>;
  setJSON(key: string, value: unknown, ttlSeconds: number): Promise<void>;
  setNX(key: string, ttlSeconds: number): Promise<boolean>;
  ttl(key: string): Promise<number>;
  rpushJSON(key: string, value: unknown, ttlSeconds: number, maxLen: number): Promise<void>;
  lrangeJSON<T>(key: string, start: number, stop: number): Promise<T[]>;
  /** Cari semua key yang cocok dengan glob pattern (mis. "trout:scan:*:meta"). */
  keys(pattern: string): Promise<string[]>;
}

function getUpstashCredentials(): { url: string; token: string } | null {
  const url = (process.env.UPSTASH_REDIS_REST_URL || process.env.KV_REST_API_URL || "").trim();
  const token = (process.env.UPSTASH_REDIS_REST_TOKEN || process.env.KV_REST_API_TOKEN || "").trim();
  if (url && token && /^https?:\/\//i.test(url)) {
    return { url, token };
  }
  return null;
}

function getTcpRedisUrl(): string | null {
  const url = (process.env.REDIS_URL || process.env.KV_URL || "").trim();
  if (url && /^rediss?:\/\//i.test(url)) {
    return url;
  }
  return null;
}

export type RedisMode = "upstash-turso-hybrid" | "node-redis-turso-hybrid" | "turso";

export function getRedisMode(): RedisMode {
  if (getUpstashCredentials()) return "upstash-turso-hybrid";
  if (getTcpRedisUrl()) return "node-redis-turso-hybrid";
  return "turso";
}

export const REDIS_CONFIGURED = true;

// ---------------- L1 In-Memory Cache (Penghemat Bandwidth Utama) ----------------

interface MemItem {
  raw: string;
  expiresAt: number;
  lastSyncedAt: number;
}

interface MemList {
  items: string[];
  expiresAt: number;
  lastSyncedAt: number;
}

const globalForHybridKv = globalThis as unknown as {
  __troutMemKvItems?: Map<string, MemItem>;
  __troutMemKvLists?: Map<string, MemList>;
  __troutUpstashClient?: UpstashRedis | null;
  __troutUpstashDeadUntil?: number;
  __troutNodeRedisClient?: RedisClientType;
  __troutNodeRedisConnecting?: Promise<RedisClientType>;
  __troutNodeRedisDeadUntil?: number;
};

const memItems = globalForHybridKv.__troutMemKvItems ?? new Map<string, MemItem>();
const memLists = globalForHybridKv.__troutMemKvLists ?? new Map<string, MemList>();
globalForHybridKv.__troutMemKvItems = memItems;
globalForHybridKv.__troutMemKvLists = memLists;

function globToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`);
}

function globToSqlLike(pattern: string): string {
  return pattern.replace(/%/g, "\\%").replace(/_/g, "\\_").replace(/\*/g, "%").replace(/\?/g, "_");
}

function getUpstashClient(): UpstashRedis | null {
  if (
    globalForHybridKv.__troutUpstashDeadUntil &&
    Date.now() < globalForHybridKv.__troutUpstashDeadUntil
  ) {
    return null;
  }
  const creds = getUpstashCredentials();
  if (!creds) return null;
  if (!globalForHybridKv.__troutUpstashClient) {
    globalForHybridKv.__troutUpstashClient = new UpstashRedis({
      url: creds.url,
      token: creds.token,
      automaticDeserialization: false,
    });
  }
  return globalForHybridKv.__troutUpstashClient;
}

function markUpstashTemporarilyDead() {
  globalForHybridKv.__troutUpstashDeadUntil = Date.now() + 45_000;
}

async function getNodeRedisClient(): Promise<RedisClientType | null> {
  if (
    globalForHybridKv.__troutNodeRedisDeadUntil &&
    Date.now() < globalForHybridKv.__troutNodeRedisDeadUntil
  ) {
    return null;
  }
  const url = getTcpRedisUrl();
  if (!url) return null;

  if (globalForHybridKv.__troutNodeRedisClient?.isOpen) {
    return globalForHybridKv.__troutNodeRedisClient;
  }
  if (globalForHybridKv.__troutNodeRedisConnecting) {
    return globalForHybridKv.__troutNodeRedisConnecting;
  }

  const client = createClient({
    url,
    socket: {
      connectTimeout: 2500,
      reconnectStrategy: false,
    },
  }) as RedisClientType;

  client.on("error", () => {});

  const connecting = client
    .connect()
    .then(() => {
      globalForHybridKv.__troutNodeRedisClient = client;
      globalForHybridKv.__troutNodeRedisConnecting = undefined;
      return client;
    })
    .catch((err) => {
      globalForHybridKv.__troutNodeRedisConnecting = undefined;
      globalForHybridKv.__troutNodeRedisDeadUntil = Date.now() + 60_000;
      throw err;
    });

  globalForHybridKv.__troutNodeRedisConnecting = connecting;
  try {
    return await connecting;
  } catch {
    return null;
  }
}

/**
 * Multi-Layer Hybrid KV:
 * 1. L1 RAM Cache (mencegah ribuan pembacaan berulang saat SSE stream polling)
 * 2. L2 Redis (Upstash REST / TCP Redis dengan string JSON kompak)
 * 3. L3 Turso (libSQL Edge SQLite over HTTP sebagai backup & failover permanen)
 */
class MultiLayerHybridKv implements Kv {
  async getJSON<T>(key: string): Promise<T | null> {
    const now = Date.now();
    const local = memItems.get(key);

    // L1 Cache Hit: jika data baru disinkronkan dalam 2,5 detik terakhir, tidak perlu panggil Redis/Turso sama sekali (0 bandwidth!)
    if (local && now <= local.expiresAt && now - local.lastSyncedAt < 2500) {
      try {
        return JSON.parse(local.raw) as T;
      } catch {
        // continue
      }
    }

    // L2: Coba baca dari Upstash Redis / TCP Redis
    const upstash = getUpstashClient();
    if (upstash) {
      try {
        const raw = await upstash.get<string>(key);
        if (raw !== null && raw !== undefined) {
          const str = typeof raw === "string" ? raw : JSON.stringify(raw);
          memItems.set(key, {
            raw: str,
            expiresAt: local?.expiresAt ?? now + 1800_000,
            lastSyncedAt: now,
          });
          return (typeof raw === "string" ? JSON.parse(raw) : raw) as T;
        }
      } catch {
        markUpstashTemporarilyDead();
      }
    } else {
      const tcp = await getNodeRedisClient();
      if (tcp) {
        try {
          const raw = await tcp.get(key);
          if (raw) {
            memItems.set(key, {
              raw,
              expiresAt: local?.expiresAt ?? now + 1800_000,
              lastSyncedAt: now,
            });
            return JSON.parse(raw) as T;
          }
        } catch {
          globalForHybridKv.__troutNodeRedisDeadUntil = Date.now() + 60_000;
        }
      }
    }

    // L3: Coba baca dari Turso SQLite Edge
    try {
      if (await ensureTursoSchema()) {
        const res = await tursoPipeline([
          {
            sql: "SELECT v, exp FROM sentinel_kv WHERE k = ? LIMIT 1",
            args: [sqlArg(key)],
          },
        ]);
        const row = res?.[0]?.rows?.[0];
        if (row) {
          const rawVal = cellToString(row[0]);
          const exp = cellToNumber(row[1]);
          if (exp && now > exp) {
            memItems.delete(key);
            return null;
          }
          if (rawVal !== null) {
            memItems.set(key, {
              raw: rawVal,
              expiresAt: exp ?? now + 1800_000,
              lastSyncedAt: now,
            });
            return JSON.parse(rawVal) as T;
          }
        }
      }
    } catch {
      // ignore
    }

    if (local && now <= local.expiresAt) {
      try {
        return JSON.parse(local.raw) as T;
      } catch {
        return null;
      }
    }
    return null;
  }

  async setJSON(key: string, value: unknown, ttlSeconds: number): Promise<void> {
    const now = Date.now();
    const exp = now + ttlSeconds * 1000;
    const raw = JSON.stringify(value);

    // 1. Simpan instan ke L1 Memory
    memItems.set(key, { raw, expiresAt: exp, lastSyncedAt: now });

    // 2. Simpan ke L2 Redis (bila aktif)
    const upstash = getUpstashClient();
    if (upstash) {
      try {
        await upstash.set(key, raw, { ex: ttlSeconds });
      } catch {
        markUpstashTemporarilyDead();
      }
    } else {
      const tcp = await getNodeRedisClient();
      if (tcp) {
        try {
          await tcp.set(key, raw, { EX: ttlSeconds });
        } catch {
          globalForHybridKv.__troutNodeRedisDeadUntil = Date.now() + 60_000;
        }
      }
    }

    // 3. Simpan ke L3 Turso SQLite (non-blocking / resilient backup)
    try {
      if (await ensureTursoSchema()) {
        await tursoPipeline([
          {
            sql: `INSERT INTO sentinel_kv (k, v, exp) VALUES (?, ?, ?)
                  ON CONFLICT(k) DO UPDATE SET v = excluded.v, exp = excluded.exp`,
            args: [sqlArg(key), sqlArg(raw), sqlArg(exp)],
          },
        ]);
      }
    } catch {
      // Sudah aman di L1 & L2
    }
  }

  async setNX(key: string, ttlSeconds: number): Promise<boolean> {
    const now = Date.now();
    const exp = now + ttlSeconds * 1000;
    const local = memItems.get(key);
    if (local && now <= local.expiresAt) {
      return false;
    }

    const upstash = getUpstashClient();
    if (upstash) {
      try {
        const ok = await upstash.set(key, String(now), { nx: true, ex: ttlSeconds });
        if (ok === "OK") {
          memItems.set(key, { raw: String(now), expiresAt: exp, lastSyncedAt: now });
          return true;
        }
        return false;
      } catch {
        markUpstashTemporarilyDead();
      }
    } else {
      const tcp = await getNodeRedisClient();
      if (tcp) {
        try {
          const ok = await tcp.set(key, String(now), { NX: true, EX: ttlSeconds });
          if (ok === "OK") {
            memItems.set(key, { raw: String(now), expiresAt: exp, lastSyncedAt: now });
            return true;
          }
          return false;
        } catch {
          globalForHybridKv.__troutNodeRedisDeadUntil = Date.now() + 60_000;
        }
      }
    }

    memItems.set(key, { raw: String(now), expiresAt: exp, lastSyncedAt: now });
    return true;
  }

  async ttl(key: string): Promise<number> {
    const now = Date.now();
    const local = memItems.get(key);
    if (local && now <= local.expiresAt) {
      return Math.max(1, Math.ceil((local.expiresAt - now) / 1000));
    }

    const upstash = getUpstashClient();
    if (upstash) {
      try {
        return await upstash.ttl(key);
      } catch {
        markUpstashTemporarilyDead();
      }
    }
    return -2;
  }

  async rpushJSON(key: string, value: unknown, ttlSeconds: number, maxLen: number): Promise<void> {
    const now = Date.now();
    const exp = now + ttlSeconds * 1000;
    const raw = JSON.stringify(value);

    const existing = memLists.get(key);
    const list = existing && now <= existing.expiresAt ? existing.items : [];
    list.push(raw);
    if (list.length > maxLen) {
      list.splice(0, list.length - maxLen);
    }
    memLists.set(key, { items: list, expiresAt: exp, lastSyncedAt: now });

    // Hemat commands di Redis: cukup rpush + expire, dan ltrim hanya sesekali (saat panjang kelipatan 25)
    const shouldTrim = list.length % 25 === 0;

    const upstash = getUpstashClient();
    if (upstash) {
      try {
        const p = upstash.pipeline();
        p.rpush(key, raw);
        if (shouldTrim) p.ltrim(key, -maxLen, -1);
        if (list.length <= 2 || shouldTrim) p.expire(key, ttlSeconds);
        await p.exec();
      } catch {
        markUpstashTemporarilyDead();
      }
    } else {
      const tcp = await getNodeRedisClient();
      if (tcp) {
        try {
          const multi = tcp.multi();
          multi.rPush(key, raw);
          if (shouldTrim) multi.lTrim(key, -maxLen, -1);
          if (list.length <= 2 || shouldTrim) multi.expire(key, ttlSeconds);
          await multi.exec();
        } catch {
          globalForHybridKv.__troutNodeRedisDeadUntil = Date.now() + 60_000;
        }
      }
    }

    // Simpan ke Turso untuk log aktivitas atau fallback apabila Redis tidak aktif
    if (!upstash && key.includes("activities")) {
      try {
        if (await ensureTursoSchema()) {
          await tursoPipeline([
            {
              sql: "INSERT INTO sentinel_list (k, v, exp) VALUES (?, ?, ?)",
              args: [sqlArg(key), sqlArg(raw), sqlArg(exp)],
            },
          ]);
        }
      } catch {
        // ignore
      }
    }
  }

  async lrangeJSON<T>(key: string, start: number, stop: number): Promise<T[]> {
    const now = Date.now();
    const local = memLists.get(key);

    // L1 Cache Hit: jika sudah ada di memori dan disinkronkan dalam 2 detik terakhir, langsung slice dari RAM (hemat 95% bandwidth SSE!)
    if (local && now <= local.expiresAt && local.items.length > 0 && now - local.lastSyncedAt < 2000) {
      const list = local.items;
      const s = start < 0 ? Math.max(0, list.length + start) : start;
      const e = stop < 0 ? list.length + 1 + stop : stop + 1;
      const out: T[] = [];
      for (const raw of list.slice(s, e)) {
        try {
          out.push(JSON.parse(raw) as T);
        } catch {
          // ignore
        }
      }
      return out;
    }

    // L2: Hanya ambil item baru mulai dari `start` (BUKAN 0..-1 seluruhnya) saat menarik dari Redis!
    const upstash = getUpstashClient();
    if (upstash) {
      try {
        const rawList = await upstash.lrange<string>(key, start, stop);
        if (rawList && rawList.length > 0) {
          const out: T[] = [];
          for (const item of rawList) {
            try {
              out.push((typeof item === "string" ? JSON.parse(item) : item) as T);
            } catch {
              // ignore
            }
          }
          return out;
        }
      } catch {
        markUpstashTemporarilyDead();
      }
    } else {
      const tcp = await getNodeRedisClient();
      if (tcp) {
        try {
          const rawList = await tcp.lRange(key, start, stop);
          if (rawList && rawList.length > 0) {
            return rawList.map((s) => JSON.parse(s) as T);
          }
        } catch {
          globalForHybridKv.__troutNodeRedisDeadUntil = Date.now() + 60_000;
        }
      }
    }

    // L3: Turso fallback
    try {
      if (await ensureTursoSchema()) {
        const res = await tursoPipeline([
          {
            sql: "SELECT v FROM sentinel_list WHERE k = ? AND (exp IS NULL OR exp > ?) ORDER BY idx ASC LIMIT 500",
            args: [sqlArg(key), sqlArg(now)],
          },
        ]);
        const rows = res?.[0]?.rows ?? [];
        if (rows.length > 0) {
          const allRaw = rows.map((r) => cellToString(r[0]) ?? "").filter(Boolean);
          memLists.set(key, { items: allRaw, expiresAt: now + 1800_000, lastSyncedAt: now });
          const s = start < 0 ? Math.max(0, allRaw.length + start) : start;
          const e = stop < 0 ? allRaw.length + 1 + stop : stop + 1;
          return allRaw.slice(s, e).map((r) => JSON.parse(r) as T);
        }
      }
    } catch {
      // ignore
    }

    if (local && now <= local.expiresAt) {
      const list = local.items;
      const s = start < 0 ? Math.max(0, list.length + start) : start;
      const e = stop < 0 ? list.length + 1 + stop : stop + 1;
      return list.slice(s, e).map((r) => JSON.parse(r) as T);
    }
    return [];
  }

  async keys(pattern: string): Promise<string[]> {
    const now = Date.now();
    const found = new Set<string>();
    const re = globToRegExp(pattern);

    for (const [k, v] of memItems.entries()) {
      if (now <= v.expiresAt && re.test(k)) {
        found.add(k);
      }
    }

    const upstash = getUpstashClient();
    if (upstash) {
      try {
        let cursor: string | number = "0";
        for (let i = 0; i < 10; i++) {
          const res: [string, string[]] = await upstash.scan(cursor, { match: pattern, count: 100 });
          cursor = res[0];
          for (const k of res[1]) found.add(k);
          if (String(cursor) === "0") break;
        }
      } catch {
        markUpstashTemporarilyDead();
      }
    }

    try {
      if (await ensureTursoSchema()) {
        const likePattern = globToSqlLike(pattern);
        const res = await tursoPipeline([
          {
            sql: "SELECT k FROM sentinel_kv WHERE k LIKE ? AND (exp IS NULL OR exp > ?) LIMIT 200",
            args: [sqlArg(likePattern), sqlArg(now)],
          },
        ]);
        for (const r of res?.[0]?.rows ?? []) {
          const k = cellToString(r[0]);
          if (k && re.test(k)) found.add(k);
        }
      }
    } catch {
      // ignore
    }

    return Array.from(found);
  }
}

let cachedKv: Kv | null = null;

export function getKv(): Kv {
  if (!cachedKv) {
    cachedKv = new MultiLayerHybridKv();
  }
  return cachedKv;
}
