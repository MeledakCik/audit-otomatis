// lib/sentinel/redis.ts
// Multi-Layer Sentinel Vault, Klaim Domain, & Sesi Admin Engine:
//   L1: In-Memory RAM Cache (0 bandwidth untuk pembacaan berulang)
//   L2: Upstash Redis Baru (cepat & hemat bandwidth)
//   L3: Turso (libSQL Edge SQLite over HTTP) — Backup persisten otomatis untuk Vault AES-256-GCM & Klaim Domain

import { Redis } from "@upstash/redis";
import {
  ensureTursoSchema,
  tursoPipeline,
  sqlArg,
  cellToString,
  cellToNumber,
  type HranaStmt,
} from "@/lib/turso";

interface MemEntry {
  value: string;
  expiresAt: number | null;
  lastSyncedAt?: number;
}

const globalForSentinelMem = globalThis as unknown as {
  __sentinelRedisMem?: Map<string, MemEntry>;
  __sentinelRedisLists?: Map<string, string[]>;
  __sentinelUpstashClient?: Redis | null;
  __sentinelUpstashDeadUntil?: number;
};
const memStore = globalForSentinelMem.__sentinelRedisMem ?? new Map<string, MemEntry>();
const memLists = globalForSentinelMem.__sentinelRedisLists ?? new Map<string, string[]>();
globalForSentinelMem.__sentinelRedisMem = memStore;
globalForSentinelMem.__sentinelRedisLists = memLists;

function isExpired(entry?: MemEntry): boolean {
  if (!entry) return true;
  if (entry.expiresAt !== null && Date.now() > entry.expiresAt) {
    return true;
  }
  return false;
}

function globToRegExp(pattern: string): RegExp {
  const escaped = pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".");
  return new RegExp(`^${escaped}$`);
}

function globToSqlLike(pattern: string): string {
  return pattern.replace(/%/g, "\\%").replace(/_/g, "\\_").replace(/\*/g, "%").replace(/\?/g, "_");
}

function getUpstashClient(): Redis | null {
  if (
    globalForSentinelMem.__sentinelUpstashDeadUntil &&
    Date.now() < globalForSentinelMem.__sentinelUpstashDeadUntil
  ) {
    return null;
  }
  const url = (process.env.UPSTASH_REDIS_REST_URL ?? process.env.KV_REST_API_URL ?? "").trim();
  const token = (process.env.UPSTASH_REDIS_REST_TOKEN ?? process.env.KV_REST_API_TOKEN ?? "").trim();
  if (!url || !token || !/^https?:\/\//i.test(url)) return null;
  if (!globalForSentinelMem.__sentinelUpstashClient) {
    globalForSentinelMem.__sentinelUpstashClient = new Redis({
      url,
      token,
      automaticDeserialization: false,
    });
  }
  return globalForSentinelMem.__sentinelUpstashClient;
}

function markUpstashDead() {
  globalForSentinelMem.__sentinelUpstashDeadUntil = Date.now() + 45_000;
}

class HybridSentinelStore {
  async get<T = string>(key: string): Promise<T | null> {
    const now = Date.now();
    const local = memStore.get(key);
    // L1 Cache Hit (0 bandwidth!)
    if (local && !isExpired(local) && local.lastSyncedAt && now - local.lastSyncedAt < 3000) {
      return local.value as unknown as T;
    }

    // L2: Upstash Redis Baru
    const upstash = getUpstashClient();
    if (upstash) {
      try {
        const val = await upstash.get<string>(key);
        if (val !== null && val !== undefined) {
          const str = typeof val === "string" ? val : JSON.stringify(val);
          memStore.set(key, {
            value: str,
            expiresAt: local?.expiresAt ?? now + 3600_000,
            lastSyncedAt: now,
          });
          return str as unknown as T;
        }
      } catch {
        markUpstashDead();
      }
    }

    // L3: Turso Edge SQLite
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
          const val = cellToString(row[0]);
          const exp = cellToNumber(row[1]);
          if (exp && now > exp) {
            memStore.delete(key);
            void tursoPipeline([{ sql: "DELETE FROM sentinel_kv WHERE k = ?", args: [sqlArg(key)] }]).catch(() => {});
            return null;
          }
          if (val !== null) {
            memStore.set(key, { value: val, expiresAt: exp, lastSyncedAt: now });
            return val as unknown as T;
          }
        }
      }
    } catch {
      // fallback to memory
    }

    if (local && !isExpired(local)) {
      return local.value as unknown as T;
    }
    memStore.delete(key);
    return null;
  }

  async set(key: string, value: string, opts?: { ex?: number; keepTtl?: boolean }): Promise<string> {
    const now = Date.now();
    const prev = memStore.get(key);
    let expiresAt: number | null = null;
    if (opts?.keepTtl && prev && !isExpired(prev)) {
      expiresAt = prev.expiresAt;
    } else if (opts?.ex) {
      expiresAt = now + opts.ex * 1000;
    }
    const strVal = String(value);

    // 1. L1 Memory
    memStore.set(key, { value: strVal, expiresAt, lastSyncedAt: now });

    // 2. L2 Upstash Redis
    const upstash = getUpstashClient();
    if (upstash) {
      try {
        if (opts?.keepTtl) {
          await upstash.set(key, strVal, { keepTtl: true });
        } else if (opts?.ex) {
          await upstash.set(key, strVal, { ex: opts.ex });
        } else {
          await upstash.set(key, strVal);
        }
      } catch {
        markUpstashDead();
      }
    }

    // 3. L3 Turso Edge SQLite
    try {
      if (await ensureTursoSchema()) {
        if (opts?.keepTtl) {
          await tursoPipeline([
            {
              sql: `INSERT INTO sentinel_kv (k, v, exp) VALUES (?, ?, ?)
                    ON CONFLICT(k) DO UPDATE SET v = excluded.v`,
              args: [sqlArg(key), sqlArg(strVal), sqlArg(expiresAt)],
            },
          ]);
        } else {
          await tursoPipeline([
            {
              sql: `INSERT INTO sentinel_kv (k, v, exp) VALUES (?, ?, ?)
                    ON CONFLICT(k) DO UPDATE SET v = excluded.v, exp = excluded.exp`,
              args: [sqlArg(key), sqlArg(strVal), sqlArg(expiresAt)],
            },
          ]);
        }
      }
    } catch {
      // saved in L1/L2
    }
    return "OK";
  }

  async del(key: string): Promise<number> {
    const existed = memStore.delete(key) || memLists.delete(key);
    const upstash = getUpstashClient();
    if (upstash) {
      try {
        await upstash.del(key);
      } catch {
        markUpstashDead();
      }
    }
    try {
      if (await ensureTursoSchema()) {
        await tursoPipeline([
          { sql: "DELETE FROM sentinel_kv WHERE k = ?", args: [sqlArg(key)] },
          { sql: "DELETE FROM sentinel_list WHERE k = ?", args: [sqlArg(key)] },
        ]);
      }
    } catch {
      // ignore
    }
    return existed ? 1 : 0;
  }

  async getdel<T = string>(key: string): Promise<T | null> {
    const val = await this.get<T>(key);
    await this.del(key);
    return val;
  }

  async mget<T = (string | null)[]>(...keys: string[]): Promise<T> {
    if (!keys.length) return [] as unknown as T;
    const upstash = getUpstashClient();
    if (upstash) {
      try {
        const res = await upstash.mget<T>(...keys);
        if (res && Array.isArray(res) && res.some((x) => x !== null)) {
          return res;
        }
      } catch {
        markUpstashDead();
      }
    }
    const out = await Promise.all(keys.map((k) => this.get<string>(k)));
    return out as unknown as T;
  }

  async ttl(key: string): Promise<number> {
    const now = Date.now();
    const entry = memStore.get(key);
    if (entry && !isExpired(entry)) {
      if (entry.expiresAt === null) return -1;
      return Math.max(1, Math.ceil((entry.expiresAt - now) / 1000));
    }

    const upstash = getUpstashClient();
    if (upstash) {
      try {
        const t = await upstash.ttl(key);
        if (t > 0) return t;
      } catch {
        markUpstashDead();
      }
    }

    try {
      if (await ensureTursoSchema()) {
        const res = await tursoPipeline([
          { sql: "SELECT exp FROM sentinel_kv WHERE k = ? LIMIT 1", args: [sqlArg(key)] },
        ]);
        const row = res?.[0]?.rows?.[0];
        if (!row) return -2;
        const exp = cellToNumber(row[0]);
        if (exp === null) return -1;
        if (now > exp) return -2;
        return Math.max(1, Math.ceil((exp - now) / 1000));
      }
    } catch {
      // ignore
    }
    return -2;
  }

  async incr(key: string): Promise<number> {
    const cur = await this.get<string>(key);
    const next = (cur ? Number(cur) || 0 : 0) + 1;
    const prev = memStore.get(key);
    await this.set(key, String(next), {
      ex: prev?.expiresAt ? Math.max(1, Math.ceil((prev.expiresAt - Date.now()) / 1000)) : 900,
    });
    return next;
  }

  async expire(key: string, seconds: number): Promise<number> {
    const exp = Date.now() + seconds * 1000;
    const entry = memStore.get(key);
    if (entry && !isExpired(entry)) {
      entry.expiresAt = exp;
    }
    const upstash = getUpstashClient();
    if (upstash) {
      try {
        await upstash.expire(key, seconds);
      } catch {
        markUpstashDead();
      }
    }
    try {
      if (await ensureTursoSchema()) {
        await tursoPipeline([
          { sql: "UPDATE sentinel_kv SET exp = ? WHERE k = ?", args: [sqlArg(exp), sqlArg(key)] },
        ]);
      }
    } catch {
      // ignore
    }
    return 1;
  }

  async exists(key: string): Promise<number> {
    const val = await this.get(key);
    return val !== null ? 1 : 0;
  }

  async scan(cursor: string | number, opts?: { match?: string; count?: number }): Promise<[string, string[]]> {
    void cursor;
    const now = Date.now();
    const pattern = opts?.match || "*";
    const re = globToRegExp(pattern);
    const found = new Set<string>();

    for (const [k, v] of memStore.entries()) {
      if (isExpired(v)) {
        memStore.delete(k);
        continue;
      }
      if (re.test(k)) found.add(k);
    }

    const upstash = getUpstashClient();
    if (upstash) {
      try {
        let cur: string | number = "0";
        for (let i = 0; i < 8; i++) {
          const res: [string, string[]] = await upstash.scan(cur, { match: pattern, count: 150 });
          cur = res[0];
          for (const k of res[1]) found.add(k);
          if (String(cur) === "0") break;
        }
      } catch {
        markUpstashDead();
      }
    }

    try {
      if (await ensureTursoSchema()) {
        const likePattern = globToSqlLike(pattern);
        const res = await tursoPipeline([
          {
            sql: "SELECT k, v, exp FROM sentinel_kv WHERE k LIKE ? AND (exp IS NULL OR exp > ?) LIMIT 400",
            args: [sqlArg(likePattern), sqlArg(now)],
          },
        ]);
        for (const r of res?.[0]?.rows ?? []) {
          const k = cellToString(r[0]);
          const v = cellToString(r[1]);
          const exp = cellToNumber(r[2]);
          if (k && re.test(k)) {
            found.add(k);
            if (v !== null) {
              memStore.set(k, { value: v, expiresAt: exp, lastSyncedAt: now });
            }
          }
        }
      }
    } catch {
      // ignore
    }

    return ["0", Array.from(found)];
  }

  async lrange<T = string>(key: string, start: number, stop: number): Promise<T[]> {
    const now = Date.now();
    const upstash = getUpstashClient();
    if (upstash) {
      try {
        const res = await upstash.lrange<T>(key, start, stop);
        if (res && res.length > 0) return res;
      } catch {
        markUpstashDead();
      }
    }

    try {
      if (await ensureTursoSchema()) {
        const res = await tursoPipeline([
          {
            sql: "SELECT v FROM sentinel_list WHERE k = ? AND (exp IS NULL OR exp > ?) ORDER BY idx ASC LIMIT 400",
            args: [sqlArg(key), sqlArg(now)],
          },
        ]);
        const rows = res?.[0]?.rows ?? [];
        if (rows.length > 0) {
          const items = rows.map((r) => cellToString(r[0]) ?? "").filter(Boolean);
          memLists.set(key, items);
          const end = stop < 0 ? items.length + 1 + stop : stop + 1;
          return items.slice(start < 0 ? Math.max(0, items.length + start) : start, end) as unknown as T[];
        }
      }
    } catch {
      // fallback
    }

    const list = memLists.get(key) ?? [];
    const end = stop < 0 ? list.length + 1 + stop : stop + 1;
    return list.slice(start < 0 ? Math.max(0, list.length + start) : start, end) as unknown as T[];
  }

  pipeline() {
    const ops: Array<() => Promise<unknown>> = [];
    const batchSql: HranaStmt[] = [];
    const upstash = getUpstashClient();
    const upstashPipe = upstash ? upstash.pipeline() : null;

    const pipe = {
      set: (key: string, value: string, opts?: { ex?: number; keepTtl?: boolean }) => {
        const exp = opts?.ex ? Date.now() + opts.ex * 1000 : null;
        if (upstashPipe) {
          if (opts?.keepTtl) upstashPipe.set(key, value, { keepTtl: true });
          else if (opts?.ex) upstashPipe.set(key, value, { ex: opts.ex });
          else upstashPipe.set(key, value);
        }
        batchSql.push({
          sql: `INSERT INTO sentinel_kv (k, v, exp) VALUES (?, ?, ?)
                ON CONFLICT(k) DO UPDATE SET v = excluded.v, exp = COALESCE(excluded.exp, sentinel_kv.exp)`,
          args: [sqlArg(key), sqlArg(String(value)), sqlArg(exp)],
        });
        ops.push(async () => {
          memStore.set(key, { value: String(value), expiresAt: exp, lastSyncedAt: Date.now() });
          return "OK";
        });
        return pipe;
      },
      get: (key: string) => {
        upstashPipe?.get(key);
        ops.push(() => this.get(key));
        return pipe;
      },
      ttl: (key: string) => {
        upstashPipe?.ttl(key);
        ops.push(() => this.ttl(key));
        return pipe;
      },
      rpush: (key: string, value: string) => {
        const exp = Date.now() + 7 * 24 * 3600 * 1000;
        upstashPipe?.rpush(key, value);
        batchSql.push({
          sql: "INSERT INTO sentinel_list (k, v, exp) VALUES (?, ?, ?)",
          args: [sqlArg(key), sqlArg(String(value)), sqlArg(exp)],
        });
        ops.push(async () => {
          const list = memLists.get(key) ?? [];
          list.push(value);
          memLists.set(key, list);
          return list.length;
        });
        return pipe;
      },
      ltrim: (key: string, start: number, stop: number) => {
        upstashPipe?.ltrim(key, start, stop);
        ops.push(async () => {
          const list = memLists.get(key) ?? [];
          const s = start < 0 ? Math.max(0, list.length + start) : start;
          const e = stop < 0 ? list.length + 1 + stop : stop + 1;
          memLists.set(key, list.slice(s, e));
          return "OK";
        });
        return pipe;
      },
      expire: (key: string, seconds: number) => {
        upstashPipe?.expire(key, seconds);
        ops.push(() => this.expire(key, seconds));
        return pipe;
      },
      exec: async () => {
        if (batchSql.length > 0) {
          try {
            if (await ensureTursoSchema()) {
              await tursoPipeline(batchSql);
            }
          } catch {
            // ignore
          }
        }
        if (upstashPipe) {
          try {
            const uRes = await upstashPipe.exec();
            await Promise.all(ops.map((fn) => fn()));
            return uRes;
          } catch {
            markUpstashDead();
          }
        }
        return Promise.all(ops.map((fn) => fn()));
      },
    };
    return pipe;
  }
}

let storeInstance: HybridSentinelStore | null = null;

/** Hybrid L1 Memory + L2 Redis Baru + L3 Turso Edge SQLite client. */
export function redis(): Redis {
  if (!storeInstance) {
    storeInstance = new HybridSentinelStore();
  }
  return storeInstance as unknown as Redis;
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

/** SCAN cursor-based di atas Hybrid Redis + Turso. */
export async function scanKeys(pattern: string, cap = 500): Promise<string[]> {
  const r = redis();
  const out: string[] = [];
  let cursor: string | number = "0";
  try {
    do {
      const res: [string, string[]] = await r.scan(cursor, { match: pattern, count: 200 });
      cursor = res[0];
      out.push(...res[1]);
    } while (String(cursor) !== "0" && out.length < cap);
  } catch {
    return [];
  }
  return out.slice(0, cap);
}

/** Fixed-window rate limit di L1 Memory (0 Redis/Turso bandwidth consumption!). */
const localRateMap = new Map<string, { count: number; expiresAt: number }>();

export async function rateLimit(scope: string, ip: string, max: number, windowSec: number) {
  const now = Date.now();
  const key = K.rl(scope, ip);
  const cur = localRateMap.get(key);
  if (!cur || now > cur.expiresAt) {
    localRateMap.set(key, { count: 1, expiresAt: now + windowSec * 1000 });
    return true;
  }
  cur.count += 1;
  return cur.count <= max;
}

export function clientIp(req: Request): string {
  const xff = req.headers.get("x-forwarded-for");
  return (xff?.split(",")[0] ?? req.headers.get("x-real-ip") ?? "unknown").trim();
}
