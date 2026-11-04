import { Redis } from "@upstash/redis";

interface MemEntry {
  value: string;
  expiresAt: number | null;
}

const globalForSentinelMem = globalThis as unknown as {
  __sentinelRedisMem?: Map<string, MemEntry>;
  __sentinelRedisLists?: Map<string, string[]>;
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

class MemoryRedisFallback {
  async get<T = string>(key: string): Promise<T | null> {
    const entry = memStore.get(key);
    if (!entry || isExpired(entry)) {
      memStore.delete(key);
      return null;
    }
    return entry.value as unknown as T;
  }

  async set(key: string, value: string, opts?: { ex?: number; keepTtl?: boolean }): Promise<string> {
    const prev = memStore.get(key);
    let expiresAt: number | null = null;
    if (opts?.keepTtl && prev && !isExpired(prev)) {
      expiresAt = prev.expiresAt;
    } else if (opts?.ex) {
      expiresAt = Date.now() + opts.ex * 1000;
    }
    memStore.set(key, { value: String(value), expiresAt });
    return "OK";
  }

  async del(key: string): Promise<number> {
    const existed = memStore.delete(key) || memLists.delete(key);
    return existed ? 1 : 0;
  }

  async getdel<T = string>(key: string): Promise<T | null> {
    const val = await this.get<T>(key);
    memStore.delete(key);
    return val;
  }

  async mget<T = (string | null)[]>(...keys: string[]): Promise<T> {
    const out = await Promise.all(keys.map((k) => this.get<string>(k)));
    return out as unknown as T;
  }

  async ttl(key: string): Promise<number> {
    const entry = memStore.get(key);
    if (!entry || isExpired(entry)) {
      memStore.delete(key);
      return -2;
    }
    if (entry.expiresAt === null) return -1;
    return Math.max(1, Math.ceil((entry.expiresAt - Date.now()) / 1000));
  }

  async incr(key: string): Promise<number> {
    const cur = await this.get<string>(key);
    const next = (cur ? Number(cur) || 0 : 0) + 1;
    const prev = memStore.get(key);
    memStore.set(key, { value: String(next), expiresAt: prev?.expiresAt ?? null });
    return next;
  }

  async expire(key: string, seconds: number): Promise<number> {
    const entry = memStore.get(key);
    if (!entry || isExpired(entry)) return 0;
    entry.expiresAt = Date.now() + seconds * 1000;
    return 1;
  }

  async exists(key: string): Promise<number> {
    const val = await this.get(key);
    return val !== null ? 1 : 0;
  }

  async scan(cursor: string | number, opts?: { match?: string; count?: number }): Promise<[string, string[]]> {
    void cursor;
    const re = opts?.match ? globToRegExp(opts.match) : null;
    const keys: string[] = [];
    for (const [k, v] of memStore.entries()) {
      if (isExpired(v)) {
        memStore.delete(k);
        continue;
      }
      if (!re || re.test(k)) keys.push(k);
    }
    return ["0", keys];
  }

  async lrange<T = string>(key: string, start: number, stop: number): Promise<T[]> {
    const list = memLists.get(key) ?? [];
    const end = stop < 0 ? list.length + 1 + stop : stop + 1;
    return list.slice(start < 0 ? Math.max(0, list.length + start) : start, end) as unknown as T[];
  }

  pipeline() {
    const ops: Array<() => Promise<unknown>> = [];
    const pipe = {
      set: (key: string, value: string, opts?: { ex?: number; keepTtl?: boolean }) => {
        ops.push(() => this.set(key, value, opts));
        return pipe;
      },
      get: (key: string) => {
        ops.push(() => this.get(key));
        return pipe;
      },
      ttl: (key: string) => {
        ops.push(() => this.ttl(key));
        return pipe;
      },
      rpush: (key: string, value: string) => {
        ops.push(async () => {
          const list = memLists.get(key) ?? [];
          list.push(value);
          memLists.set(key, list);
          return list.length;
        });
        return pipe;
      },
      ltrim: (key: string, start: number, stop: number) => {
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
        ops.push(() => this.expire(key, seconds));
        return pipe;
      },
      exec: async () => Promise.all(ops.map((fn) => fn())),
    };
    return pipe;
  }
}

let client: Redis | null = null;
let memFallback: MemoryRedisFallback | null = null;

/** Upstash REST client (fetch-based → aman di Node maupun Edge/proxy) dengan in-memory fallback. */
export function redis(): Redis {
  const url = process.env.UPSTASH_REDIS_REST_URL ?? process.env.KV_REST_API_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN ?? process.env.KV_REST_API_TOKEN;
  if (url && token) {
    if (!client) {
      client = new Redis({ url, token, automaticDeserialization: false });
    }
    return client;
  }
  if (!memFallback) {
    memFallback = new MemoryRedisFallback();
  }
  return memFallback as unknown as Redis;
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
  return (xff?.split(",")[0] ?? req.headers.get("x-real-ip") ?? "unknown").trim();
}
