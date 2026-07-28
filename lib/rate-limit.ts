import { getRedis, REDIS_CONFIGURED } from "./redis";

/**
 * Cooldown per (user, hostname) — SEKARANG berbasis Redis (SET ... NX EX),
 * yang atomik dan konsisten di semua serverless instance Vercel.
 *
 * Sebelumnya ini cuma `Map` in-memory: tiap instance serverless punya map
 * kosong sendiri-sendiri, jadi limit "1 scan/domain/5 menit" praktis TIDAK
 * pernah kena di Vercel (bisa dipakai spam scan ke domain yang sama dari
 * banyak invocation berbeda) — celah keamanan, bukan cuma bug UX.
 *
 * Fallback in-memory tetap ada untuk dev lokal tanpa Redis.
 */

const COOLDOWN_SECONDS = 5 * 60; // 5 menit
const COOLDOWN_MS = COOLDOWN_SECONDS * 1000;

const memCooldowns = new Map<string, number>();

export async function checkAndRegisterCooldown(
  userKey: string,
  hostname: string
): Promise<{ allowed: true } | { allowed: false; retryAfterMs: number }> {
  const key = `trout:cooldown:${userKey}:${hostname.toLowerCase()}`;

  if (REDIS_CONFIGURED) {
    const redis = getRedis();
    // SET dengan NX (cuma set kalau belum ada) + EX (auto-expire) = klaim
    // cooldown yang atomik, tanpa race condition antar request paralel.
    const claimed = await redis.set(key, Date.now(), { nx: true, ex: COOLDOWN_SECONDS });
    if (claimed) return { allowed: true };

    const ttl = await redis.ttl(key);
    return { allowed: false, retryAfterMs: Math.max(0, ttl) * 1000 };
  }

  const now = Date.now();
  const last = memCooldowns.get(key);
  if (last && now - last < COOLDOWN_MS) {
    return { allowed: false, retryAfterMs: COOLDOWN_MS - (now - last) };
  }
  memCooldowns.set(key, now);
  return { allowed: true };
}

/**
 * Budget request per scan: hard cap total request + delay antar request
 * supaya scanner tidak jadi alat DDoS. Ini SENGAJA tetap in-memory (class
 * biasa, bukan module-level singleton) karena scope-nya cuma satu eksekusi
 * runScan() yang berjalan sekuensial dalam satu invocation — tidak perlu
 * dibagi antar instance seperti scan-store/rate-limit di atas.
 */
export class RequestBudget {
  private used = 0;
  constructor(
    private readonly max = 100,
    private readonly delayMs = 500
  ) {}

  get remaining() {
    return Math.max(0, this.max - this.used);
  }

  get count() {
    return this.used;
  }

  canSpend(n = 1): boolean {
    return this.used + n <= this.max;
  }

  async spend<T>(fn: () => Promise<T>): Promise<T | null> {
    if (!this.canSpend()) return null;
    this.used++;
    const result = await fn();
    await sleep(this.delayMs);
    return result;
  }
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
