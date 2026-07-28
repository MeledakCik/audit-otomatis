import { getKv, REDIS_CONFIGURED } from "./redis";

const IS_DEV = process.env.NODE_ENV === "development";

const COOLDOWN_SECONDS = IS_DEV ? 10 : 5 * 60;
const COOLDOWN_MS = COOLDOWN_SECONDS * 1000;

const memCooldowns = new Map<string, number>();

export async function checkAndRegisterCooldown(
  userKey: string,
  hostname: string
): Promise<{ allowed: true } | { allowed: false; retryAfterMs: number }> {
  const key = `trout:cooldown:${userKey}:${hostname.toLowerCase()}`;

  if (REDIS_CONFIGURED) {
    const kv = getKv();
    const claimed = await kv.setNX(key, COOLDOWN_SECONDS);
    if (claimed) return { allowed: true };

    const ttl = await kv.ttl(key);
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

export class RequestBudget {
  private used = 0;
  constructor(private readonly max = 100, private readonly delayMs = 500) {}
  get remaining() { return Math.max(0, this.max - this.used); }
  get count() { return this.used; }
  canSpend(n = 1): boolean { return this.used + n <= this.max; }
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