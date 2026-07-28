/**
 * Rate limiting sederhana berbasis memory (bukan permanen, hilang saat
 * server restart). Cocok untuk tool internal single-instance.
 */

const COOLDOWN_MS = 5 * 60 * 1000; // 5 menit

// key = `${userKey}:${hostname}`
const lastScanAt = new Map<string, number>();

export function checkAndRegisterCooldown(
  userKey: string,
  hostname: string
): { allowed: true } | { allowed: false; retryAfterMs: number } {
  const key = `${userKey}:${hostname.toLowerCase()}`;
  const now = Date.now();
  const last = lastScanAt.get(key);
  if (last && now - last < COOLDOWN_MS) {
    return { allowed: false, retryAfterMs: COOLDOWN_MS - (now - last) };
  }
  lastScanAt.set(key, now);
  return { allowed: true };
}

/**
 * Budget request per scan: hard cap total request + delay antar request
 * supaya scanner tidak jadi alat DDoS.
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
