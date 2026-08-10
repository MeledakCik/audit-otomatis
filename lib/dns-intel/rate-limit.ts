import { getKv, REDIS_CONFIGURED } from "@/lib/redis";

const WINDOW_MS = 60_000;
const MAX_PER_WINDOW = 10;

// Fallback in-memory kalau Redis belum dikonfigurasi (dev lokal) — sama
// polanya dengan lib/rate-limit.ts punya trout sendiri.
const memWindows = new Map<string, number[]>();

function currentWindowBucket(): number {
  return Math.floor(Date.now() / WINDOW_MS);
}

/**
 * Rate limit 10 request/menit per IP, fixed-window. Dipisah dari
 * lib/rate-limit.ts (yang isinya cooldown per-domain 5 menit untuk full
 * scan) karena semantiknya beda: ini benar-benar per-IP, per-menit.
 */
export async function checkDnsRateLimit(ip: string): Promise<{ allowed: true } | { allowed: false; retryAfterMs: number }> {
  const bucket = currentWindowBucket();
  const key = `trout:dns-intel:rl:${ip}:${bucket}`;

  if (REDIS_CONFIGURED) {
    const kv = getKv();
    await kv.rpushJSON(key, Date.now(), 65, 50);
    const entries = await kv.lrangeJSON<number>(key, 0, -1);
    if (entries.length > MAX_PER_WINDOW) {
      const msLeftInWindow = WINDOW_MS - (Date.now() % WINDOW_MS);
      return { allowed: false, retryAfterMs: msLeftInWindow };
    }
    return { allowed: true };
  }

  const now = Date.now();
  const list = (memWindows.get(ip) ?? []).filter((t) => now - t < WINDOW_MS);
  if (list.length >= MAX_PER_WINDOW) {
    const oldest = Math.min(...list);
    return { allowed: false, retryAfterMs: Math.max(0, WINDOW_MS - (now - oldest)) };
  }
  list.push(now);
  memWindows.set(ip, list);
  return { allowed: true };
}
