import { Redis } from "@upstash/redis";

/**
 * PENTING — kenapa file ini ada:
 *
 * Di Vercel, tiap request (Server Action maupun Route Handler) bisa dieksekusi
 * di instance serverless yang BERBEDA, bahkan untuk request-request yang
 * datang beruntun dari user yang sama. Data yang cuma disimpan di memory
 * proses Node (module-level `Map`, `globalThis`, dst) TIDAK dijamin sama
 * antar instance — ini yang menyebabkan endpoint seperti
 * `/api/scan/[id]/stream` mengembalikan 404 "Scan tidak ditemukan" padahal
 * scan-nya baru saja dibuat lewat Server Action di instance lain.
 *
 * Solusinya: state scan (dan cooldown rate-limit) harus disimpan di storage
 * eksternal yang bisa diakses semua instance — di sini pakai Upstash Redis,
 * karena:
 *   1. Vercel KV sudah di-deprecate & diganti integrasi "Upstash Redis" di
 *      Vercel Marketplace (otomatis inject env var saat di-install).
 *   2. Upstash pakai REST API (bukan koneksi TCP persisten), jadi aman
 *      dipanggil dari serverless/edge function tanpa connection pooling.
 *
 * Cara setup di Vercel:
 *   1. Buka project di Vercel Dashboard -> tab "Storage" -> "Marketplace
 *      Database Storage" -> cari "Upstash" -> pilih produk Redis -> Connect.
 *   2. Vercel otomatis menambahkan env var `KV_REST_API_URL` &
 *      `KV_REST_API_TOKEN` (atau `UPSTASH_REDIS_REST_URL` /
 *      `UPSTASH_REDIS_REST_TOKEN`, keduanya didukung) ke project ini.
 *   3. Redeploy. Selesai — tidak perlu ubah kode apa pun.
 *
 * Untuk dev lokal (`next dev`) TANPA setup Redis, scan-store.ts otomatis
 * jatuh ke in-memory Map seperti sebelumnya (cukup untuk 1 proses lokal).
 * Fallback ini SENGAJA tidak dipakai kalau berjalan di Vercel production
 * tanpa Redis ter-setup — akan melempar error yang jelas daripada diam-diam
 * 404 seperti sebelumnya.
 */

function hasRedisEnv(): boolean {
  return Boolean(
    (process.env.KV_REST_API_URL && process.env.KV_REST_API_TOKEN) ||
      (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN)
  );
}

export const REDIS_CONFIGURED = hasRedisEnv();

let cachedClient: Redis | null = null;

export function getRedis(): Redis {
  if (!REDIS_CONFIGURED) {
    throw new Error(
      "Redis belum dikonfigurasi (env UPSTASH_REDIS_REST_URL/TOKEN atau KV_REST_API_URL/TOKEN tidak ditemukan). " +
        "Install integrasi 'Upstash Redis' dari Vercel Marketplace, atau isi .env.local untuk dev."
    );
  }
  if (!cachedClient) {
    cachedClient = Redis.fromEnv();
  }
  return cachedClient;
}

// Dijalankan sekali saat module di-load (build/cold start), bukan per-request,
// supaya kelihatan jelas di log server kalau env belum di-setup — sebelum
// user bingung kenapa scan-nya "hilang".
if (!REDIS_CONFIGURED && process.env.NODE_ENV !== "test") {
  const isProd = process.env.VERCEL === "1" || process.env.NODE_ENV === "production";
  const msg =
    "[redis] Env Redis (UPSTASH_REDIS_REST_URL/TOKEN) tidak ditemukan — " +
    (isProd
      ? "scan-store & rate-limit TIDAK akan berfungsi benar di Vercel tanpa ini " +
        "(tiap serverless instance akan punya state sendiri-sendiri). " +
        "Install integrasi Upstash Redis dari Vercel Marketplace lalu redeploy."
      : "pakai in-memory fallback (OK untuk `next dev` lokal, tidak untuk production).");
  // eslint-disable-next-line no-console
  console.warn(msg);
}
