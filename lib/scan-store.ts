import type {
  DiscoveredEndpoint,
  Finding,
  GraphData,
  LibraryDetection,
  ScanLogEvent,
  ScanState,
  ScanStatus,
} from "./types";
import { getRedis, REDIS_CONFIGURED } from "./redis";

/**
 * Store untuk state scan — SEKARANG berbasis Redis (Upstash) supaya konsisten
 * di semua serverless instance Vercel. Lihat lib/redis.ts untuk penjelasan
 * kenapa ini perlu.
 *
 * Data tetap tidak permanen: semua key di-set dengan TTL (SCAN_TTL_SECONDS),
 * sama seperti behavior lama ("jangan di log permanen").
 *
 * Kalau Redis belum dikonfigurasi (mis. dev lokal tanpa setup), semua fungsi
 * di file ini otomatis jatuh ke in-memory Map per-proses — cukup untuk
 * `next dev`, TAPI TIDAK aman dipakai di Vercel production (lihat warning di
 * lib/redis.ts).
 *
 * Semua fungsi publik sekarang async (network round-trip ke Redis), jadi
 * semua pemanggilnya (scan-runner.ts, route handlers) HARUS di-await.
 */

const MAX_LOGS_KEPT = 500;
const SCAN_TTL_SECONDS = 30 * 60; // auto-bersih 30 menit setelah dibuat, sama seperti sebelumnya

const metaKey = (id: string) => `trout:scan:${id}:meta`;
const logsKey = (id: string) => `trout:scan:${id}:logs`;

type ScanMeta = Omit<ScanState, "logs">;

// --- Fallback in-memory (HANYA dev lokal tanpa Redis) ---
const globalForScanStore = globalThis as unknown as {
  __troutScansMem?: Map<string, ScanState>;
};
const memScans = globalForScanStore.__troutScansMem ?? new Map<string, ScanState>();
globalForScanStore.__troutScansMem = memScans;

function scheduleMemCleanup(id: string) {
  setTimeout(() => {
    memScans.delete(id);
  }, SCAN_TTL_SECONDS * 1000).unref?.();
}

function freshState(id: string, domain: string, origin: string): ScanState {
  return {
    id,
    domain,
    origin,
    status: "queued",
    createdAt: Date.now(),
    logs: [],
    findings: [],
    endpoints: [],
    endpointsDiscovered: 0,
    requestsMade: 0,
    graph: { nodes: [], edges: [] },
    pagesCrawled: 0,
    jsFilesScanned: 0,
    librariesDetected: [],
  };
}

export async function createScan(id: string, domain: string, origin: string): Promise<ScanState> {
  const state = freshState(id, domain, origin);

  if (REDIS_CONFIGURED) {
    const redis = getRedis();
    const { logs: _logs, ...meta } = state;
    await redis.set(metaKey(id), meta, { ex: SCAN_TTL_SECONDS });
  } else {
    memScans.set(id, state);
    scheduleMemCleanup(id);
  }

  return state;
}

export async function getScan(id: string): Promise<ScanState | undefined> {
  if (REDIS_CONFIGURED) {
    const redis = getRedis();
    const meta = await redis.get<ScanMeta>(metaKey(id));
    if (!meta) return undefined;
    const logs = await getLogsSince(id, 0);
    return { ...meta, logs };
  }
  return memScans.get(id);
}

/** Ambil log dari index tertentu (dipakai SSE stream buat resume via Last-Event-ID). */
export async function getLogsSince(id: string, fromIndex: number): Promise<ScanLogEvent[]> {
  if (REDIS_CONFIGURED) {
    const redis = getRedis();
    const raw = await redis.lrange<ScanLogEvent>(logsKey(id), fromIndex, -1);
    return raw ?? [];
  }
  const state = memScans.get(id);
  if (!state) return [];
  return state.logs.slice(fromIndex);
}

async function updateMeta(id: string, mutate: (state: ScanMeta) => void): Promise<void> {
  if (REDIS_CONFIGURED) {
    const redis = getRedis();
    const meta = await redis.get<ScanMeta>(metaKey(id));
    if (!meta) return;
    mutate(meta);
    await redis.set(metaKey(id), meta, { ex: SCAN_TTL_SECONDS });
  } else {
    const state = memScans.get(id);
    if (!state) return;
    mutate(state);
  }
}

export async function emit(id: string, event: Omit<ScanLogEvent, "timestamp">): Promise<void> {
  const full: ScanLogEvent = { ...event, timestamp: Date.now() };

  if (REDIS_CONFIGURED) {
    const redis = getRedis();
    const pipeline = redis.pipeline();
    pipeline.rpush(logsKey(id), full);
    pipeline.ltrim(logsKey(id), -MAX_LOGS_KEPT, -1);
    pipeline.expire(logsKey(id), SCAN_TTL_SECONDS);
    await pipeline.exec();
  } else {
    const state = memScans.get(id);
    if (!state) return;
    state.logs.push(full);
    if (state.logs.length > MAX_LOGS_KEPT) {
      state.logs.splice(0, state.logs.length - MAX_LOGS_KEPT);
    }
  }

  if (event.type === "status" && event.status) {
    await updateMeta(id, (s) => {
      s.status = event.status!;
    });
  }
  if (event.type === "finding" && event.finding) {
    await updateMeta(id, (s) => {
      s.findings.push(event.finding!);
    });
  }
}

export async function setStatus(id: string, status: ScanStatus): Promise<void> {
  await emit(id, { type: "status", status });
}

export async function log(id: string, message: string): Promise<void> {
  await emit(id, { type: "log", message });
}

export async function addFinding(id: string, finding: Finding): Promise<void> {
  await emit(id, { type: "finding", finding });
}

export async function markDone(id: string): Promise<void> {
  await emit(id, { type: "done", message: "Scan selesai." });
}

export async function markError(id: string, message: string): Promise<void> {
  await emit(id, { type: "error", message });
}

export async function markBlocked(id: string, reason: string): Promise<void> {
  await updateMeta(id, (s) => {
    s.blockedReason = reason;
  });
  await emit(id, { type: "blocked", message: reason, status: "blocked_cloudflare" });
}

export async function bumpRequestCount(id: string, n = 1): Promise<void> {
  await updateMeta(id, (s) => {
    s.requestsMade += n;
  });
}

export async function setEndpointsDiscovered(id: string, n: number): Promise<void> {
  await updateMeta(id, (s) => {
    s.endpointsDiscovered = n;
  });
}

/**
 * Simpan daftar lengkap link/endpoint yang ditemukan dan broadcast ke client
 * lewat SSE supaya tampil di dashboard, bukan cuma angka jumlahnya.
 */
export async function setDiscoveredEndpoints(id: string, endpoints: DiscoveredEndpoint[]): Promise<void> {
  await updateMeta(id, (s) => {
    s.endpoints = endpoints;
  });
  await emit(id, { type: "endpoints", endpoints });
}

/**
 * Simpan peta relasi page -> js -> endpoint hasil crawl mendalam. Tidak
 * di-broadcast lewat SSE (graph bisa besar) — client mengambilnya lewat
 * GET /api/scan/[id]/graph setelah scan selesai/berjalan.
 */
export async function setGraph(id: string, graph: GraphData): Promise<void> {
  await updateMeta(id, (s) => {
    s.graph = graph;
  });
}

export async function setPagesCrawled(id: string, n: number): Promise<void> {
  await updateMeta(id, (s) => {
    s.pagesCrawled = n;
  });
}

export async function bumpJsFilesScanned(id: string, n = 1): Promise<void> {
  await updateMeta(id, (s) => {
    s.jsFilesScanned += n;
  });
}

export async function setLibrariesDetected(id: string, libs: LibraryDetection[]): Promise<void> {
  await updateMeta(id, (s) => {
    s.librariesDetected = libs;
  });
}
