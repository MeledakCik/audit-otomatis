import type { DiscoveredEndpoint, Finding, ScanLogEvent, ScanState, ScanStatus } from "./types";

/**
 * Store di memory proses (bukan file/DB permanen). Data hilang saat server
 * restart — sesuai requirement "jangan di log permanen".
 *
 * PENTING: modul ini bisa ter-instantiate lebih dari sekali dalam satu
 * proses Node yang sama — Next.js (khususnya dengan Turbopack di dev mode)
 * meng-compile Route Handlers (app/api/**\/route.ts) sebagai module graph
 * yang terpisah dari Server Components/Actions. Kalau `scans`/`subscribers`
 * cuma module-level `const`, tiap graph dapat instance Map-nya sendiri —
 * akibatnya scan yang dibuat lewat Server Action (startScanAction) tidak
 * ketemu saat di-query dari Route Handler (stream/export), walau masih
 * dalam proses `next dev` yang sama. Nempelin ke globalThis memastikan
 * semua graph share satu instance yang sama, sekaligus survive HMR reload.
 */
const globalForScanStore = globalThis as unknown as {
  __troutScans?: Map<string, ScanState>;
  __troutSubscribers?: Map<string, Set<(event: ScanLogEvent) => void>>;
};

const scans = globalForScanStore.__troutScans ?? new Map<string, ScanState>();
const subscribers =
  globalForScanStore.__troutSubscribers ?? new Map<string, Set<(event: ScanLogEvent) => void>>();

globalForScanStore.__troutScans = scans;
globalForScanStore.__troutSubscribers = subscribers;

const MAX_LOGS_KEPT = 500;
const SCAN_TTL_MS = 30 * 60 * 1000; // auto-bersihkan 30 menit setelah dibuat

export function createScan(id: string, domain: string, origin: string): ScanState {
  const state: ScanState = {
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
  scans.set(id, state);
  scheduleCleanup(id);
  return state;
}

export function getScan(id: string): ScanState | undefined {
  return scans.get(id);
}

function scheduleCleanup(id: string) {
  setTimeout(() => {
    scans.delete(id);
    subscribers.delete(id);
  }, SCAN_TTL_MS).unref?.();
}

export function emit(id: string, event: Omit<ScanLogEvent, "timestamp">) {
  const state = scans.get(id);
  if (!state) return;
  const full: ScanLogEvent = { ...event, timestamp: Date.now() };

  if (event.type === "status" && event.status) {
    state.status = event.status;
  }
  if (event.type === "finding" && event.finding) {
    state.findings.push(event.finding);
  }

  state.logs.push(full);
  if (state.logs.length > MAX_LOGS_KEPT) {
    state.logs.splice(0, state.logs.length - MAX_LOGS_KEPT);
  }

  const subs = subscribers.get(id);
  if (subs) {
    for (const cb of subs) cb(full);
  }
}

export function subscribe(id: string, cb: (event: ScanLogEvent) => void): () => void {
  if (!subscribers.has(id)) subscribers.set(id, new Set());
  subscribers.get(id)!.add(cb);
  return () => {
    subscribers.get(id)?.delete(cb);
  };
}

export function setStatus(id: string, status: ScanStatus) {
  emit(id, { type: "status", status });
}

export function log(id: string, message: string) {
  emit(id, { type: "log", message });
}

export function addFinding(id: string, finding: Finding) {
  emit(id, { type: "finding", finding });
}

export function markDone(id: string) {
  emit(id, { type: "done", message: "Scan selesai." });
}

export function markError(id: string, message: string) {
  emit(id, { type: "error", message });
}

export function markBlocked(id: string, reason: string) {
  const state = scans.get(id);
  if (state) state.blockedReason = reason;
  emit(id, { type: "blocked", message: reason, status: "blocked_cloudflare" });
}

export function bumpRequestCount(id: string, n = 1) {
  const state = scans.get(id);
  if (state) state.requestsMade += n;
}

export function setEndpointsDiscovered(id: string, n: number) {
  const state = scans.get(id);
  if (state) state.endpointsDiscovered = n;
}

/**
 * Simpan daftar lengkap link/endpoint yang ditemukan (crawler + form +
 * JS analyzer, method GET/POST asli beserta payload field kalau ada) dan
 * broadcast ke client lewat SSE supaya tampil di dashboard, bukan cuma
 * angka jumlahnya.
 */
export function setDiscoveredEndpoints(id: string, endpoints: DiscoveredEndpoint[]) {
  const state = scans.get(id);
  if (state) state.endpoints = endpoints;
  emit(id, { type: "endpoints", endpoints });
}

/**
 * Simpan peta relasi page -> js -> endpoint hasil crawl mendalam. Tidak
 * di-broadcast lewat SSE (graph bisa besar) — client mengambilnya lewat
 * GET /api/scan/[id]/graph setelah scan selesai/berjalan.
 */
export function setGraph(id: string, graph: import("./types").GraphData) {
  const state = scans.get(id);
  if (state) state.graph = graph;
}

export function setPagesCrawled(id: string, n: number) {
  const state = scans.get(id);
  if (state) state.pagesCrawled = n;
}

export function bumpJsFilesScanned(id: string, n = 1) {
  const state = scans.get(id);
  if (state) state.jsFilesScanned += n;
}

export function setLibrariesDetected(id: string, libs: import("./types").LibraryDetection[]) {
  const state = scans.get(id);
  if (state) state.librariesDetected = libs;
}
