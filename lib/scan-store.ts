import { withCwe } from "./vuln/cwe";
import type {
  CrawledPage,
  DiscoveredEndpoint,
  Finding,
  GraphData,
  LibraryDetection,
  ScanLogEvent,
  ScanState,
  ScanStatus,
} from "./types";
import { getKv } from "./redis";

const MAX_LOGS_KEPT = 350;
const SCAN_TTL_SECONDS = 30 * 60; // auto-bersih 30 menit setelah dibuat

/** Batas keras satu scan (di bawah maxDuration 300s route). Lewat ini scan dihentikan otomatis. */
export const SCAN_MAX_MS = 270_000;
/** Scan non-terminal yang lebih tua dari ini dianggap macet/mati (runner hilang) dan di-reap. */
const SCAN_STALE_MS = 6 * 60_000;
const STOP_TTL_SECONDS = 10 * 60;
const STOP_CHECK_INTERVAL_MS = 4000;

const TERMINAL_STATUSES = new Set<ScanStatus>(["done", "error", "blocked_cloudflare", "stopped"]);
export const isTerminalStatus = (s: ScanStatus) => TERMINAL_STATUSES.has(s);

export class ScanAbortedError extends Error {
  constructor(message: string, readonly deleted = false) {
    super(message);
    this.name = "ScanAbortedError";
  }
}

interface StopRecord {
  reason: string;
  deleted: boolean;
  at: number;
}

const metaKey = (id: string) => `trout:scan:${id}:meta`;
const logsKey = (id: string) => `trout:scan:${id}:logs`;
const stopKey = (id: string) => `trout:scan:${id}:stop`;
const META_KEY_PATTERN = "trout:scan:*:meta";

type ScanMeta = Omit<ScanState, "logs">;

// --- L1 In-Memory Store (Super Cepat + 0 Bandwidth untuk SSE Stream & RequestCount) ---
const globalForScanStore = globalThis as unknown as {
  __troutScansMem?: Map<string, ScanState>;
  __troutScansLastPersist?: Map<string, number>;
  __troutScansStop?: Map<string, StopRecord>;
  __troutScansStopChecked?: Map<string, number>;
};
const memScans = globalForScanStore.__troutScansMem ?? new Map<string, ScanState>();
const lastPersist = globalForScanStore.__troutScansLastPersist ?? new Map<string, number>();
const memStop = globalForScanStore.__troutScansStop ?? new Map<string, StopRecord>();
const stopChecked = globalForScanStore.__troutScansStopChecked ?? new Map<string, number>();
globalForScanStore.__troutScansStop = memStop;
globalForScanStore.__troutScansStopChecked = stopChecked;
globalForScanStore.__troutScansMem = memScans;
globalForScanStore.__troutScansLastPersist = lastPersist;

function scheduleMemCleanup(id: string) {
  setTimeout(() => {
    memScans.delete(id);
    lastPersist.delete(id);
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
    pages: [],
  };
}

function findingDedupKey(f: Finding): string {
  return `${f.severity}|${f.category ?? ""}|${f.title.trim()}|${f.endpoint.trim()}|${f.evidence.trim().slice(0, 120)}`;
}

async function persistMetaToDb(id: string, force = false): Promise<void> {
  const state = memScans.get(id);
  if (!state) return;
  const now = Date.now();
  const prev = lastPersist.get(id) ?? 0;
  // Throttle DB writes ke maksimal 1x setiap 3 detik kecuali force=true (saat create, finding baru, atau done)
  if (!force && now - prev < 3000) return;
  lastPersist.set(id, now);

  const { logs: _logs, ...meta } = state;
  await getKv().setJSON(metaKey(id), meta, SCAN_TTL_SECONDS);
}

export async function createScan(id: string, domain: string, origin: string): Promise<ScanState> {
  const state = freshState(id, domain, origin);
  memScans.set(id, state);
  scheduleMemCleanup(id);
  await persistMetaToDb(id, true);
  return state;
}

export async function getScan(id: string): Promise<ScanState | undefined> {
  const local = memScans.get(id);
  if (local) {
    await reapIfStale(local);
    return local;
  }
  if (memStop.get(id)?.deleted) return undefined; // baru dihapus admin
  const meta = await getKv().getJSON<ScanMeta>(metaKey(id));
  if (!meta) return undefined;
  const logs = await getLogsSince(id, 0);
  const full: ScanState = { ...meta, logs };
  memScans.set(id, full);
  await reapIfStale(full);
  return full;
}

/**
 * Scan yang belum selesai tapi sudah lewat SCAN_STALE_MS berarti runner-nya mati/macet
 * (mis. instance serverless dimatikan) — tandai "stopped" supaya stream/polling client berhenti
 * dan tidak terus menghabiskan command Redis.
 */
async function reapIfStale(state: ScanState): Promise<void> {
  if (isTerminalStatus(state.status)) return;
  if (Date.now() - state.createdAt <= SCAN_STALE_MS) return;
  await markStopped(state.id, "Scan macet/melewati batas waktu — dihentikan otomatis.");
}

export async function getLogsSince(id: string, fromIndex: number): Promise<ScanLogEvent[]> {
  const local = memScans.get(id);
  if (local && local.logs.length > 0) {
    return local.logs.slice(fromIndex);
  }
  return await getKv().lrangeJSON<ScanLogEvent>(logsKey(id), fromIndex, -1);
}

export async function emit(id: string, event: Omit<ScanLogEvent, "timestamp">): Promise<void> {
  const full: ScanLogEvent = { ...event, timestamp: Date.now() };
  let state = memScans.get(id);
  if (!state) {
    state = await getScan(id);
  }

  // Penjaga zombie: setelah scan terminal (stopped/done/error), tulisan non-terminal dari runner
  // yang masih berjalan diabaikan total supaya tidak membuang command Redis / Turso.
  const isTerminalEvent =
    event.type === "done" || event.type === "error" || event.type === "blocked" || event.type === "stopped";
  if (!isTerminalEvent && ((state && isTerminalStatus(state.status)) || memStop.has(id))) {
    return;
  }

  if (state) {
    if (event.type === "finding" && event.finding) {
      const incomingKey = findingDedupKey(event.finding);
      const alreadyExists = state.findings.some((existing) => findingDedupKey(existing) === incomingKey);
      if (alreadyExists) {
        return;
      }
      state.findings.push(event.finding);
    }
    state.logs.push(full);
    if (state.logs.length > MAX_LOGS_KEPT) {
      state.logs.splice(0, state.logs.length - MAX_LOGS_KEPT);
    }
    if (event.type === "status" && event.status) {
      state.status = event.status;
    }
  }

  // Simpan log penting ke Turso DB; untuk log teks biasa tetap disimpan via rpushJSON yang ringan
  await getKv().rpushJSON(logsKey(id), full, SCAN_TTL_SECONDS, MAX_LOGS_KEPT);

  if (
    event.type === "status" ||
    event.type === "finding" ||
    event.type === "done" ||
    event.type === "error" ||
    event.type === "blocked" ||
    event.type === "stopped"
  ) {
    const force =
      event.type === "done" || event.type === "error" || event.type === "blocked" || event.type === "stopped";
    await persistMetaToDb(id, force);
  }
}

export async function setStatus(id: string, status: ScanStatus): Promise<void> {
  await checkpoint(id);
  await emit(id, { type: "status", status });
}

/**
 * Titik pengecekan hemat: melempar ScanAbortedError bila scan melewati batas waktu atau ada
 * permintaan stop/hapus (dari admin / instance lain lewat key Redis). Cek memori selalu gratis;
 * cek Redis dibatasi 1x per STOP_CHECK_INTERVAL_MS per scan.
 */
export async function checkpoint(id: string): Promise<void> {
  const mem = memStop.get(id);
  if (mem) throw new ScanAbortedError(mem.reason, mem.deleted);

  const state = memScans.get(id);
  if (state && Date.now() - state.createdAt > SCAN_MAX_MS) {
    throw new ScanAbortedError(`Melewati batas waktu scan (${Math.round(SCAN_MAX_MS / 1000)} detik) — dihentikan otomatis.`);
  }

  const now = Date.now();
  if (now - (stopChecked.get(id) ?? 0) < STOP_CHECK_INTERVAL_MS) return;
  stopChecked.set(id, now);
  try {
    const rec = await getKv().getJSON<StopRecord>(stopKey(id));
    if (rec) {
      memStop.set(id, rec);
      throw new ScanAbortedError(rec.reason, rec.deleted);
    }
  } catch (e) {
    if (e instanceof ScanAbortedError) throw e;
    // gagal baca Redis → jangan hentikan scan
  }
}

/** Minta scan berhenti (bisa dipanggil dari instance mana pun). */
export async function requestStop(id: string, reason: string, deleted = false): Promise<void> {
  const rec: StopRecord = { reason, deleted, at: Date.now() };
  memStop.set(id, rec);
  try {
    await getKv().setJSON(stopKey(id), rec, STOP_TTL_SECONDS);
  } catch {
    // tetap berlaku di instance ini
  }
}

/** Tandai scan "stopped" (terminal). Idempotent. */
export async function markStopped(id: string, reason: string): Promise<void> {
  let state = memScans.get(id);
  if (!state) state = await getScan(id);
  if (state && isTerminalStatus(state.status)) return;
  if (state) {
    state.status = "stopped";
    state.stoppedReason = reason;
  }
  await persistMetaToDb(id, true);
  await emit(id, { type: "stopped", message: reason, status: "stopped" });
}

/**
 * Dipanggil runner saat menangkap ScanAbortedError. Bila scan sudah dihapus admin,
 * jangan menulis apa pun ke Redis (supaya data tidak "hidup lagi").
 */
export async function finalizeAborted(id: string, err: ScanAbortedError): Promise<void> {
  if (err.deleted || memStop.get(id)?.deleted) {
    memScans.delete(id);
    lastPersist.delete(id);
    return;
  }
  await markStopped(id, err.message);
}

/** Hapus scan sepenuhnya (admin). Runner yang masih jalan akan berhenti di checkpoint berikutnya. */
export async function deleteScan(id: string): Promise<void> {
  await requestStop(id, "Dihapus oleh admin.", true);
  memScans.delete(id);
  lastPersist.delete(id);
  await getKv().del(metaKey(id), logsKey(id));
  // key stop dibiarkan (TTL 10 menit) sebagai tombstone untuk runner di instance lain
}

/** Hentikan semua scan yang masih berjalan (admin). Mengembalikan jumlah yang dihentikan. */
export async function stopAllRunning(reason = "Dihentikan oleh admin."): Promise<number> {
  const list = await listScans(200);
  let n = 0;
  for (const s of list) {
    if (isTerminalStatus(s.status)) continue;
    await requestStop(s.id, reason);
    await markStopped(s.id, reason);
    n++;
  }
  return n;
}

export async function log(id: string, message: string): Promise<void> {
  await emit(id, { type: "log", message });
}

export async function addFinding(id: string, finding: Finding): Promise<void> {
  await emit(id, { type: "finding", finding: withCwe(finding) });
}

export async function markDone(id: string): Promise<void> {
  const state = memScans.get(id);
  if (state && state.status === "stopped") return;
  if (state) state.status = "done";
  await persistMetaToDb(id, true);
  await emit(id, { type: "done", message: "Scan selesai." });
}

export async function markError(id: string, message: string): Promise<void> {
  const state = memScans.get(id);
  if (state && state.status === "stopped") return;
  if (state) state.status = "error";
  await persistMetaToDb(id, true);
  await emit(id, { type: "error", message });
}

export async function markBlocked(id: string, reason: string): Promise<void> {
  const state = memScans.get(id);
  if (state) {
    state.blockedReason = reason;
    state.status = "blocked_cloudflare";
  }
  await persistMetaToDb(id, true);
  await emit(id, { type: "blocked", message: reason, status: "blocked_cloudflare" });
}

/**
 * HEMAT BANDWIDTH 100x LIPAT:
 * Sebelumnya bumpRequestCount melakukan GET + SET penuh seluruh objek ScanMeta (ratusan KB)
 * di setiap 1 request HTTP (hingga 140x per scan = >25 MB per scan!).
 * Sekarang cukup update counter di RAM dan disinkronkan secara periodik.
 */
export async function bumpRequestCount(id: string, n = 1): Promise<void> {
  const state = memScans.get(id);
  if (state) {
    state.requestsMade += n;
  }
}

export async function setEndpointsDiscovered(id: string, n: number): Promise<void> {
  const state = memScans.get(id);
  if (state) {
    state.endpointsDiscovered = n;
    await persistMetaToDb(id, false);
  }
}

export async function setDiscoveredEndpoints(id: string, endpoints: DiscoveredEndpoint[]): Promise<void> {
  const state = memScans.get(id);
  if (state) {
    state.endpoints = endpoints;
  }
  await emit(id, { type: "endpoints", endpoints });
}

export async function setGraph(id: string, graph: GraphData): Promise<void> {
  const state = memScans.get(id);
  if (state) {
    state.graph = graph;
    await persistMetaToDb(id, false);
  }
}

export async function setPagesCrawled(id: string, n: number): Promise<void> {
  const state = memScans.get(id);
  if (state) {
    state.pagesCrawled = n;
  }
}

export async function setPages(id: string, pages: CrawledPage[]): Promise<void> {
  const state = memScans.get(id);
  if (state) {
    state.pages = pages;
    await persistMetaToDb(id, true);
  }
}

export interface ScanSummary {
  id: string;
  domain: string;
  origin: string;
  createdAt: number;
  status: ScanStatus;
  pagesCount: number;
  findingsCount: number;
  severityCounts: Record<Finding["severity"], number>;
  blockedReason?: string;
}

const EMPTY_SEVERITY_COUNTS: Record<Finding["severity"], number> = {
  CRITICAL: 0,
  HIGH: 0,
  MEDIUM: 0,
  LOW: 0,
  INFO: 0,
};

/** Daftar semua scan (untuk /requests & /history), terbaru dulu. */
export async function listScans(limit = 50): Promise<ScanSummary[]> {
  const seen = new Map<string, ScanMeta>();

  for (const s of memScans.values()) {
    seen.set(s.id, s);
  }

  try {
    const kv = getKv();
    const keys = await kv.keys(META_KEY_PATTERN);
    const found = await Promise.all(keys.slice(0, limit).map((k) => kv.getJSON<ScanMeta>(k)));
    for (const m of found) {
      if (m && m.id && !seen.has(m.id)) {
        seen.set(m.id, m);
      }
    }
  } catch {
    // fallback to memScans
  }

  return Array.from(seen.values())
    .map((m) => {
      const severityCounts = { ...EMPTY_SEVERITY_COUNTS };
      for (const f of m.findings ?? []) severityCounts[f.severity]++;
      const stale = !isTerminalStatus(m.status) && Date.now() - m.createdAt > SCAN_STALE_MS;
      return {
        id: m.id,
        domain: m.domain,
        origin: m.origin,
        createdAt: m.createdAt,
        status: (stale ? "stopped" : m.status) as ScanStatus,
        pagesCount: m.pages?.length ?? 0,
        findingsCount: m.findings?.length ?? 0,
        severityCounts,
        blockedReason: m.blockedReason,
      };
    })
    .sort((a, b) => b.createdAt - a.createdAt)
    .slice(0, limit);
}

export async function bumpJsFilesScanned(id: string, n = 1): Promise<void> {
  const state = memScans.get(id);
  if (state) {
    state.jsFilesScanned += n;
  }
}

export async function setLibrariesDetected(id: string, libs: LibraryDetection[]): Promise<void> {
  const state = memScans.get(id);
  if (state) {
    state.librariesDetected = libs;
    await persistMetaToDb(id, false);
  }
}
