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

const metaKey = (id: string) => `trout:scan:${id}:meta`;
const logsKey = (id: string) => `trout:scan:${id}:logs`;
const META_KEY_PATTERN = "trout:scan:*:meta";

type ScanMeta = Omit<ScanState, "logs">;

// --- L1 In-Memory Store (Super Cepat + 0 Bandwidth untuk SSE Stream & RequestCount) ---
const globalForScanStore = globalThis as unknown as {
  __troutScansMem?: Map<string, ScanState>;
  __troutScansLastPersist?: Map<string, number>;
};
const memScans = globalForScanStore.__troutScansMem ?? new Map<string, ScanState>();
const lastPersist = globalForScanStore.__troutScansLastPersist ?? new Map<string, number>();
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
    return local;
  }
  const meta = await getKv().getJSON<ScanMeta>(metaKey(id));
  if (!meta) return undefined;
  const logs = await getLogsSince(id, 0);
  const full: ScanState = { ...meta, logs };
  memScans.set(id, full);
  return full;
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
    event.type === "blocked"
  ) {
    const force = event.type === "done" || event.type === "error" || event.type === "blocked";
    await persistMetaToDb(id, force);
  }
}

export async function setStatus(id: string, status: ScanStatus): Promise<void> {
  await emit(id, { type: "status", status });
}

export async function log(id: string, message: string): Promise<void> {
  await emit(id, { type: "log", message });
}

export async function addFinding(id: string, finding: Finding): Promise<void> {
  await emit(id, { type: "finding", finding: withCwe(finding) });
}

export async function markDone(id: string): Promise<void> {
  const state = memScans.get(id);
  if (state) state.status = "done";
  await persistMetaToDb(id, true);
  await emit(id, { type: "done", message: "Scan selesai." });
}

export async function markError(id: string, message: string): Promise<void> {
  const state = memScans.get(id);
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
      return {
        id: m.id,
        domain: m.domain,
        origin: m.origin,
        createdAt: m.createdAt,
        status: m.status,
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
