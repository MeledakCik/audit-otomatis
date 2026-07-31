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
import { getKv, REDIS_CONFIGURED } from "./redis";

const MAX_LOGS_KEPT = 500;
const SCAN_TTL_SECONDS = 30 * 60; // auto-bersih 30 menit setelah dibuat, sama seperti sebelumnya

const metaKey = (id: string) => `trout:scan:${id}:meta`;
const logsKey = (id: string) => `trout:scan:${id}:logs`;
const META_KEY_PATTERN = "trout:scan:*:meta";

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
    pages: [],
  };
}

export async function createScan(id: string, domain: string, origin: string): Promise<ScanState> {
  const state = freshState(id, domain, origin);

  if (REDIS_CONFIGURED) {
    const { logs: _logs, ...meta } = state;
    await getKv().setJSON(metaKey(id), meta, SCAN_TTL_SECONDS);
  } else {
    memScans.set(id, state);
    scheduleMemCleanup(id);
  }

  return state;
}

export async function getScan(id: string): Promise<ScanState | undefined> {
  if (REDIS_CONFIGURED) {
    const meta = await getKv().getJSON<ScanMeta>(metaKey(id));
    if (!meta) return undefined;
    const logs = await getLogsSince(id, 0);
    return { ...meta, logs };
  }
  return memScans.get(id);
}
export async function getLogsSince(id: string, fromIndex: number): Promise<ScanLogEvent[]> {
  if (REDIS_CONFIGURED) {
    return await getKv().lrangeJSON<ScanLogEvent>(logsKey(id), fromIndex, -1);
  }
  const state = memScans.get(id);
  if (!state) return [];
  return state.logs.slice(fromIndex);
}

async function updateMeta(id: string, mutate: (state: ScanMeta) => void): Promise<void> {
  if (REDIS_CONFIGURED) {
    const kv = getKv();
    const meta = await kv.getJSON<ScanMeta>(metaKey(id));
    if (!meta) return;
    mutate(meta);
    await kv.setJSON(metaKey(id), meta, SCAN_TTL_SECONDS);
  } else {
    const state = memScans.get(id);
    if (!state) return;
    mutate(state);
  }
}

export async function emit(id: string, event: Omit<ScanLogEvent, "timestamp">): Promise<void> {
  const full: ScanLogEvent = { ...event, timestamp: Date.now() };

  if (REDIS_CONFIGURED) {
    await getKv().rpushJSON(logsKey(id), full, SCAN_TTL_SECONDS, MAX_LOGS_KEPT);
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
export async function setDiscoveredEndpoints(id: string, endpoints: DiscoveredEndpoint[]): Promise<void> {
  await updateMeta(id, (s) => {
    s.endpoints = endpoints;
  });
  await emit(id, { type: "endpoints", endpoints });
}
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

export async function setPages(id: string, pages: CrawledPage[]): Promise<void> {
  await updateMeta(id, (s) => {
    s.pages = pages;
  });
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
  let metas: ScanMeta[];

  if (REDIS_CONFIGURED) {
    const kv = getKv();
    const keys = await kv.keys(META_KEY_PATTERN);
    const found = await Promise.all(keys.map((k) => kv.getJSON<ScanMeta>(k)));
    metas = found.filter((m): m is ScanMeta => m !== null);
  } else {
    metas = Array.from(memScans.values());
  }

  return metas
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
  await updateMeta(id, (s) => {
    s.jsFilesScanned += n;
  });
}

export async function setLibrariesDetected(id: string, libs: LibraryDetection[]): Promise<void> {
  await updateMeta(id, (s) => {
    s.librariesDetected = libs;
  });
}
