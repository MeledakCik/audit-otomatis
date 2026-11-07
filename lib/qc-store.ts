import type {
  QcContentResult,
  QcLogEvent,
  QcModulesSelection,
  QcModuleKey,
  QcPerfResult,
  QcResult,
  QcSeoResult,
  QcState,
  QcStatus,
} from "./qc-types";
import { getKv, REDIS_CONFIGURED } from "./redis";

const MAX_LOGS_KEPT = 300;
const QC_TTL_SECONDS = 30 * 60; // sama seperti scan: auto-bersih 30 menit

/** QC non-terminal lebih tua dari ini dianggap macet dan di-reap jadi "error". */
const QC_STALE_MS = 6 * 60_000;
const QC_TERMINAL = new Set<QcStatus>(["done", "error"]);
const deletedQc = new Set<string>(); // tombstone in-memory: runner yang masih jalan berhenti menulis

export class QcAbortedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "QcAbortedError";
  }
}

/** Dipakai sebagai guard RequestBudget di runner QC. */
export async function qcCheckpoint(id: string): Promise<void> {
  if (deletedQc.has(id)) throw new QcAbortedError("QC dihapus oleh admin.");
}

const metaKey = (id: string) => `trout:qc:${id}:meta`;
const logsKey = (id: string) => `trout:qc:${id}:logs`;
// Setiap modul QC (seo/perf/content) punya key hasil sendiri-sendiri —
// SENGAJA dipisah dari meta, karena 3 modul dijalankan PARALEL
// (Promise.all di lib/qc-runner.ts). Kalau hasilnya ditulis ke satu field
// gabungan di meta lewat pola get->mutate->set (updateMeta), tulisan yang
// selesai lebih dulu bisa hilang tertimpa tulisan modul lain yang baca
// meta versi lama sebelum tulisan pertama ke-persist (lost update / race
// condition) — ini kejadian nyata di Redis (Upstash REST, ada latensi
// network antar get/set), meski di fallback in-memory nyaris tak terlihat
// karena mutasi objek JS instan tanpa round-trip.
const resultKey = (id: string, module: QcModuleKey) => `trout:qc:${id}:result:${module}`;

type QcMeta = Omit<QcState, "logs" | "result"> & { result: Omit<QcResult, QcModuleKey> };

// --- Fallback in-memory (HANYA dev lokal tanpa Redis) ---
const globalForQcStore = globalThis as unknown as {
  __troutQcMem?: Map<string, QcState>;
};
const memQc = globalForQcStore.__troutQcMem ?? new Map<string, QcState>();
globalForQcStore.__troutQcMem = memQc;

function scheduleMemCleanup(id: string) {
  setTimeout(() => {
    memQc.delete(id);
  }, QC_TTL_SECONDS * 1000).unref?.();
}

function freshState(id: string, domain: string, origin: string, modules: QcModulesSelection): QcState {
  return {
    id,
    domain,
    origin,
    modules,
    status: "queued",
    createdAt: Date.now(),
    logs: [],
    result: {},
    requestsMade: 0,
  };
}

export async function createQc(
  id: string,
  domain: string,
  origin: string,
  modules: QcModulesSelection
): Promise<QcState> {
  const state = freshState(id, domain, origin, modules);

  if (REDIS_CONFIGURED) {
    const { logs: _logs, ...meta } = state;
    await getKv().setJSON(metaKey(id), meta, QC_TTL_SECONDS);
  } else {
    memQc.set(id, state);
    scheduleMemCleanup(id);
  }

  return state;
}

export async function getQc(id: string): Promise<QcState | undefined> {
  if (deletedQc.has(id)) return undefined;
  if (REDIS_CONFIGURED) {
    const kv = getKv();
    const meta = await kv.getJSON<QcMeta>(metaKey(id));
    if (!meta) return undefined;

    if (!QC_TERMINAL.has(meta.status) && Date.now() - meta.createdAt > QC_STALE_MS) {
      await markQcError(id, "QC macet/melewati batas waktu — dihentikan otomatis.");
      meta.status = "error";
      meta.error = "QC macet/melewati batas waktu — dihentikan otomatis.";
    }

    const [logs, seo, perf, content] = await Promise.all([
      getQcLogsSince(id, 0),
      kv.getJSON<QcSeoResult>(resultKey(id, "seo")),
      kv.getJSON<QcPerfResult>(resultKey(id, "perf")),
      kv.getJSON<QcContentResult>(resultKey(id, "content")),
    ]);

    const result: QcResult = {
      ...meta.result,
      ...(seo ? { seo } : {}),
      ...(perf ? { perf } : {}),
      ...(content ? { content } : {}),
    };

    return { ...meta, logs, result };
  }
  return memQc.get(id);
}

export async function getQcLogsSince(id: string, fromIndex: number): Promise<QcLogEvent[]> {
  if (REDIS_CONFIGURED) {
    return await getKv().lrangeJSON<QcLogEvent>(logsKey(id), fromIndex, -1);
  }
  const state = memQc.get(id);
  if (!state) return [];
  return state.logs.slice(fromIndex);
}

async function updateMeta(id: string, mutate: (state: QcMeta) => void): Promise<void> {
  if (deletedQc.has(id)) return;
  if (REDIS_CONFIGURED) {
    const kv = getKv();
    const meta = await kv.getJSON<QcMeta>(metaKey(id));
    if (!meta) return;
    mutate(meta);
    await kv.setJSON(metaKey(id), meta, QC_TTL_SECONDS);
  } else {
    const state = memQc.get(id);
    if (!state) return;
    mutate(state as unknown as QcMeta);
  }
}

export async function emitQc(id: string, event: Omit<QcLogEvent, "timestamp">): Promise<void> {
  if (deletedQc.has(id)) return;
  const full: QcLogEvent = { ...event, timestamp: Date.now() };

  if (REDIS_CONFIGURED) {
    await getKv().rpushJSON(logsKey(id), full, QC_TTL_SECONDS, MAX_LOGS_KEPT);
  } else {
    const state = memQc.get(id);
    if (!state) return;
    state.logs.push(full);
    if (state.logs.length > MAX_LOGS_KEPT) {
      state.logs.splice(0, state.logs.length - MAX_LOGS_KEPT);
    }
  }

  if (event.type === "status" && event.status) {
    await updateMeta(id, (s) => {
      if (s.status === "error") return; // sudah dihentikan/gagal: jangan dihidupkan lagi
      s.status = event.status!;
    });
  }
}

export async function setQcStatus(id: string, status: QcStatus): Promise<void> {
  await emitQc(id, { type: "status", status });
}

export async function logQc(id: string, message: string): Promise<void> {
  await emitQc(id, { type: "log", message });
}

/**
 * Simpan hasil satu modul QC ke key Redis-nya sendiri (BUKAN read-modify-write
 * ke meta gabungan) — aman dipanggil bersamaan (concurrent) dari 3 modul
 * QC yang jalan paralel tanpa saling menimpa. Lihat komentar `resultKey`.
 */
export async function setModuleResult<K extends QcModuleKey>(
  id: string,
  module: K,
  result: NonNullable<QcResult[K]>
): Promise<void> {
  if (REDIS_CONFIGURED) {
    await getKv().setJSON(resultKey(id, module), result, QC_TTL_SECONDS);
  } else {
    const state = memQc.get(id);
    if (state) state.result = { ...state.result, [module]: result };
  }
  await emitQc(id, { type: "module_done", module });
}

export async function setOverallScore(id: string, overallScore: number): Promise<void> {
  // Dipanggil sekali saja, setelah Promise.all semua modul selesai (lihat
  // lib/qc-runner.ts) — tidak concurrent, jadi read-modify-write di sini
  // aman dan tidak butuh key terpisah seperti setModuleResult.
  await updateMeta(id, (s) => {
    s.result = { ...s.result, overallScore };
  });
}

export async function bumpQcRequestCount(id: string, n = 1): Promise<void> {
  await updateMeta(id, (s) => {
    s.requestsMade += n;
  });
}

export async function markQcDone(id: string): Promise<void> {
  await emitQc(id, { type: "done", message: "QC selesai." });
}

export async function markQcError(id: string, message: string): Promise<void> {
  await updateMeta(id, (s) => {
    s.error = message;
    s.status = "error";
  });
  await emitQc(id, { type: "error", message });
}

export interface QcSummary {
  id: string;
  domain: string;
  origin: string;
  createdAt: number;
  status: QcStatus;
  overallScore?: number;
  modules: QcModulesSelection;
  requestsMade: number;
}

export async function listQcs(limit = 50): Promise<QcSummary[]> {
  let metas: QcMeta[] = [];
  if (REDIS_CONFIGURED) {
    try {
      const kv = getKv();
      const keys = await kv.keys("trout:qc:*:meta");
      const found = await Promise.all(keys.map((k) => kv.getJSON<QcMeta>(k)));
      metas = found.filter((m): m is QcMeta => m !== null);
    } catch {
      metas = [];
    }
  } else {
    metas = Array.from(memQc.values()) as unknown as QcMeta[];
  }

  return metas
    .map((m) => ({
      id: m.id,
      domain: m.domain,
      origin: m.origin,
      createdAt: m.createdAt,
      status: (!QC_TERMINAL.has(m.status) && Date.now() - m.createdAt > QC_STALE_MS ? "error" : m.status) as QcStatus,
      overallScore: m.result?.overallScore,
      modules: m.modules,
      requestsMade: m.requestsMade ?? 0,
    }))
    .sort((a, b) => b.createdAt - a.createdAt)
    .slice(0, limit);
}


/** Hentikan QC (admin): tandai terminal "error" supaya stream/polling berhenti. */
export async function stopQc(id: string, reason = "Dihentikan oleh admin."): Promise<void> {
  const meta = await getKv().getJSON<QcMeta>(metaKey(id));
  if (!meta || QC_TERMINAL.has(meta.status)) return;
  await markQcError(id, reason);
  await updateMeta(id, (s) => {
    s.status = "error";
  });
}

/** Hapus QC sepenuhnya (admin). */
export async function deleteQc(id: string): Promise<void> {
  deletedQc.add(id);
  memQc.delete(id);
  setTimeout(() => deletedQc.delete(id), 10 * 60_000).unref?.();
  await getKv().del(
    metaKey(id),
    logsKey(id),
    resultKey(id, "seo"),
    resultKey(id, "perf"),
    resultKey(id, "content")
  );
}

/** Hentikan semua QC yang masih berjalan. */
export async function stopAllRunningQcs(reason = "Dihentikan oleh admin."): Promise<number> {
  const list = await listQcs(200);
  let n = 0;
  for (const q of list) {
    if (QC_TERMINAL.has(q.status)) continue;
    await stopQc(q.id, reason);
    n++;
  }
  return n;
}
