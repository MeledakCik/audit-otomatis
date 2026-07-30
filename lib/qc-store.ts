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
  if (REDIS_CONFIGURED) {
    const kv = getKv();
    const meta = await kv.getJSON<QcMeta>(metaKey(id));
    if (!meta) return undefined;

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
  });
  await emitQc(id, { type: "error", message });
}
