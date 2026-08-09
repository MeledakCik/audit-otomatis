import type { AttackMapLogEntry, AttackMapReport } from "./types";

const STORAGE_KEY = "sentinel-map-log";
const MAX_ENTRIES = 30;

export function loadAttackMapHistory(): AttackMapLogEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as AttackMapLogEntry[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveAttackMapToHistory(report: AttackMapReport): AttackMapLogEntry[] {
  const entry: AttackMapLogEntry = {
    id: report.id,
    createdAt: report.createdAt,
    hostname: report.hostname,
    totalNodes: report.stats.totalNodes,
    apiCount: report.stats.apiCount,
    report,
  };

  const current = loadAttackMapHistory();
  const next = [entry, ...current].slice(0, MAX_ENTRIES);

  if (typeof window !== "undefined") {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      // localStorage penuh/diblokir — history tetap ada in-memory untuk sesi ini.
    }
  }
  return next;
}

export function clearAttackMapHistory(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(STORAGE_KEY);
}
