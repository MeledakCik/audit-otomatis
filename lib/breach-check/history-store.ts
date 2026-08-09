import type { BreachLogEntry, ScanMode } from "./types";

const STORAGE_KEY = "sentinel-breach-log";
const MAX_ENTRIES = 50;

export function loadBreachLog(): BreachLogEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as BreachLogEntry[]) : [];
  } catch {
    return [];
  }
}

export function saveBreachLogEntry(entry: {
  mode: ScanMode;
  query: string;
  clean: boolean;
  breachCount: number;
}): BreachLogEntry[] {
  const now = Date.now();
  const label = entry.clean
    ? `${entry.query} — CLEAN`
    : `${entry.query} — ${entry.breachCount} breach${entry.breachCount === 1 ? "" : "es"}`;

  const record: BreachLogEntry = {
    id: `${now.toString(36)}-${Math.random().toString(36).slice(2, 8)}`,
    createdAt: now,
    mode: entry.mode,
    query: entry.query,
    clean: entry.clean,
    breachCount: entry.breachCount,
    label,
  };

  const current = loadBreachLog();
  const next = [record, ...current].slice(0, MAX_ENTRIES);

  if (typeof window !== "undefined") {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      // storage full/blocked — history just stays in-memory for this session
    }
  }

  return next;
}

export function clearBreachLog(): void {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
}
