import type { StackFingerprintLogEntry, StackFingerprintReport } from "./types";

const STORAGE_KEY = "sentinel-stack-log";
const MAX_ENTRIES = 30;

export function loadStackFingerprintHistory(): StackFingerprintLogEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as StackFingerprintLogEntry[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveStackFingerprintToHistory(report: StackFingerprintReport): StackFingerprintLogEntry[] {
  const entry: StackFingerprintLogEntry = {
    id: report.id,
    createdAt: report.createdAt,
    domain: report.domain,
    stackCount: report.stacks.length,
    report,
  };

  const current = loadStackFingerprintHistory();
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

export function clearStackFingerprintHistory() {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
}
