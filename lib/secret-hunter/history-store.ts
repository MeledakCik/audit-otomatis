import type { SecretHuntLogEntry, SecretHuntReport } from "./types";

const STORAGE_KEY = "sentinel-secrets-log";
const MAX_ENTRIES = 50;

export function loadSecretHuntHistory(): SecretHuntLogEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as SecretHuntLogEntry[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveSecretHuntToHistory(report: SecretHuntReport): SecretHuntLogEntry[] {
  const entry: SecretHuntLogEntry = {
    id: report.id,
    createdAt: report.createdAt,
    hostname: report.hostname,
    riskLevel: report.riskLevel,
    findingsCount: report.findings.length,
    report,
  };

  const current = loadSecretHuntHistory();
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

export function clearSecretHuntHistory(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(STORAGE_KEY);
}
