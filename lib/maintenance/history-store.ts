import type { MaintenanceLogEntry, SecurityReport } from "./types";

const STORAGE_KEY = "sentinel_maintenance_logs";
const MAX_ENTRIES = 50;

export function loadHistory(): MaintenanceLogEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as MaintenanceLogEntry[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveToHistory(report: SecurityReport): MaintenanceLogEntry[] {
  const entry: MaintenanceLogEntry = {
    id: report.id,
    createdAt: report.createdAt,
    sourceName: report.sourceName,
    overallSeverity: report.overallSeverity,
    summary: report.summary,
    report,
  };

  const current = loadHistory();
  const next = [entry, ...current].slice(0, MAX_ENTRIES);

  if (typeof window !== "undefined") {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      // localStorage penuh / diblokir — history tetap dipakai in-memory untuk sesi ini.
    }
  }
  return next;
}

export function updateEntryReport(reportId: string, updater: (report: SecurityReport) => SecurityReport): MaintenanceLogEntry[] {
  const current = loadHistory();
  const next = current.map((entry) => {
    if (entry.id !== reportId) return entry;
    const updatedReport = updater(entry.report);
    return {
      ...entry,
      report: updatedReport,
      overallSeverity: updatedReport.overallSeverity,
      summary: updatedReport.summary,
    };
  });

  if (typeof window !== "undefined") {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      // ignore
    }
  }
  return next;
}

export function clearHistory(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(STORAGE_KEY);
}
