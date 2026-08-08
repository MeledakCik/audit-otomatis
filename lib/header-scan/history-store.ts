import type { HeaderScanLogEntry, HeaderScanReport } from "./types";

const STORAGE_KEY = "sentinel_maintenance_logs";
const MAX_ENTRIES = 50;

// Timeline entry format shared with the general maintenance log, so a header
// scan shows up alongside other maintenance events:
// "Header Scan [date] - Grade B (75/100)"
interface MaintenanceTimelineEntry {
  id: string;
  createdAt: number;
  sourceName: string;
  kind: "header-scan";
  label: string;
  report: HeaderScanReport;
}

export function loadHeaderScanHistory(): HeaderScanLogEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as MaintenanceTimelineEntry[];
    if (!Array.isArray(parsed)) return [];
    return parsed
      .filter((e) => e.kind === "header-scan" && e.report)
      .map((e) => ({
        id: e.id,
        createdAt: e.createdAt,
        hostname: e.report.hostname,
        grade: e.report.grade,
        score: e.report.score,
        report: e.report,
      }));
  } catch {
    return [];
  }
}

export function saveHeaderScanToHistory(report: HeaderScanReport): HeaderScanLogEntry[] {
  const label = `Header Scan ${new Date(report.createdAt).toLocaleDateString("id-ID")} - Grade ${report.grade} (${report.score}/100)`;

  const entry: MaintenanceTimelineEntry = {
    id: report.id,
    createdAt: report.createdAt,
    sourceName: report.hostname,
    kind: "header-scan",
    label,
    report,
  };

  const current = readRawTimeline();
  const next = [entry, ...current].slice(0, MAX_ENTRIES);

  if (typeof window !== "undefined") {
    try {
      window.localStorage.setItem(STORAGE_KEY, JSON.stringify(next));
    } catch {
      // localStorage penuh/diblokir — history tetap ada in-memory untuk sesi ini.
    }
  }

  return loadHeaderScanHistory();
}

export function clearHeaderScanHistory(): void {
  if (typeof window === "undefined") return;
  try {
    const current = readRawTimeline();
    const kept = current.filter((e) => e.kind !== "header-scan");
    window.localStorage.setItem(STORAGE_KEY, JSON.stringify(kept));
  } catch {
    // ignore
  }
}

function readRawTimeline(): MaintenanceTimelineEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}
