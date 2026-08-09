import type { SubdomainWatchLogEntry, SubdomainWatchReport } from "./types";

const STORAGE_KEY = "sentinel-subdomain-log";
const MAX_ENTRIES = 30;
const RATE_LIMIT_KEY = "sentinel-subdomain-last-scan-at";
const RATE_LIMIT_MS = 10_000;

export function loadSubdomainWatchHistory(): SubdomainWatchLogEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as SubdomainWatchLogEntry[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveSubdomainWatchToHistory(report: SubdomainWatchReport): SubdomainWatchLogEntry[] {
  const entry: SubdomainWatchLogEntry = {
    id: report.id,
    createdAt: report.createdAt,
    domain: report.domain,
    totalFound: report.totalFound,
    highCount: report.rows.filter((r) => r.risk === "HIGH").length,
    report,
  };

  const current = loadSubdomainWatchHistory();
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

export function clearSubdomainWatchHistory() {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
}

/** Rate limit ramah crt.sh: maksimal 1 scan domain baru per 10 detik. */
export function getScanCooldownMsRemaining(): number {
  if (typeof window === "undefined") return 0;
  try {
    const last = Number(window.localStorage.getItem(RATE_LIMIT_KEY) ?? 0);
    const remaining = RATE_LIMIT_MS - (Date.now() - last);
    return remaining > 0 ? remaining : 0;
  } catch {
    return 0;
  }
}

export function markScanStarted() {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(RATE_LIMIT_KEY, String(Date.now()));
  } catch {
    // ignore
  }
}
