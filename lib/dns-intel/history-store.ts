import type { DnsIntelLogEntry, DnsIntelReport } from "./types";

const STORAGE_KEY = "sentinel-dns-intel-log";
const MAX_ENTRIES = 40;

function riskCountOf(report: DnsIntelReport): number {
  let n = 0;
  if (report.security.spf.risk === "HIGH") n++;
  if (report.security.dmarc.risk !== "LOW") n++;
  n += report.security.takeoverHints.length;
  return n;
}

export function loadDnsIntelHistory(): DnsIntelLogEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) return [];
    const parsed = JSON.parse(raw) as DnsIntelLogEntry[];
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function saveDnsIntelToHistory(report: DnsIntelReport): DnsIntelLogEntry[] {
  const entry: DnsIntelLogEntry = {
    id: report.id,
    createdAt: report.createdAt,
    domain: report.domain,
    riskCount: riskCountOf(report),
    report,
  };

  const current = loadDnsIntelHistory();
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

export function clearDnsIntelHistory(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(STORAGE_KEY);
}
