"use client";

import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Radar, Lock } from "lucide-react";
import { InputPanel } from "./input-panel";
import { ResultsTable } from "./results-table";
import { MiniGraph } from "./mini-graph";
import { HistoryPanel } from "./history-panel";
import {
  loadSubdomainWatchHistory,
  saveSubdomainWatchToHistory,
  clearSubdomainWatchHistory,
  getScanCooldownMsRemaining,
  markScanStarted,
} from "@/lib/subdomain-watch/history-store";
import type { SubdomainRow, SubdomainWatchLogEntry, SubdomainWatchReport } from "@/lib/subdomain-watch/types";

const INITIAL_BATCH = 20;
const BATCH_SIZE = 20;
const CONCURRENCY = 5;

function cryptoRandomId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

async function checkOne(subdomain: string, rootDomain: string): Promise<SubdomainRow> {
  try {
    const res = await fetch("/api/scan-subdomain/check", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ subdomain, rootDomain }),
    });
    const data = await res.json();
    if (!data.ok) {
      return {
        subdomain,
        status: "error",
        cname: null,
        httpStatus: null,
        risk: "UNKNOWN",
        service: null,
        reason: null,
        fix: null,
        errorMessage: data.error ?? "Gagal cek subdomain.",
      };
    }
    return data.row as SubdomainRow;
  } catch {
    return {
      subdomain,
      status: "error",
      cname: null,
      httpStatus: null,
      risk: "UNKNOWN",
      service: null,
      reason: null,
      fix: null,
      errorMessage: "Gagal menghubungi server.",
    };
  }
}

export function SubdomainWatchView() {
  const searchParams = useSearchParams();
  const initialDomain = searchParams.get("domain") ?? undefined;

  const [report, setReport] = useState<SubdomainWatchReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [checkingMore, setCheckingMore] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [liveStatus, setLiveStatus] = useState<string | null>(null);
  const [history, setHistory] = useState<SubdomainWatchLogEntry[]>([]);
  const [cooldownMs, setCooldownMs] = useState(0);
  const reportRef = useRef<SubdomainWatchReport | null>(null);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setHistory(loadSubdomainWatchHistory());
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setCooldownMs(getScanCooldownMsRemaining());
  }, []);

  function syncReport(next: SubdomainWatchReport) {
    reportRef.current = next;
    setReport({ ...next, rows: [...next.rows] });
  }

  async function runBatch(subdomains: string[], rootDomain: string) {
    if (subdomains.length === 0) return;
    let cursor = 0;
    async function worker() {
      while (cursor < subdomains.length) {
        const subdomain = subdomains[cursor++];
        const current = reportRef.current;
        if (!current) return;
        const idx = current.rows.findIndex((r) => r.subdomain === subdomain);
        if (idx >= 0) {
          current.rows[idx] = { ...current.rows[idx], status: "checking" };
          syncReport(current);
        }
        const result = await checkOne(subdomain, rootDomain);
        const latest = reportRef.current;
        if (!latest) return;
        const latestIdx = latest.rows.findIndex((r) => r.subdomain === subdomain);
        if (latestIdx >= 0) {
          latest.rows[latestIdx] = result;
          syncReport(latest);
        }
      }
    }
    const workers = Array.from({ length: Math.min(CONCURRENCY, subdomains.length) }, () => worker());
    await Promise.all(workers);

    const finalReport = reportRef.current;
    if (finalReport) {
      setHistory(saveSubdomainWatchToHistory(finalReport));
    }
  }

  async function handleScan(domainInput: string) {
    const remaining = getScanCooldownMsRemaining();
    if (remaining > 0) {
      setCooldownMs(remaining);
      return;
    }

    setLoading(true);
    setError(null);
    setLiveStatus(`Mengambil sertifikat untuk ${domainInput} dari crt.sh...`);
    markScanStarted();
    setCooldownMs(10_000);

    try {
      const res = await fetch("/api/scan-subdomain", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: domainInput }),
      });
      const data = await res.json();
      if (!data.ok) {
        setError(data.error || "Gagal melakukan scan.");
        setLiveStatus(null);
        setLoading(false);
        return;
      }

      const subdomains: string[] = data.subdomains;
      const rows: SubdomainRow[] = subdomains.map((s) => ({
        subdomain: s,
        status: "pending",
        cname: null,
        httpStatus: null,
        risk: "UNKNOWN",
        service: null,
        reason: null,
        fix: null,
      }));

      const nextReport: SubdomainWatchReport = {
        id: cryptoRandomId(),
        createdAt: Date.now(),
        domain: data.domain,
        totalFound: data.totalFound,
        truncated: data.truncated,
        rows,
      };
      syncReport(nextReport);
      setLiveStatus(`Ditemukan ${data.totalFound} subdomain — mengecek ${Math.min(INITIAL_BATCH, rows.length)} teratas...`);
      setLoading(false);

      await runBatch(subdomains.slice(0, INITIAL_BATCH), data.domain);
      setLiveStatus(null);
    } catch {
      setError("Tidak bisa menghubungi server. Coba lagi.");
      setLiveStatus(null);
      setLoading(false);
    }
  }

  async function handleCheckMore() {
    const current = reportRef.current;
    if (!current) return;
    const pending = current.rows.filter((r) => r.status === "pending").map((r) => r.subdomain);
    if (pending.length === 0) return;
    setCheckingMore(true);
    await runBatch(pending.slice(0, BATCH_SIZE), current.domain);
    setCheckingMore(false);
  }

  function handleSelectHistory(entry: SubdomainWatchLogEntry) {
    reportRef.current = entry.report;
    setReport(entry.report);
    setError(null);
    setLiveStatus(null);
  }

  function handleClearHistory() {
    clearSubdomainWatchHistory();
    setHistory([]);
  }

  const checkedCount = report ? report.rows.filter((r) => r.status === "checked" || r.status === "error").length : 0;
  const hasMoreToCheck = report ? checkedCount < report.rows.length : false;

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 max-w-[1600px] mx-auto">
      <div className="flex items-start gap-3">
        <div className="h-10 w-10 grid place-items-center rounded-xl bg-gradient-to-br from-[#c084fc] to-[#9333ea] text-black shadow-lg shadow-purple-500/20 shrink-0">
          <Radar className="h-5 w-5 text-white" strokeWidth={2.5} />
        </div>
        <div>
          <h1 className="text-lg font-extrabold tracking-tight text-foreground flex items-center gap-2">
            Subdomain Takeover Watch
            <Lock className="h-4 w-4 text-accent" />
          </h1>
          <p className="text-xs font-mono text-muted-dim">
            Passive CT log only, no DNS bruteforce — subdomain discovery via crt.sh + heuristic takeover check.
          </p>
        </div>
      </div>

      {error && (
        <div className="rounded-lg border border-sev-critical/40 bg-sev-critical/10 px-4 py-2.5 text-xs font-mono text-sev-critical">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 items-start">
        <div className="space-y-4 xl:sticky xl:top-6">
          <InputPanel onScan={handleScan} loading={loading} liveStatus={liveStatus} cooldownMs={cooldownMs} initialDomain={initialDomain} />
          <HistoryPanel entries={history} activeId={report?.id} onSelect={handleSelectHistory} onClear={handleClearHistory} />
        </div>
        <div className="space-y-6">
          <ResultsTable
            report={report}
            checkedCount={checkedCount}
            onCheckMore={handleCheckMore}
            checkingMore={checkingMore}
            hasMoreToCheck={hasMoreToCheck}
          />
          {report && <MiniGraph domain={report.domain} rows={report.rows} />}
        </div>
      </div>
    </div>
  );
}
