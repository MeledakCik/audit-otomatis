"use client";

import { useEffect, useState } from "react";
import { Radar, Lock } from "lucide-react";
import { InputPanel } from "./input-panel";
import { RecordsTable } from "./records-table";
import { EmailSecurityCard } from "./email-security-card";
import { AttackSurfaceAlert } from "./attack-surface-alert";
import { ExportBar } from "./export-bar";
import { HistoryPanel } from "./history-panel";
import { loadDnsIntelHistory, saveDnsIntelToHistory, clearDnsIntelHistory } from "@/lib/dns-intel/history-store";
import type { DnsIntelLogEntry, DnsIntelReport } from "@/lib/dns-intel/types";

export function DnsIntelView() {
  const [report, setReport] = useState<DnsIntelReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<DnsIntelLogEntry[]>([]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setHistory(loadDnsIntelHistory());
  }, []);

  async function handleScan(domain: string) {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch(`/api/dns-intel?domain=${encodeURIComponent(domain)}`, { cache: "no-store" });
      const data = await res.json();
      if (!data.ok) {
        setError(data.error || "Gagal melakukan DNS lookup.");
        return;
      }
      const nextReport = data.report as DnsIntelReport;
      setReport(nextReport);
      setHistory(saveDnsIntelToHistory(nextReport));
    } catch {
      setError("Tidak bisa menghubungi server. Coba lagi.");
    } finally {
      setLoading(false);
    }
  }

  function handleSelectHistory(entry: DnsIntelLogEntry) {
    setReport(entry.report);
    setError(null);
  }

  function handleClearHistory() {
    clearDnsIntelHistory();
    setHistory([]);
  }

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 max-w-[1600px] mx-auto">
      <div className="flex items-start gap-3">
        <div className="h-10 w-10 grid place-items-center rounded-xl bg-gradient-to-br from-[#22d3ee] to-[#0891b2] shadow-lg shadow-cyan-500/20 shrink-0">
          <Radar className="h-5 w-5 text-black" strokeWidth={2.5} />
        </div>
        <div>
          <h1 className="text-lg font-extrabold tracking-tight text-foreground flex items-center gap-2">
            DNS Intel &amp; Surface Scanner
            <Lock className="h-4 w-4 text-accent" />
          </h1>
          <p className="text-xs font-mono text-muted-dim">
            Passive DNS reconnaissance — email security posture &amp; subdomain takeover hints, GET-only, no AXFR.
          </p>
        </div>
      </div>

      <InputPanel onScan={handleScan} loading={loading} />

      {error && (
        <div className="rounded-lg border border-sev-critical/40 bg-sev-critical/10 px-4 py-2.5 text-xs font-mono text-sev-critical">
          {error}
        </div>
      )}

      {report && (
        <>
          <ExportBar report={report} />

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 items-start">
            <RecordsTable rows={report.recordRows} queryErrors={report.queryErrors} />
            <EmailSecurityCard security={report.security} />
            <AttackSurfaceAlert hints={report.security.takeoverHints} />
          </div>
        </>
      )}

      <HistoryPanel entries={history} activeId={report?.id} onSelect={handleSelectHistory} onClear={handleClearHistory} />
    </div>
  );
}
