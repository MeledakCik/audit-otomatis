"use client";

import { useEffect, useState } from "react";
import { Wrench, ShieldCheck } from "lucide-react";
import { InputPanel } from "./input-panel";
import { OutputPanel } from "./output-panel";
import { HistoryPanel } from "./history-panel";
import { loadHistory, saveToHistory, updateEntryReport, clearHistory } from "@/lib/maintenance/history-store";
import type { MaintenanceLogEntry, SecurityReport } from "@/lib/maintenance/types";

export function MaintenanceLogView() {
  const [report, setReport] = useState<SecurityReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [history, setHistory] = useState<MaintenanceLogEntry[]>([]);

  useEffect(() => {
    // Sync from localStorage (external system) once on mount — client-only,
    // so this intentionally can't be a lazy useState initializer (would
    // mismatch the server-rendered HTML).
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setHistory(loadHistory());
  }, []);

  async function handleAnalyze(input: string, filename?: string) {
    setLoading(true);
    setError(null);
    try {
      const res = await fetch("/api/maintenance-log/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ input, filename }),
      });
      const data = await res.json();
      if (!data.ok) {
        setError(data.error || "Gagal menganalisis input.");
        return;
      }
      const nextReport = data.report as SecurityReport;
      setReport(nextReport);
      setHistory(saveToHistory(nextReport));
    } catch {
      setError("Tidak bisa menghubungi server analisis. Coba lagi.");
    } finally {
      setLoading(false);
    }
  }

  function handleToggleStep(findingId: string, stepIndex: number) {
    if (!report) return;
    const nextReport: SecurityReport = {
      ...report,
      findings: report.findings.map((f) =>
        f.id !== findingId
          ? f
          : {
              ...f,
              remediationSteps: f.remediationSteps.map((s, i) =>
                i === stepIndex ? { ...s, done: !s.done } : s
              ),
            }
      ),
    };
    setReport(nextReport);
    setHistory(updateEntryReport(nextReport.id, () => nextReport));
  }

  function handleMarkPatched() {
    if (!report) return;
    const already = report.timeline.some((t) => t.label === "Patched");
    const nextTimeline = already
      ? report.timeline
      : [...report.timeline, { label: "Patched" as const, timestamp: Date.now() }, { label: "Verified" as const, timestamp: Date.now() }];
    const nextReport: SecurityReport = { ...report, timeline: nextTimeline };
    setReport(nextReport);
    setHistory(updateEntryReport(nextReport.id, () => nextReport));
  }

  function handleSelectHistory(entry: MaintenanceLogEntry) {
    setReport(entry.report);
    setError(null);
  }

  function handleClearHistory() {
    clearHistory();
    setHistory([]);
  }

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 max-w-[1600px] mx-auto">
      <div className="flex items-start gap-3">
        <div className="h-10 w-10 grid place-items-center rounded-xl bg-gradient-to-br from-[#c084fc] to-[#9333ea] text-black shadow-lg shadow-purple-500/20 shrink-0">
          <Wrench className="h-5 w-5 text-white" strokeWidth={2.5} />
        </div>
        <div>
          <h1 className="text-lg font-extrabold tracking-tight text-foreground flex items-center gap-2">
            Maintenance Log
            <ShieldCheck className="h-4 w-4 text-accent" />
          </h1>
          <p className="text-xs font-mono text-muted-dim">
            Cyber Security Incident Analyzer — upload log/kode, temukan kebocoran, dapatkan langkah remediasi.
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
          <InputPanel onAnalyze={handleAnalyze} loading={loading} />
          <HistoryPanel entries={history} activeId={report?.id} onSelect={handleSelectHistory} onClear={handleClearHistory} />
        </div>
        <div>
          <OutputPanel report={report} loading={loading} onToggleStep={handleToggleStep} onMarkPatched={handleMarkPatched} />
        </div>
      </div>
    </div>
  );
}
