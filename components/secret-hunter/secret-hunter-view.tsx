"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import { KeyRound, Lock } from "lucide-react";
import { InputPanel } from "./input-panel";
import { OutputPanel } from "./output-panel";
import { HistoryPanel } from "./history-panel";
import {
  loadSecretHuntHistory,
  saveSecretHuntToHistory,
  clearSecretHuntHistory,
} from "@/lib/secret-hunter/history-store";
import type { SecretHuntLogEntry, SecretHuntReport } from "@/lib/secret-hunter/types";

export function SecretHunterView() {
  const searchParams = useSearchParams();
  const initialDomain = searchParams.get("domain") ?? undefined;

  const [report, setReport] = useState<SecretHuntReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [liveStatus, setLiveStatus] = useState<string | null>(null);
  const [history, setHistory] = useState<SecretHuntLogEntry[]>([]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setHistory(loadSecretHuntHistory());
  }, []);

  async function handleScan(domain: string) {
    setLoading(true);
    setError(null);
    setLiveStatus(`Crawling ${domain} (GET-only, same-origin JS)...`);
    try {
      const res = await fetch("/api/scan-secrets", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      const data = await res.json();
      if (!data.ok) {
        setError(data.error || "Gagal melakukan scan.");
        setLiveStatus(null);
        return;
      }
      const nextReport = data.report as SecretHuntReport;
      setReport(nextReport);
      setLiveStatus(`Selesai — ${nextReport.filesScanned} file, ${nextReport.findings.length} temuan, risk ${nextReport.riskLevel}`);
      setHistory(saveSecretHuntToHistory(nextReport));
    } catch {
      setError("Tidak bisa menghubungi server. Coba lagi.");
      setLiveStatus(null);
    } finally {
      setLoading(false);
    }
  }

  function handleSelectHistory(entry: SecretHuntLogEntry) {
    setReport(entry.report);
    setError(null);
    setLiveStatus(null);
  }

  function handleClearHistory() {
    clearSecretHuntHistory();
    setHistory([]);
  }

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 max-w-[1600px] mx-auto">
      <div className="flex items-start gap-3">
        <div className="h-10 w-10 grid place-items-center rounded-xl bg-gradient-to-br from-[#c084fc] to-[#9333ea] text-black shadow-lg shadow-purple-500/20 shrink-0">
          <KeyRound className="h-5 w-5 text-white" strokeWidth={2.5} />
        </div>
        <div>
          <h1 className="text-lg font-extrabold tracking-tight text-foreground flex items-center gap-2">
            JS Secret Hunter
            <Lock className="h-4 w-4 text-accent" />
          </h1>
          <p className="text-xs font-mono text-muted-dim">
            Cari credential/secret ter-hardcode di JS same-origin — 100% pasif, GET-only, tanpa verifikasi value.
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
          <InputPanel onScan={handleScan} loading={loading} liveStatus={liveStatus} initialDomain={initialDomain} />
          <HistoryPanel entries={history} activeId={report?.id} onSelect={handleSelectHistory} onClear={handleClearHistory} />
        </div>
        <div>
          <OutputPanel report={report} loading={loading} />
        </div>
      </div>
    </div>
  );
}
