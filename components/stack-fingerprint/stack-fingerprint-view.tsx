"use client";

import { useEffect, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Fingerprint, Lock } from "lucide-react";
import { InputPanel } from "./input-panel";
import { ResultsGrid } from "./results-grid";
import { HistoryPanel } from "./history-panel";
import { detectStacks } from "@/lib/stack-fingerprint/detect";
import {
  loadStackFingerprintHistory,
  saveStackFingerprintToHistory,
  clearStackFingerprintHistory,
} from "@/lib/stack-fingerprint/history-store";
import type { StackFingerprintLogEntry, StackFingerprintReport } from "@/lib/stack-fingerprint/types";

function cryptoRandomId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

export function StackFingerprintView() {
  const searchParams = useSearchParams();
  const initialDomain = searchParams.get("domain") ?? undefined;

  const [report, setReport] = useState<StackFingerprintReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [liveStatus, setLiveStatus] = useState<string | null>(null);
  const [history, setHistory] = useState<StackFingerprintLogEntry[]>([]);
  const reportRef = useRef<StackFingerprintReport | null>(null);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setHistory(loadStackFingerprintHistory());
  }, []);

  async function handleScan(domainInput: string) {
    setLoading(true);
    setError(null);
    setLiveStatus(`Mengambil homepage ${domainInput}...`);

    try {
      const res = await fetch(`/api/stack?domain=${encodeURIComponent(domainInput)}`, { method: "GET" });
      const data = await res.json();
      if (!data.ok) {
        setError(data.error || "Gagal melakukan fingerprint.");
        setLiveStatus(null);
        setLoading(false);
        return;
      }

      setLiveStatus("Menjalankan deteksi tech stack...");
      const stacks = detectStacks(data.headers, data.htmlSnippet);

      const nextReport: StackFingerprintReport = {
        id: cryptoRandomId(),
        createdAt: Date.now(),
        domain: data.domain,
        targetUrl: data.targetUrl,
        finalUrl: data.finalUrl,
        statusCode: data.statusCode,
        stacks,
      };

      reportRef.current = nextReport;
      setReport(nextReport);
      setHistory(saveStackFingerprintToHistory(nextReport));
      setLiveStatus(null);
      setLoading(false);
    } catch {
      setError("Tidak bisa menghubungi server. Coba lagi.");
      setLiveStatus(null);
      setLoading(false);
    }
  }

  function handleSelectHistory(entry: StackFingerprintLogEntry) {
    reportRef.current = entry.report;
    setReport(entry.report);
    setError(null);
    setLiveStatus(null);
  }

  function handleClearHistory() {
    clearStackFingerprintHistory();
    setHistory([]);
  }

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 max-w-[1600px] mx-auto">
      <div className="flex items-start gap-3">
        <div className="h-10 w-10 grid place-items-center rounded-xl bg-gradient-to-br from-[#c084fc] to-[#9333ea] text-black shadow-lg shadow-purple-500/20 shrink-0">
          <Fingerprint className="h-5 w-5 text-white" strokeWidth={2.5} />
        </div>
        <div>
          <h1 className="text-lg font-extrabold tracking-tight text-foreground flex items-center gap-2">
            Tech Stack Fingerprint
            <Lock className="h-4 w-4 text-accent" />
          </h1>
          <p className="text-xs font-mono text-muted-dim">
            Passive homepage fingerprinting — headers + HTML markers only. Educational asset inventory, no CVE lookup.
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
        <div className="space-y-6">
          <ResultsGrid report={report} />
        </div>
      </div>
    </div>
  );
}
