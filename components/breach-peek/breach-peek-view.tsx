"use client";

import { useEffect, useState } from "react";
import { Radar, Lock } from "lucide-react";
import { InputPanel } from "./input-panel";
import { OutputPanel } from "./output-panel";
import { HistoryPanel } from "./history-panel";
import { scanDomain } from "@/lib/breach-check/domain-probe";
import { loadBreachLog, saveBreachLogEntry, clearBreachLog } from "@/lib/breach-check/history-store";
import type { BreachLogEntry, DomainBreachReport, EmailBreachReport, EmailBreachResult } from "@/lib/breach-check/types";

type Result =
  | { mode: "email"; report: EmailBreachReport }
  | { mode: "domain"; report: DomainBreachReport }
  | null;

export function BreachPeekView() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<Result>(null);
  const [liveStatus, setLiveStatus] = useState<string | null>(null);
  const [history, setHistory] = useState<BreachLogEntry[]>([]);

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    setHistory(loadBreachLog());
  }, []);

  async function handleScanEmail(email: string) {
    setLoading(true);
    setError(null);
    setResult(null);
    setLiveStatus(`Checking ${email} against XposedOrNot...`);

    try {
      const res = await fetch(`/api/breach-free?email=${encodeURIComponent(email)}`);
      const json = (await res.json()) as EmailBreachResult;

      if (!json.ok) {
        setError(json.error);
        setLiveStatus(null);
        return;
      }

      setResult({ mode: "email", report: json });
      setLiveStatus(json.clean ? "Clean — no breaches found" : `Found in ${json.breachCount} breach(es)`);
      setHistory(
        saveBreachLogEntry({ mode: "email", query: json.email, clean: json.clean, breachCount: json.breachCount })
      );
    } catch {
      setError("Couldn't reach the scan service. Try again.");
      setLiveStatus(null);
    } finally {
      setLoading(false);
    }
  }

  async function handleScanDomain(domain: string) {
    setLoading(true);
    setError(null);
    setResult(null);
    setLiveStatus(`Probing 5 common addresses at ${domain}...`);

    try {
      const report = await scanDomain(domain);
      setResult({ mode: "domain", report });
      setLiveStatus(`${report.hitCount} of ${report.totalProbed} common emails found in breaches`);
      setHistory(
        saveBreachLogEntry({
          mode: "domain",
          query: report.domain,
          clean: report.hitCount === 0,
          breachCount: report.combinedBreaches.length,
        })
      );
    } catch {
      setError("Couldn't complete the domain scan. Try again.");
      setLiveStatus(null);
    } finally {
      setLoading(false);
    }
  }

  function handleClearHistory() {
    clearBreachLog();
    setHistory([]);
  }

  return (
    <div className="p-4 sm:p-6 lg:p-8 space-y-6 max-w-[1600px] mx-auto">
      <div className="flex items-start gap-3">
        <div className="h-10 w-10 grid place-items-center rounded-xl bg-gradient-to-br from-[#c084fc] to-[#9333ea] text-black shadow-lg shadow-purple-500/20 shrink-0">
          <Radar className="h-5 w-5 text-white" strokeWidth={2.5} />
        </div>
        <div>
          <h1 className="text-lg font-extrabold tracking-tight text-foreground flex items-center gap-2">
            Breach Peek <span className="text-[10px] font-bold uppercase tracking-widest text-accent">Free</span>
            <Lock className="h-4 w-4 text-accent" />
          </h1>
          <p className="text-xs font-mono text-muted-dim">
            Check if an email or domain shows up in known data breaches — 100% passive OSINT, no API key required.
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6 items-start">
        <div className="space-y-4 xl:sticky xl:top-6">
          <InputPanel onScanEmail={handleScanEmail} onScanDomain={handleScanDomain} loading={loading} liveStatus={liveStatus} />
          <HistoryPanel entries={history} onClear={handleClearHistory} />
        </div>
        <div>
          <OutputPanel loading={loading} error={error} result={result} />
        </div>
      </div>

      <p className="text-[10px] font-mono text-muted-dim text-center pt-2 border-t border-border">
        Powered by the XposedOrNot free OSINT breach database — 100% passive, no credentials or exploits involved.
      </p>
    </div>
  );
}
