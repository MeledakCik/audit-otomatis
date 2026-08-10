"use client";

import React, { useState, useEffect, useRef, useCallback } from "react";
import {
  Play,
  Square,
  RefreshCw,
  ShieldCheck,
  AlertCircle,
  Gauge,
  Target,
  Activity,
  Hash,
  Terminal,
  Server,
  Zap,
  Globe,
  Lock,
  Search,
  Cpu,
} from "lucide-react";

// --- Types ---
export interface DomainStatusResult {
  domain: string;
  isGuarded: boolean;
  httpStatus: number | null;
  responseTimeMs: number;
  serverHeader: string;
  error?: string;
  scannedAt: string;
}

export interface BatchStatusResult {
  results: DomainStatusResult[];
  totalTargets: number;
  successCount: number;
  failedCount: number;
  threads: number;
  durationMs: number;
  summary: {
    avgLatency: number | null;
    targetsWithGuard: string[];
    targetsWithoutGuard: string[];
  };
}

const MAX_LOG_LINES = 100;

function timeLabel(ts: number): string {
  return new Date(ts).toLocaleTimeString("en-US", {
    hour12: false,
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

function buildLogLine(res: DomainStatusResult): string {
  const t = timeLabel(Date.now());
  if (res.error) {
    return `[${t}] ❌ ${res.domain} -> ERR: ${res.error}`;
  }
  const guardStr = res.isGuarded ? "🛡️ GUARDED" : "⚠️ UNGUARDED";
  const codeStr = res.httpStatus !== null ? `[${res.httpStatus}]` : "[---]";
  const latStr = `${res.responseTimeMs}ms`;
  const srvStr = res.serverHeader !== "Unknown" ? `(${res.serverHeader})` : "";
  return `[${t}] ${guardStr} | ${res.domain} ${codeStr} - ${latStr} ${srvStr}`.trim();
}

const accentMap: Record<string, string> = {
  zinc: "from-transparent via-zinc-500/30 to-transparent",
  emerald: "from-transparent via-emerald-500/60 to-transparent",
  amber: "from-transparent via-amber-500/60 to-transparent",
  purple: "from-transparent via-purple-500/60 to-transparent",
  rose: "from-transparent via-rose-500/60 to-transparent",
};

function StatTile({ icon: Icon, label, value, subtitle, accent = "zinc", valueClassName = "text-white" }: any) {
  return (
    <div className="group relative overflow-hidden rounded-2xl border border-purple-900/30 bg-[#0d0914]/80 p-4 backdrop-blur-xl transition-all hover:border-purple-800/30 hover:shadow-[0_0_20px_rgba(124,58,237,0.08)]">
      <div className={`absolute top-0 left-0 h-0.5 w-full bg-gradient-to-r ${accentMap[accent] || accentMap.zinc} opacity-60 group-hover:opacity-100 transition-opacity`} />

      <div className="flex items-center justify-between">
        <span className="text-[10px] font-semibold uppercase tracking-[0.14em] text-purple-400 group-hover:text-purple-300">
          {label}
        </span>
        <div className="flex h-6 w-6 items-center justify-center rounded-full border border-white/[0.06] bg-white/[0.03] text-purple-400 group-hover:text-purple-300 transition-colors">
          <Icon className="h-3.5 w-3.5" />
        </div>
      </div>

      <div className="mt-3">
        <div className={`text-xl md:text-2xl font-bold tracking-tight font-mono leading-none ${valueClassName}`}>
          {value}
        </div>
        {subtitle && (
          <div className="mt-1.5 text-[11px] font-mono text-zinc-500">
            {subtitle}
          </div>
        )}
      </div>
    </div>
  );
}

export default function ThreatLab() {
  const [domainInput, setDomainInput] = useState<string>("");
  const [threadsInput, setThreadsInput] = useState<string>("5");
  const [timeoutInput, setTimeoutInput] = useState<string>("4000");
  const [useProxy, setUseProxy] = useState<boolean>(false);

  const [isRunning, setIsRunning] = useState<boolean>(false);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [connected, setConnected] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const [batchData, setBatchData] = useState<BatchStatusResult | null>(null);
  const [logs, setLogs] = useState<string[]>([]);
  const [eventCount, setEventCount] = useState<number>(0);

  const mountedRef = useRef<boolean>(true);
  const pollIntervalRef = useRef<NodeJS.Timeout | null>(null);
  const startTimeoutRef = useRef<NodeJS.Timeout | null>(null);

  const clearTimers = useCallback(() => {
    if (pollIntervalRef.current) {
      clearInterval(pollIntervalRef.current);
      pollIntervalRef.current = null;
    }
    if (startTimeoutRef.current) {
      clearTimeout(startTimeoutRef.current);
      startTimeoutRef.current = null;
    }
  }, []);

  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
      clearTimers();
    };
  }, [clearTimers]);

  // Fetch target initial configuration
  const fetchConfig = useCallback(async () => {
    try {
      const res = await fetch("/api/shield-status?action=config", { cache: "no-store" });
      if (!res.ok) return;
      const data = await res.json();
      if (!mountedRef.current) return;
      if (data.config) {
        setThreadsInput(String(data.config.threads ?? 5));
        setTimeoutInput(String(data.config.timeout ?? 4000));
        setUseProxy(Boolean(data.config.useProxy));
      }
    } catch {
      // Ignore initial config error
    }
  }, []);

  useEffect(() => {
    fetchConfig();
  }, [fetchConfig]);

  // Poll Scanner Status
  const pollStatus = useCallback(async () => {
    try {
      const res = await fetch(
        `/api/shield-status?action=check&useProxy=${useProxy}&timeout=${parseInt(timeoutInput) || 4000}&threads=${parseInt(threadsInput) || 5}`,
        { cache: "no-store" }
      );

      if (!res.ok) {
        const errorData = await res.json().catch(() => null);
        throw new Error(errorData?.error || `HTTP ${res.status}`);
      }

      const data: BatchStatusResult = await res.json();
      if (!mountedRef.current) return;

      const safeData: BatchStatusResult = {
        ...data,
        results: data.results ?? [],
        summary: data.summary ?? { avgLatency: null, targetsWithGuard: [], targetsWithoutGuard: [] },
      };

      setBatchData(safeData);
      setConnected(safeData.successCount > 0 || safeData.totalTargets > 0);
      setEventCount((c) => c + 1);

      if (safeData.results.length > 0) {
        const newLogs = safeData.results.map((r) => buildLogLine(r));
        setLogs((prev) => [...newLogs, ...prev].slice(0, MAX_LOG_LINES));
      } else if (safeData.totalTargets === 0) {
        setLogs((prev) => [
          `[${timeLabel(Date.now())}] ⚠️ Target kosong. Silakan periksa domain input.`,
          ...prev,
        ].slice(0, MAX_LOG_LINES));
      }
      setError(null);
    } catch (err: any) {
      if (!mountedRef.current) return;
      setConnected(false);
      setError(err.message || "Gagal mengambil status pemindaian");
    }
  }, [useProxy, timeoutInput, threadsInput]);

  // Action: Start Scan
  const startScan = async () => {
    const trimmedDomains = domainInput.trim();

    if (!trimmedDomains) {
      setError("Field 'domains' wajib diisi (string dipisah koma atau array)");
      return;
    }

    setIsLoading(true);
    setError(null);
    clearTimers();

    try {
      // 1. Clear targets
      await fetch("/api/shield-status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clearTargets: true }),
      });

      // 2. Add targets
      const addRes = await fetch("/api/shield-status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          domains: trimmedDomains,
          threads: parseInt(threadsInput) || 4,
          timeout: parseInt(timeoutInput) || 4000,
          useProxy,
        }),
      });

      if (!addRes.ok) {
        const errorJson = await addRes.json().catch(() => null);
        throw new Error(errorJson?.error || `Gagal menambah target: HTTP ${addRes.status}`);
      }

      const addData = await addRes.json();
      if (addData?.config?.targetCount === 0) {
        throw new Error("Tidak ada target valid yang berhasil ditambahkan");
      }

      await fetchConfig();
      setIsRunning(true);

      startTimeoutRef.current = setTimeout(async () => {
        if (mountedRef.current) {
          await pollStatus();
          pollIntervalRef.current = setInterval(pollStatus, 3000);
        }
      }, 500);
    } catch (err: any) {
      setError(err.message || String(err));
      setIsRunning(false);
    } finally {
      setIsLoading(false);
    }
  };

  // Action: Stop Scan
  const stopScan = async () => {
    setIsLoading(true);
    clearTimers();
    try {
      await fetch("/api/shield-status", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ clearTargets: true }),
      });
      setIsRunning(false);
      setConnected(false);
      setLogs((prev) => [`[${timeLabel(Date.now())}] 🛑 Scan dihentikan oleh pengguna.`, ...prev]);
    } catch (err: any) {
      setError(err.message || String(err));
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#07050a] text-zinc-200 p-4 md:p-8 font-mono antialiased selection:bg-purple-500/30 selection:text-purple-200">
      <div className="max-w-6xl mx-auto space-y-6">
        {/* Header Title (Diubah ke Threads Labs) */}
        <div className="flex items-start gap-3">
          <div className="p-2.5 rounded-2xl bg-gradient-to-br from-purple-600 to-fuchsia-600 shadow-lg shadow-purple-500/20 text-white mt-1">
            <Cpu className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl md:text-2xl font-bold tracking-tight text-white">
                Thread Labs
              </h1>
              <Lock className="w-4 h-4 text-purple-400" />
            </div>
            <p className="text-xs md:text-sm text-zinc-400 mt-1">
              Multi-threaded Concurrent Scanner, WAF detection & passive header auditing.
            </p>
          </div>
        </div>

        {/* Header Controls (Cyber Input Card) */}
        <div className="rounded-2xl border border-purple-900/30 bg-[#0d0914]/80 backdrop-blur-xl p-5 shadow-xl shadow-purple-950/10 space-y-5">
          <div className="flex items-center gap-2 text-xs font-semibold tracking-wider text-purple-400 uppercase border-b border-purple-900/20 pb-3">
            <Target className="w-4 h-4" />
            <span>Target Configuration</span>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-end">
            {/* Target Domains Input */}
            <div className="lg:col-span-6 space-y-1.5">
              <label className="text-[11px] font-medium text-zinc-400 uppercase tracking-wider flex items-center gap-1.5">
                <Globe className="w-3.5 h-3.5 text-zinc-500" />
                Target Domain(s)
              </label>
              <input
                type="text"
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                placeholder="example.com, target.id"
                className="w-full bg-[#050308] border border-purple-900/40 rounded-xl px-4 py-2.5 text-xs text-purple-200 placeholder-zinc-600 focus:outline-none focus:border-purple-500 focus:ring-1 focus:ring-purple-500/50 transition-all font-mono disabled:opacity-50"
                disabled={isRunning || isLoading}
                onKeyDown={(e) => {
                  if (e.key === "Enter" && !isRunning && domainInput.trim()) {
                    startScan();
                  }
                }}
              />
            </div>

            {/* Config Controls */}
            <div className="lg:col-span-4 grid grid-cols-3 gap-2">
              <div className="space-y-1.5">
                <label className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
                  Threads
                </label>
                <input
                  type="number"
                  value={threadsInput}
                  onChange={(e) => setThreadsInput(e.target.value)}
                  className="w-full bg-[#050308] border border-purple-900/40 rounded-xl px-3 py-2 text-xs text-purple-200 focus:outline-none focus:border-purple-500 font-mono disabled:opacity-50"
                  disabled={isRunning || isLoading}
                />
              </div>

              <div className="space-y-1.5">
                <label className="text-[10px] font-semibold uppercase tracking-wider text-zinc-500">
                  Timeout (ms)
                </label>
                <input
                  type="number"
                  value={timeoutInput}
                  onChange={(e) => setTimeoutInput(e.target.value)}
                  className="w-full bg-[#050308] border border-purple-900/40 rounded-xl px-3 py-2 text-xs text-purple-200 focus:outline-none focus:border-purple-500 font-mono disabled:opacity-50"
                  disabled={isRunning || isLoading}
                />
              </div>

              <div className="flex items-center justify-center pt-5">
                <label className="relative flex cursor-pointer items-center gap-2 text-xs text-purple-300/80">
                  <input
                    type="checkbox"
                    checked={useProxy}
                    onChange={(e) => setUseProxy(e.target.checked)}
                    disabled={isRunning || isLoading}
                    className="rounded border-purple-900/50 bg-[#050308] text-purple-600 focus:ring-0 focus:ring-offset-0 disabled:opacity-50"
                  />
                  Proxy
                </label>
              </div>
            </div>

            {/* Action Button */}
            <div className="lg:col-span-2">
              {!isRunning ? (
                <button
                  onClick={startScan}
                  disabled={isLoading}
                  className="w-full relative group overflow-hidden rounded-xl bg-gradient-to-r from-purple-700 via-fuchsia-600 to-purple-600 p-[1px] font-semibold text-xs transition-all duration-300 hover:shadow-[0_0_25px_rgba(168,85,247,0.4)] disabled:opacity-50"
                >
                  <div className="flex items-center justify-center gap-2 rounded-xl bg-[#130a21] px-4 py-2.5 transition-all duration-300 group-hover:bg-transparent text-white">
                    {isLoading ? (
                      <RefreshCw className="h-4 w-4 animate-spin text-purple-300" />
                    ) : (
                      <Play className="h-4 w-4 text-purple-300 group-hover:text-white" />
                    )}
                    <span>START SCAN</span>
                  </div>
                </button>
              ) : (
                <button
                  onClick={stopScan}
                  disabled={isLoading}
                  className="w-full relative group overflow-hidden rounded-xl bg-gradient-to-r from-rose-700 to-pink-600 p-[1px] font-semibold text-xs transition-all duration-300 hover:shadow-[0_0_25px_rgba(244,63,94,0.4)] disabled:opacity-50"
                >
                  <div className="flex items-center justify-center gap-2 rounded-xl bg-[#1d080e] px-4 py-2.5 transition-all duration-300 group-hover:bg-transparent text-white">
                    {isLoading ? (
                      <RefreshCw className="h-4 w-4 animate-spin text-rose-300" />
                    ) : (
                      <Square className="h-4 w-4 text-rose-300 group-hover:text-white" />
                    )}
                    <span>STOP SCAN</span>
                  </div>
                </button>
              )}
            </div>
          </div>

          {/* Error Alert Banner */}
          {error && (
            <div className="rounded-xl border border-rose-900/40 bg-rose-950/20 p-3.5 text-xs text-rose-400 flex items-center gap-2.5">
              <AlertCircle className="h-4 w-4 shrink-0 text-rose-400" />
              <span>{error}</span>
            </div>
          )}
        </div>

        {/* Stats Grid */}
        {(isRunning || batchData) && batchData && (batchData.totalTargets ?? 0) > 0 && (
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
            <StatTile
              icon={Target}
              label="Targets"
              value={String(batchData.totalTargets ?? 0)}
              subtitle={`${batchData.successCount ?? 0} success`}
              accent="purple"
            />
            <StatTile
              icon={Activity}
              label="Success Rate"
              value={`${
                (batchData.totalTargets ?? 0) > 0
                  ? (((batchData.successCount ?? 0) / batchData.totalTargets) * 100).toFixed(0)
                  : 0
              }%`}
              valueClassName={
                (batchData.successCount ?? 0) >= (batchData.failedCount ?? 0)
                  ? "text-emerald-400"
                  : "text-amber-400"
              }
              accent="emerald"
            />
            <StatTile
              icon={Gauge}
              label="Avg Latency"
              value={
                batchData.summary?.avgLatency !== null && batchData.summary?.avgLatency !== undefined
                  ? `${batchData.summary.avgLatency}ms`
                  : "—"
              }
              accent="amber"
            />
            <StatTile
              icon={ShieldCheck}
              label="With Guard"
              value={String(batchData.summary?.targetsWithGuard?.length ?? 0)}
              valueClassName="text-emerald-400"
              accent="emerald"
            />
            <StatTile
              icon={AlertCircle}
              label="Without Guard"
              value={String(batchData.summary?.targetsWithoutGuard?.length ?? 0)}
              valueClassName="text-amber-400"
              accent="amber"
            />
            <StatTile
              icon={Hash}
              label="Threads"
              value={String(batchData.threads ?? 0)}
              accent="purple"
            />
          </div>
        )}

        {/* Results Table */}
        {batchData && (batchData.results?.length ?? 0) > 0 && (
          <div className="overflow-hidden rounded-2xl border border-purple-900/30 bg-[#0d0914]/80 backdrop-blur-xl shadow-xl shadow-purple-950/10">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-purple-900/20 bg-[#07050a]/60 text-purple-300 uppercase tracking-wider text-[10px]">
                  <tr>
                    <th className="px-5 py-3.5 font-semibold">Domain Target</th>
                    <th className="px-5 py-3.5 font-semibold">Guard Status</th>
                    <th className="px-5 py-3.5 font-semibold">HTTP Code</th>
                    <th className="px-5 py-3.5 font-semibold">Latency</th>
                    <th className="px-5 py-3.5 font-semibold">Server Header</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-purple-900/20 font-mono text-zinc-300">
                  {(batchData.results ?? []).map((res, index) => (
                    <tr key={index} className="hover:bg-purple-950/20 transition-colors">
                      <td className="px-5 py-3.5 font-semibold text-white">{res.domain}</td>
                      <td className="px-5 py-3.5">
                        {res.isGuarded ? (
                          <span className="inline-flex items-center gap-1.5 rounded-md bg-emerald-950/40 px-2.5 py-1 text-[10px] font-bold text-emerald-400 border border-emerald-800/40">
                            <Zap className="h-3 w-3" /> GUARDED
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 rounded-md bg-amber-950/40 px-2.5 py-1 text-[10px] font-bold text-amber-400 border border-amber-800/40">
                            <AlertCircle className="h-3 w-3" /> UNGUARDED
                          </span>
                        )}
                      </td>
                      <td className="px-5 py-3.5">
                        {res.httpStatus ? (
                          <span className={res.httpStatus < 400 ? "text-emerald-400 font-bold" : "text-rose-400 font-bold"}>
                            {res.httpStatus}
                          </span>
                        ) : (
                          <span className="text-zinc-600">ERR</span>
                        )}
                      </td>
                      <td className="px-5 py-3.5 text-purple-200">{res.responseTimeMs}ms</td>
                      <td className="px-5 py-3.5 text-zinc-400">{res.serverHeader}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Realtime Terminal Console */}
        <div className="overflow-hidden rounded-2xl border border-purple-900/30 bg-[#050308]/90 font-mono text-xs shadow-xl shadow-purple-950/20">
          <div className="flex items-center justify-between border-b border-purple-900/20 bg-[#0d0914]/80 px-4 py-3 text-zinc-400">
            <div className="flex items-center gap-2">
              <Terminal className="h-3.5 w-3.5 text-fuchsia-400" />
              <span className="font-semibold text-purple-200 text-xs">Live Execution Console</span>
            </div>
            <div className="flex items-center gap-4 text-[11px]">
              <span className="flex items-center gap-1.5">
                <Server className="h-3 w-3 text-zinc-500" />
                Status:{" "}
                <span className={connected ? "text-fuchsia-400 font-bold" : "text-zinc-500"}>
                  {connected ? "ACTIVE" : "IDLE"}
                </span>
              </span>
              <span>Events: {eventCount}</span>
            </div>
          </div>

          <div className="h-64 overflow-y-auto p-4 space-y-1.5 text-zinc-400">
            {logs.length === 0 ? (
              <div className="text-zinc-600 italic">Console siap. Masukkan domain dan klik "START SCAN"...</div>
            ) : (
              logs.map((log, i) => (
                <div
                  key={i}
                  className={
                    log.includes("❌")
                      ? "text-rose-400"
                      : log.includes("🛡️")
                      ? "text-emerald-400 font-medium"
                      : log.includes("⚠️")
                      ? "text-amber-400"
                      : "text-purple-200/80"
                  }
                >
                  {log}
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
}