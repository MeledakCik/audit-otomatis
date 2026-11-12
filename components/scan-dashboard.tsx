"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useScanStream } from "@/lib/use-scan-stream";
import { StatusPill } from "@/components/status-pill";
import { TerminalLog } from "@/components/terminal-log";
import { FindingsTable } from "@/components/findings-table";
import { EndpointsTable } from "@/components/endpoints-table";
import { GraphView } from "@/components/graph-view";
import { SentinelAudit } from "@/components/sentinel/sentinel-audit";
import { VerifiedBadge } from "@/components/verified-badge";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import {
  ArrowLeft,
  Download,
  FileText,
  Lock,
  Network,
  Radar,
  ShieldAlert,
  Terminal,
  Globe,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/types";

const SEV_ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

export function ScanDashboard({
  scanId,
  domain,
}: {
  scanId: string;
  domain: string;
}) {
  const { connect, status, logs, findings, endpoints, blockedReason } =
    useScanStream();
  const [activeTab, setActiveTab] = useState<"overview" | "sentinel" | "endpoints">("overview");

  useEffect(() => {
    connect(scanId);
  }, [scanId, connect]);

  const counts = useMemo(() => {
    const c: Record<Severity, number> = {
      CRITICAL: 0,
      HIGH: 0,
      MEDIUM: 0,
      LOW: 0,
      INFO: 0,
    };
    for (const f of findings) c[f.severity]++;
    return c;
  }, [findings]);

  const isTerminal =
    status === "done" || status === "error" || status === "blocked_cloudflare" || status === "stopped";

  return (
    <div className="flex flex-1 flex-col min-h-full">
      {/* Sticky Scan Header */}
      <header className="border-b border-border bg-panel/85 backdrop-blur-md sticky top-0 z-20 rounded-[20px] shadow-sm">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 py-3.5 flex flex-wrap items-center justify-between gap-3 rounded-[20px] shadow-sm">
          <div className="flex items-center gap-3 min-w-0">
            <Link
              href="/dashboard"
              className="flex items-center justify-center h-9 w-9 rounded-xl border border-border bg-foreground/[0.03] hover:bg-foreground/[0.08] text-soft transition-colors shrink-0"
              title="Kembali ke Beranda Scan"
            >
              <ArrowLeft className="h-4 w-4" />
            </Link>
            <div className="min-w-0">
              <div className="flex items-center gap-2">
                <Globe className="h-3.5 w-3.5 text-purple-400 shrink-0" />
                <span className="text-sm font-extrabold text-foreground truncate">
                  {domain}
                </span>
                <span className="hidden sm:inline-block text-xs font-mono text-muted bg-foreground/[0.04] px-2 py-0.5 rounded-md border border-border">
                  ID: {scanId}
                </span>
              </div>
              <div className="text-xs font-mono text-muted">
                Full Passive Audit &amp; Sentinel Encrypted Vault
              </div>
            </div>
          </div>

          <div className="flex items-center gap-2.5 flex-wrap">
            <VerifiedBadge variant="header" className="hidden md:inline-flex" />
            <StatusPill status={status} />
            <Link href={`/scan/${scanId}/report`}>
              <Button
                variant="outline"
                size="sm"
                disabled={!isTerminal && findings.length === 0}
                className="h-8 text-xs gap-1.5 rounded-xl"
              >
                <FileText className="h-3.5 w-3.5" />
                Laporan HTML
              </Button>
            </Link>
            <a href={`/api/scan/${scanId}/export`} download>
              <Button
                variant="outline"
                size="sm"
                disabled={!isTerminal && findings.length === 0}
                className="h-8 text-xs gap-1.5 rounded-xl"
              >
                <Download className="h-3.5 w-3.5" />
                Export .MD
              </Button>
            </a>
          </div>
        </div>
      </header>

      <div className="flex-1 mx-auto w-full max-w-6xl px-4 sm:px-6 py-6 flex flex-col gap-5">
        {blockedReason && (
          <div className="rounded-2xl border border-amber-500/40 bg-amber-500/10 px-4 py-3.5 text-xs text-amber-200 leading-relaxed animate-fade-up">
            <span className="font-bold uppercase tracking-widest block mb-1 text-amber-400">
              Scan Dihentikan — Proteksi Cloudflare Challenge
            </span>
            {blockedReason}
          </div>
        )}

        {/* Severity KPI Cards */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 animate-fade-up">
          {SEV_ORDER.map((sev) => (
            <div
              key={sev}
              className="rounded-2xl border border-foreground/[0.08] bg-gradient-to-b from-[#161024] to-sunken px-4 py-3.5 flex items-center justify-between gap-2 shadow-sm"
            >
              <div className="flex flex-col gap-0.5 min-w-0">
                <span className="text-xs font-mono uppercase tracking-widest text-muted truncate">
                  {sev}
                </span>
                <span
                  className="text-2xl font-extrabold tabular-nums"
                  style={{
                    color:
                      counts[sev] > 0
                        ? `var(--sev-${sev.toLowerCase()})`
                        : undefined,
                  }}
                >
                  {counts[sev]}
                </span>
              </div>
              <span
                className="h-2.5 w-2.5 rounded-full shrink-0"
                style={{
                  background: `var(--sev-${sev.toLowerCase()})`,
                  boxShadow:
                    counts[sev] > 0
                      ? `0 0 10px 2px var(--sev-${sev.toLowerCase()})`
                      : undefined,
                  opacity: counts[sev] > 0 ? 1 : 0.3,
                }}
              />
            </div>
          ))}
        </div>

        {/* Navigation Sub-Tabs inside Scan Dashboard */}
        <div className="flex flex-wrap items-center gap-2 border-b border-border pb-3">
          <button
            type="button"
            onClick={() => setActiveTab("overview")}
            className={cn(
              "inline-flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-mono font-bold transition-all cursor-pointer",
              activeTab === "overview"
                ? "bg-purple-600 text-white shadow-lg shadow-purple-600/25"
                : "border border-border bg-foreground/[0.03] text-soft hover:text-foreground"
            )}
          >
            <Radar className="h-3.5 w-3.5" />
            <span>Temuan &amp; Live Log ({findings.length})</span>
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("sentinel")}
            className={cn(
              "inline-flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-mono font-bold transition-all cursor-pointer",
              activeTab === "sentinel"
                ? "bg-gradient-to-r from-purple-600 to-pink-600 text-white shadow-lg shadow-pink-600/25"
                : "border border-purple-500/30 bg-purple-500/10 text-purple-200 hover:bg-purple-500/20"
            )}
          >
            <Lock className="h-3.5 w-3.5" />
            <span>Sentinel Vault &amp; Klaim Domain</span>
            {counts.CRITICAL > 0 && (
              <span className="rounded-full bg-red-500 px-1.5 py-0.2 text-xs text-white font-extrabold">
                {counts.CRITICAL} CRIT
              </span>
            )}
          </button>

          <button
            type="button"
            onClick={() => setActiveTab("endpoints")}
            className={cn(
              "inline-flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-mono font-bold transition-all cursor-pointer",
              activeTab === "endpoints"
                ? "bg-purple-600 text-white shadow-lg shadow-purple-600/25"
                : "border border-border bg-foreground/[0.03] text-soft hover:text-foreground"
            )}
          >
            <Network className="h-3.5 w-3.5" />
            <span>API Explorer &amp; Relasi Graph ({endpoints.length})</span>
          </button>
        </div>

        {/* Tab 1: Findings + Live Log + Sentinel Quick Card */}
        {activeTab === "overview" && (
          <div className="space-y-5">
            <div className="grid lg:grid-cols-5 gap-4 flex-1 min-h-0 animate-fade-up">
              <Card className="lg:col-span-3 flex flex-col min-h-0 border-border bg-panel">
                <CardHeader className="border-b border-foreground/[0.06]">
                  <CardTitle className="flex items-center gap-2">
                    <ShieldAlert className="h-4 w-4 text-purple-400" />
                    <span>Daftar Temuan Keamanan ({findings.length})</span>
                  </CardTitle>
                  <button
                    type="button"
                    onClick={() => setActiveTab("sentinel")}
                    className="text-xs font-mono text-purple-300 hover:text-purple-200 underline cursor-pointer"
                  >
                    Buka Sentinel Vault &amp; Klaim Kepemilikan →
                  </button>
                </CardHeader>
                <div className="overflow-y-auto thin-scroll max-h-[50vh] lg:max-h-[62vh]">
                  <FindingsTable findings={findings} />
                </div>
              </Card>

              <Card className="lg:col-span-2 flex flex-col min-h-0 border-border bg-panel">
                <CardHeader className="border-b border-foreground/[0.06]">
                  <CardTitle className="flex items-center gap-2">
                    <Terminal className="h-4 w-4 text-emerald-400" />
                    <span>Live Telemetry Log</span>
                  </CardTitle>
                  <span className="text-xs font-mono text-muted">
                    {logs.length} event
                  </span>
                </CardHeader>
                <div className="h-[42vh] lg:h-[62vh]">
                  <TerminalLog logs={logs} />
                </div>
              </Card>
            </div>

            {/* Integrated Sentinel Vault & Domain Claim directly below findings */}
            <div className="pt-2">
              <SentinelAudit initialDomain={domain} embedded autoLoadPublic />
            </div>
          </div>
        )}

        {/* Tab 2: Dedicated Sentinel Vault & Domain Ownership Claim */}
        {activeTab === "sentinel" && (
          <div className="animate-fade-up">
            <SentinelAudit initialDomain={domain} embedded autoLoadPublic />
          </div>
        )}

        {/* Tab 3: API Explorer & Attack Surface Relation Graph */}
        {activeTab === "endpoints" && (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 animate-fade-up">
            <Card className="flex flex-col min-h-0 border-border bg-panel">
              <CardHeader className="border-b border-foreground/[0.06]">
                <CardTitle>
                  API Explorer — Endpoint Ditemukan ({endpoints.length})
                </CardTitle>
                <span className="text-xs text-muted">
                  Klik endpoint untuk uji langsung (GET-only) atau salin cURL
                </span>
              </CardHeader>
              <div className="h-full flex flex-col min-h-0 overflow-hidden">
                <EndpointsTable endpoints={endpoints} scanId={scanId} />
              </div>
            </Card>

            <Card className="flex flex-col min-h-0 border-border bg-panel">
              <CardHeader className="border-b border-foreground/[0.06]">
                <CardTitle>Peta Relasi Page → JS → Endpoint</CardTitle>
                <a
                  href={`/api/scan/${scanId}/graph`}
                  target="_blank"
                  rel="noreferrer"
                >
                  <Button variant="outline" size="sm">
                    lihat graph.json
                  </Button>
                </a>
              </CardHeader>
              <GraphView scanId={scanId} status={status} />
            </Card>
          </div>
        )}
      </div>
    </div>
  );
}
