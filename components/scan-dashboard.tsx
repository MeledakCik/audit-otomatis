"use client";

import { useEffect, useMemo } from "react";
import Link from "next/link";
import { useScanStream } from "@/lib/use-scan-stream";
import { StatusPill } from "@/components/status-pill";
import { TerminalLog } from "@/components/terminal-log";
import { FindingsTable } from "@/components/findings-table";
import { EndpointsTable } from "@/components/endpoints-table";
import { GraphView } from "@/components/graph-view";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
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
    status === "done" || status === "error" || status === "blocked_cloudflare";

  return (
    <div className="flex flex-1 flex-col">
      <header className="border-b border-border bg-surface/60 backdrop-blur-sm sticky top-0 z-10">
        <div className="mx-auto max-w-5xl px-4 sm:px-6 py-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <Link
              href="/"
              className="flex items-center justify-center h-8 w-8 rounded-lg border border-white/10 bg-white/[0.02] hover:bg-white/[0.06] text-slate-300 transition-colors shrink-0"
              title="Kembali ke Beranda"
            >
              <span className="text-sm">←</span>
            </Link>
            <Link href="/" className="flex items-center gap-2.5 group min-w-0">
              <span className="h-2 w-2 rounded-full bg-accent shrink-0 shadow-[0_0_8px_1px_var(--accent)] animate-pulse" />
              <span className="text-sm font-bold tracking-wide uppercase text-gradient-accent group-hover:brightness-125 transition-all truncate">
                AUTO-SEC-AUDITOR
              </span>
            </Link>
          </div>
          <div className="flex items-center gap-2 sm:gap-3 min-w-0">
            <span className="text-xs text-muted truncate max-w-[40vw] sm:max-w-none">
              {domain}
            </span>
            <StatusPill status={status} />
          </div>
        </div>
      </header>

      <main className="flex-1 mx-auto w-full max-w-5xl px-4 sm:px-6 py-5 sm:py-6 flex flex-col gap-4">
        {blockedReason && (
          <div className="rounded-xl border border-sev-high/40 bg-sev-high/10 px-4 py-3 text-xs text-sev-high leading-relaxed animate-fade-up">
            <span className="font-bold uppercase tracking-widest block mb-1">
              Scan dihentikan — Cloudflare Challenge
            </span>
            {blockedReason}
          </div>
        )}

        <div className="grid grid-cols-2 sm:grid-cols-5 gap-3 animate-fade-up">
          {SEV_ORDER.map((sev) => (
            <div
              key={sev}
              className="rounded-2xl border border-border bg-surface px-4 py-3 flex items-center justify-between gap-2"
            >
              <div className="flex flex-col gap-0.5 min-w-0">
                <span className="text-[10px] uppercase tracking-widest text-muted-dim truncate">
                  {sev}
                </span>
                <span
                  className="text-xl font-bold tabular-nums"
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
                className="h-2 w-2 rounded-full shrink-0"
                style={{
                  background: `var(--sev-${sev.toLowerCase()})`,
                  boxShadow:
                    counts[sev] > 0
                      ? `0 0 8px 1px var(--sev-${sev.toLowerCase()})`
                      : undefined,
                  opacity: counts[sev] > 0 ? 1 : 0.35,
                }}
              />
            </div>
          ))}
        </div>

        <div
          className="grid lg:grid-cols-5 gap-4 flex-1 min-h-0 animate-fade-up"
          style={{ "--delay": "60ms" } as React.CSSProperties}
        >
          <Card className="lg:col-span-3 flex flex-col min-h-0">
            <CardHeader>
              <CardTitle>Temuan ({findings.length})</CardTitle>
              <div className="flex items-center gap-2">
                <Link href={`/scan/${scanId}/report`}>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={!isTerminal && findings.length === 0}
                  >
                    lihat laporan
                  </Button>
                </Link>
                <a href={`/api/scan/${scanId}/export`} download>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={!isTerminal && findings.length === 0}
                  >
                    export .md
                  </Button>
                </a>
              </div>
            </CardHeader>
            <div className="overflow-y-auto thin-scroll max-h-[45vh] lg:max-h-[60vh]">
              <FindingsTable findings={findings} />
            </div>
          </Card>

          <Card className="lg:col-span-2 flex flex-col min-h-0">
            <CardHeader>
              <CardTitle>Log Aktivitas</CardTitle>
              <span className="text-[10px] text-muted-dim">
                {logs.length} event
              </span>
            </CardHeader>
            <div className="h-[40vh] lg:h-[60vh]">
              <TerminalLog logs={logs} />
            </div>
          </Card>
        </div>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-2">
          <Card
            className="flex flex-col min-h-0 animate-fade-up"
            style={{ "--delay": "120ms" } as React.CSSProperties}
          >
            <CardHeader>
              <CardTitle>
                API Explorer — Endpoint Ditemukan ({endpoints.length})
              </CardTitle>
              <span className="text-[10px] text-muted-dim">
                gaya Postman: klik tiap endpoint buat lihat detail, salin cURL,
                atau kirim langsung (GET-only)
              </span>
            </CardHeader>
            <div className="h-full lg:h-full flex flex-col min-h-0 overflow-hidden">
              <EndpointsTable endpoints={endpoints} scanId={scanId} />
            </div>
          </Card>

          <Card
            className="flex flex-col min-h-0 animate-fade-up"
            style={{ "--delay": "180ms" } as React.CSSProperties}
          >
            <CardHeader>
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
      </main>
    </div>
  );
}
