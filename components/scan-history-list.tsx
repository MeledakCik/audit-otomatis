"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ShieldAlert, ScanLine, FileClock } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { StatusPill } from "@/components/status-pill";
import { cn } from "@/lib/utils";
import type { ScanStatus, Finding } from "@/lib/types";

interface ScanSummary {
  id: string;
  domain: string;
  origin: string;
  createdAt: number;
  status: ScanStatus;
  pagesCount: number;
  findingsCount: number;
  severityCounts: Record<Finding["severity"], number>;
  blockedReason?: string;
}

const SEV_ORDER: Finding["severity"][] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEV_DOT: Record<Finding["severity"], string> = {
  CRITICAL: "text-sev-critical",
  HIGH: "text-sev-high",
  MEDIUM: "text-sev-medium",
  LOW: "text-sev-low",
  INFO: "text-sev-info",
};

function relativeTime(ts: number): string {
  const sec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (sec < 5) return "baru saja";
  if (sec < 60) return `${sec} detik lalu`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min} menit lalu`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr} jam lalu`;
  return `${Math.floor(hr / 24)} hari lalu`;
}

function FindingsSummary({ counts, total }: { counts: Record<Finding["severity"], number>; total: number }) {
  if (total === 0) {
    return <span className="text-muted-dim">—</span>;
  }
  const present = SEV_ORDER.filter((s) => counts[s] > 0);
  return (
    <div className="flex items-center gap-2.5 flex-wrap">
      {present.map((s) => (
        <span key={s} className={cn("inline-flex items-center gap-1 font-bold", SEV_DOT[s])}>
          <span className="h-1.5 w-1.5 rounded-full bg-current" />
          {counts[s]}
        </span>
      ))}
    </div>
  );
}

export function ScanHistoryList() {
  const [scans, setScans] = useState<ScanSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch("/api/history");
        const data = await res.json().catch(() => null);
        if (!res.ok) throw new Error(data?.error ?? `HTTP ${res.status}`);
        if (!cancelled) setScans(data.scans ?? []);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : "Gagal memuat riwayat scan.");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="w-full min-h-full">
      <div className="mx-auto max-w-6xl px-6 lg:px-8 py-10 space-y-6">
        <div className="space-y-3">
          <div className="inline-flex items-center px-3 py-1 rounded-md bg-accent/10 border border-accent/20 text-xs font-mono tracking-[0.2em] uppercase text-accent">
            $ ls ~/reports --sort=date
          </div>
          <h1 className="text-2xl lg:text-3xl font-extrabold tracking-tight text-foreground">Scan History</h1>
          <p className="text-sm text-muted-dim max-w-xl">
            Riwayat semua audit keamanan yang pernah dijalankan, ringkas per tingkat severity. Untuk
            lihat detail request/response mentah, pakai{" "}
            <Link href="/requests" className="text-accent hover:underline">
              Request Inspector
            </Link>
            .
          </p>
        </div>

        <Card>
          <CardHeader>
            <CardTitle>
              <FileClock className="h-3.5 w-3.5" />
              Reports
            </CardTitle>
            {scans && <span className="text-[10px] font-mono text-muted-dim">{scans.length} total</span>}
          </CardHeader>
          <CardContent className="p-0">
            {error && (
              <div className="px-4 py-10 text-center text-xs text-sev-critical font-mono">$ error: {error}</div>
            )}

            {!error && scans === null && (
              <div className="px-4 py-10 text-center text-xs text-muted-dim font-mono">
                <span className="cursor-blink">$ booting report index…</span>
              </div>
            )}

            {!error && scans !== null && scans.length === 0 && (
              <div className="px-4 py-10 text-center text-xs text-muted-dim font-mono space-y-2">
                <p>&gt; No scans found. Run</p>
                <Link href="/">
                  <Button variant="outline" size="sm" className="mt-1">
                    <ScanLine className="h-3.5 w-3.5" />
                    $ trout --scan
                  </Button>
                </Link>
              </div>
            )}

            {!error && scans !== null && scans.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full text-xs font-mono">
                  <thead>
                    <tr className="border-b border-border text-[10px] uppercase tracking-widest text-muted-dim">
                      <th className="text-left font-semibold px-4 py-2.5">ID</th>
                      <th className="text-left font-semibold px-4 py-2.5">Hostname</th>
                      <th className="text-left font-semibold px-4 py-2.5">Date</th>
                      <th className="text-left font-semibold px-4 py-2.5">Pages</th>
                      <th className="text-left font-semibold px-4 py-2.5">Findings</th>
                      <th className="text-left font-semibold px-4 py-2.5">Status</th>
                      <th className="text-right font-semibold px-4 py-2.5">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {scans.map((s) => (
                      <tr
                        key={s.id}
                        className="border-b border-border last:border-0 hover:bg-surface-raised transition-colors"
                      >
                        <td className="px-4 py-2.5 text-accent">{s.id.slice(0, 8)}</td>
                        <td className="px-4 py-2.5 text-foreground truncate max-w-[200px]" title={s.origin}>
                          {s.domain}
                        </td>
                        <td className="px-4 py-2.5 text-muted-dim whitespace-nowrap">{relativeTime(s.createdAt)}</td>
                        <td className="px-4 py-2.5 text-muted">{s.pagesCount}</td>
                        <td className="px-4 py-2.5">
                          <FindingsSummary counts={s.severityCounts} total={s.findingsCount} />
                        </td>
                        <td className="px-4 py-2.5">
                          <StatusPill status={s.status} />
                        </td>
                        <td className="px-4 py-2.5">
                          <div className="flex items-center justify-end gap-1.5">
                            <Link href={`/scan/${s.id}`}>
                              <Button variant="outline" size="sm">
                                <ShieldAlert className="h-3 w-3" />
                                View Report
                              </Button>
                            </Link>
                            <Link href={`/requests/${s.id}`}>
                              <Button variant="ghost" size="sm">
                                Requests
                              </Button>
                            </Link>
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
