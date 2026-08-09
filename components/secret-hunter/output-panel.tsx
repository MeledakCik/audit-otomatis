"use client";

import { ScanSearch, ShieldOff } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { StatsBar } from "./stats-bar";
import { FindingsTable } from "./findings-table";
import { RiskSummary } from "./risk-summary";
import type { SecretHuntReport } from "@/lib/secret-hunter/types";

interface OutputPanelProps {
  report: SecretHuntReport | null;
  loading: boolean;
}

function ScanningState() {
  return (
    <Card>
      <CardContent className="py-16">
        <div className="relative mx-auto h-40 w-full max-w-md overflow-hidden rounded-xl border border-accent/30 bg-[#0a0710]">
          <div className="sentinel-scan-line absolute left-0 right-0 h-px bg-accent shadow-[0_0_12px_2px_var(--accent)]" />
          <div className="absolute inset-0 grid place-items-center">
            <ScanSearch className="h-8 w-8 text-accent/70 animate-pulse" />
          </div>
        </div>
        <p className="mt-6 text-center text-xs font-mono uppercase tracking-widest text-muted animate-pulse">
          Crawling JS same-origin & regex-scanning teksnya...
        </p>
      </CardContent>
    </Card>
  );
}

function EmptyState() {
  return (
    <Card>
      <CardContent className="py-20 text-center space-y-2">
        <ShieldOff className="h-8 w-8 text-muted-dim mx-auto" />
        <p className="text-sm text-muted">Belum ada hasil scan.</p>
        <p className="text-xs text-muted-dim">Masukkan domain di panel kiri, lalu klik Scan for Secrets.</p>
      </CardContent>
    </Card>
  );
}

export function OutputPanel({ report, loading }: OutputPanelProps) {
  if (loading) return <ScanningState />;
  if (!report) return <EmptyState />;

  return (
    <div className="space-y-4">
      <StatsBar filesScanned={report.filesScanned} findingsCount={report.findings.length} riskLevel={report.riskLevel} />
      <FindingsTable findings={report.findings} />
      <RiskSummary report={report} />
    </div>
  );
}
