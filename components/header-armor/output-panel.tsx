"use client";

import { Download, FileJson, Wrench, ShieldOff, ScanSearch, ListChecks } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { ScoreCircle, GradeBadge } from "./score-circle";
import { HeaderCheckRow } from "./header-check-row";
import { downloadHeaderScanAsJson, downloadHardeningKit, exportHeaderScanAsPdf } from "@/lib/header-scan/export";
import type { HeaderScanReport } from "@/lib/header-scan/types";

interface OutputPanelProps {
  report: HeaderScanReport | null;
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
          Membaca response header target (GET only)...
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
        <p className="text-xs text-muted-dim">Masukkan domain di panel kiri, lalu klik Scan Headers.</p>
      </CardContent>
    </Card>
  );
}

export function OutputPanel({ report, loading }: OutputPanelProps) {
  if (loading) return <ScanningState />;
  if (!report) return <EmptyState />;

  const passCount = report.checks.filter((c) => c.pass).length;

  return (
    <div className="space-y-4">
      {/* Grade + Score */}
      <Card>
        <CardContent className="flex flex-col sm:flex-row items-center gap-6 py-8">
          <GradeBadge grade={report.grade} />
          <ScoreCircle score={report.score} grade={report.grade} />
          <div className="flex-1 min-w-0 space-y-1.5 text-center sm:text-left">
            <div className="text-sm font-mono text-muted-dim truncate">Target</div>
            <div className="text-base font-bold font-mono text-foreground truncate">{report.finalUrl}</div>
            <div className="flex flex-wrap items-center justify-center sm:justify-start gap-3 text-[11px] font-mono text-muted-dim pt-1">
              <span>HTTP {report.statusCode}</span>
              <span>·</span>
              <span>
                {passCount}/{report.checks.length} header lolos
              </span>
              <span>·</span>
              <span>{new Date(report.createdAt).toLocaleString("id-ID")}</span>
            </div>
            <div className="flex flex-wrap justify-center sm:justify-start gap-2 pt-2">
              <Button size="sm" variant="outline" onClick={() => exportHeaderScanAsPdf(report)}>
                <Download className="h-3.5 w-3.5" /> Export PDF
              </Button>
              <Button size="sm" variant="outline" onClick={() => downloadHeaderScanAsJson(report)}>
                <FileJson className="h-3.5 w-3.5" /> Export JSON
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Header checks */}
      <Card>
        <CardHeader>
          <CardTitle>
            <ListChecks className="h-3.5 w-3.5 text-accent" /> Header Checks
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-2.5">
          {report.checks.map((c) => (
            <HeaderCheckRow key={c.key} check={c} />
          ))}
        </CardContent>
      </Card>

      {/* Hardening kit */}
      <Card>
        <CardContent className="py-6 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="text-center sm:text-left">
            <div className="text-sm font-semibold text-foreground">Generate Hardening Kit</div>
            <p className="text-xs font-mono text-muted-dim">
              Satu file <span className="text-accent">next.config.js</span> snippet berisi semua header yang masih hilang.
            </p>
          </div>
          <Button onClick={() => downloadHardeningKit(report)}>
            <Wrench className="h-4 w-4" /> Generate Hardening Kit
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
