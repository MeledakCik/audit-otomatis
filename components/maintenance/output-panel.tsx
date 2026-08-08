"use client";

import { Download, FileJson, Sparkles, Clock, ShieldOff, ScanSearch } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { FindingCard } from "./finding-card";
import { SeverityIndicator } from "./severity-indicator";
import { downloadReportAsJson, exportReportAsPdf } from "@/lib/maintenance/export";
import type { SecurityReport } from "@/lib/maintenance/types";

interface OutputPanelProps {
  report: SecurityReport | null;
  loading: boolean;
  onToggleStep: (findingId: string, stepIndex: number) => void;
  onMarkPatched: () => void;
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
          Sentinel AI sedang menganalisis input...
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
        <p className="text-sm text-muted">Belum ada laporan.</p>
        <p className="text-xs text-muted-dim">Upload file atau paste kode/log di panel kiri, lalu klik Analyze.</p>
      </CardContent>
    </Card>
  );
}

export function OutputPanel({ report, loading, onToggleStep, onMarkPatched }: OutputPanelProps) {
  if (loading) return <ScanningState />;
  if (!report) return <EmptyState />;

  const timeline = report.timeline;

  return (
    <div className="space-y-4">
      {/* Executive Summary */}
      <Card>
        <CardHeader>
          <CardTitle>
            <Sparkles className="h-3.5 w-3.5 text-accent" /> Executive Summary
            {report.aiEnriched && <span className="text-[9px] normal-case text-accent">· AI-enriched</span>}
          </CardTitle>
          <SeverityIndicator severity={report.overallSeverity} />
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-sm leading-relaxed text-foreground/90">{report.summary}</p>
          <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-muted-dim">
            <span>Source: <span className="text-foreground">{report.sourceName}</span></span>
            <span>·</span>
            <span>{report.findings.length} temuan</span>
            <span>·</span>
            <span>{new Date(report.createdAt).toLocaleString("id-ID")}</span>
          </div>
          <div className="flex flex-wrap gap-2 pt-1">
            <Button size="sm" variant="outline" onClick={() => exportReportAsPdf(report)}>
              <Download className="h-3.5 w-3.5" /> Export PDF
            </Button>
            <Button size="sm" variant="outline" onClick={() => downloadReportAsJson(report)}>
              <FileJson className="h-3.5 w-3.5" /> Export JSON
            </Button>
            <Button size="sm" variant="ghost" onClick={onMarkPatched}>
              Tandai Sudah Dipatch
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Timeline */}
      <Card>
        <CardHeader>
          <CardTitle>
            <Clock className="h-3.5 w-3.5 text-accent" /> Maintenance Log Timeline
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ol className="space-y-2">
            {timeline.map((ev, i) => (
              <li key={i} className="flex items-center gap-3 text-xs font-mono">
                <span className="h-2 w-2 rounded-full bg-accent shrink-0" />
                <span className="text-muted-dim">[{new Date(ev.timestamp).toLocaleString("id-ID")}]</span>
                <span className="text-foreground font-semibold">{ev.label}</span>
              </li>
            ))}
          </ol>
        </CardContent>
      </Card>

      {/* Findings */}
      {report.findings.length === 0 ? (
        <Card>
          <CardContent className="py-10 text-center text-sm text-muted">
            Tidak ada pola berbahaya yang terdeteksi pada input ini. 🎉
          </CardContent>
        </Card>
      ) : (
        report.findings.map((finding, i) => (
          <FindingCard key={finding.id} finding={finding} index={i} onToggleStep={onToggleStep} />
        ))
      )}
    </div>
  );
}
