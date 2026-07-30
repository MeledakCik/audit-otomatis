"use client";

import { useEffect } from "react";
import Link from "next/link";
import { useQcStream } from "@/lib/use-qc-stream";
import { QcStatusPill } from "@/components/qc-status-pill";
import { QcTerminalLog } from "@/components/qc-terminal-log";
import { QcScoreDonut } from "@/components/qc-score-donut";
import { QcIssueList } from "@/components/qc-issue-list";
import { Button } from "@/components/ui/button";
import { Card, CardHeader, CardTitle } from "@/components/ui/card";
import type { QcModulesSelection } from "@/lib/qc-types";

export function QcDashboard({
  qcId,
  domain,
  modules,
}: {
  qcId: string;
  domain: string;
  modules: QcModulesSelection;
}) {
  const { connect, status, logs, result, errorMessage } = useQcStream();

  useEffect(() => {
    connect(qcId);
  }, [qcId, connect]);

  const isTerminal = status === "done" || status === "error";
  const isLoading = !isTerminal;

  return (
    <div className="flex flex-1 flex-col">
      <header className="border-b border-border bg-surface/60 backdrop-blur-sm sticky top-0 z-10">
        <div className="mx-auto max-w-5xl px-4 sm:px-6 py-4 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <Link
              href="/qc"
              className="flex items-center justify-center h-8 w-8 rounded-lg border border-white/10 bg-white/[0.02] hover:bg-white/[0.06] text-slate-300 transition-colors shrink-0"
              title="Kembali ke QC"
            >
              <span className="text-sm">←</span>
            </Link>
            <Link
              href="/qc"
              className="flex items-center gap-2.5 group min-w-0"
            >
              <span className="h-2 w-2 rounded-full bg-accent shrink-0 shadow-[0_0_8px_1px_var(--accent)] animate-pulse" />
              <span className="text-sm font-bold tracking-wide uppercase text-gradient-accent group-hover:brightness-125 transition-all truncate">
                QC OTOMATIS
              </span>
            </Link>
          </div>
          <div className="flex items-center gap-2 sm:gap-3 min-w-0">
            <span className="text-xs text-muted truncate max-w-[40vw] sm:max-w-none">
              {domain}
            </span>
            <QcStatusPill status={status} />
          </div>
        </div>
      </header>

      <main className="flex-1 mx-auto w-full max-w-5xl px-4 sm:px-6 py-5 sm:py-6 flex flex-col gap-4">
        {status === "error" && errorMessage && (
          <div className="rounded-xl border border-sev-high/40 bg-sev-high/10 px-4 py-3 text-xs text-sev-high leading-relaxed animate-fade-up">
            <span className="font-bold uppercase tracking-widest block mb-1">
              QC dihentikan
            </span>
            {errorMessage}
          </div>
        )}

        <Card className="animate-fade-up">
          <CardHeader>
            <CardTitle>
              Skor QC{" "}
              {result.overallScore !== undefined
                ? `— Keseluruhan ${result.overallScore}/100`
                : ""}
            </CardTitle>
            <div className="flex items-center gap-2">
              <a href={`/api/qc/${qcId}/export`} download>
                <Button variant="outline" size="sm" disabled={!isTerminal}>
                  export .md
                </Button>
              </a>
            </div>
          </CardHeader>
          <div className="flex flex-wrap items-center justify-around gap-6 px-6 py-6">
            {modules.seo && (
              <QcScoreDonut
                label="SEO"
                score={result.seo?.score ?? null}
                loading={isLoading && !result.seo}
              />
            )}
            {modules.perf && (
              <QcScoreDonut
                label="Performance"
                score={result.perf?.score ?? null}
                loading={isLoading && !result.perf}
              />
            )}
            {modules.content && (
              <QcScoreDonut
                label="Content/Link"
                score={result.content?.score ?? null}
                loading={isLoading && !result.content}
              />
            )}
          </div>
        </Card>

        <div
          className="grid lg:grid-cols-2 gap-4 animate-fade-up"
          style={{ "--delay": "60ms" } as React.CSSProperties}
        >
          {modules.seo && (
            <Card className="flex flex-col min-h-0">
              <CardHeader>
                <CardTitle>QC SEO Otomatis</CardTitle>
                {result.seo && (
                  <span className="text-[10px] text-muted-dim">
                    {result.seo.issues.length} issue
                  </span>
                )}
              </CardHeader>
              <div className="overflow-y-auto thin-scroll max-h-[40vh] px-3 py-2">
                {result.seo ? (
                  <QcIssueList issues={result.seo.issues} />
                ) : (
                  <p className="text-xs text-muted-dim italic px-1 py-2">
                    {isLoading ? "Sedang berjalan…" : "Modul tidak dijalankan."}
                  </p>
                )}
              </div>
            </Card>
          )}

          {modules.perf && (
            <Card className="flex flex-col min-h-0">
              <CardHeader>
                <CardTitle>QC Performance</CardTitle>
                {result.perf && (
                  <span className="text-[10px] text-muted-dim">
                    {result.perf.metrics.source === "pagespeed"
                      ? "PageSpeed Insights"
                      : "fallback manual"}
                  </span>
                )}
              </CardHeader>
              <div className="overflow-y-auto thin-scroll max-h-[40vh] px-3 py-2 flex flex-col gap-3">
                {result.perf ? (
                  <>
                    <div className="grid grid-cols-2 gap-2 text-[11px] font-mono px-1">
                      <MetricCell label="LCP" value={result.perf.metrics.lcp} />
                      <MetricCell label="CLS" value={result.perf.metrics.cls} />
                      <MetricCell label="FCP" value={result.perf.metrics.fcp} />
                      <MetricCell label="TBT" value={result.perf.metrics.tbt} />
                      <MetricCell
                        label="Size"
                        value={
                          result.perf.metrics.sizeBytes
                            ? `${(result.perf.metrics.sizeBytes / 1024).toFixed(0)} KB`
                            : null
                        }
                      />
                      <MetricCell
                        label="Modern img"
                        value={fmtBool(result.perf.metrics.modernImageFormat)}
                      />
                    </div>
                    {result.perf.metrics.lcpElement && (
                      <div className="rounded-lg border border-sev-high/30 bg-sev-high/[0.06] px-3 py-2">
                        <div className="text-[9px] uppercase tracking-widest text-muted-dim mb-1">
                          Elemen Penyebab LCP
                        </div>
                        {result.perf.metrics.lcpElement.selector && (
                          <div className="text-[11px] font-mono text-sev-high mb-1">
                            {result.perf.metrics.lcpElement.selector}
                          </div>
                        )}
                        {result.perf.metrics.lcpElement.snippet && (
                          <code className="block text-[10px] font-mono text-muted break-all whitespace-pre-wrap">
                            {result.perf.metrics.lcpElement.snippet}
                          </code>
                        )}
                        {result.perf.metrics.lcpElement.isLazyLoaded && (
                          <div className="mt-1.5 text-[10px] text-sev-high">
                            ⚠ Elemen ini kena loading=&quot;lazy&quot; —
                            sebaiknya di-load prioritas tinggi.
                          </div>
                        )}
                      </div>
                    )}
                    <QcIssueList issues={result.perf.issues} />
                  </>
                ) : (
                  <p className="text-xs text-muted-dim italic px-1 py-2">
                    {isLoading ? "Sedang berjalan…" : "Modul tidak dijalankan."}
                  </p>
                )}
              </div>
            </Card>
          )}
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {modules.content && (
            <Card
              className="flex flex-col min-h-0 animate-fade-up"
              style={{ "--delay": "120ms" } as React.CSSProperties}
            >
              <CardHeader>
                <CardTitle>QC Content / Link</CardTitle>
                {result.content && (
                  <span className="text-[10px] text-muted-dim">
                    {result.content.checked.linksChecked} link dicek ·{" "}
                    {result.content.brokenLinks.length} broken
                  </span>
                )}
              </CardHeader>
              {result.content ? (
                <div className="grid lg:grid-cols-2 gap-3 px-3 py-2">
                  <div className="min-h-0">
                    <div className="text-[10px] uppercase tracking-widest text-muted-dim px-1 pb-1.5">
                      Broken Links ({result.content.brokenLinks.length})
                    </div>
                    <div className="overflow-y-auto thin-scroll max-h-[30vh] flex flex-col gap-1">
                      {result.content.brokenLinks.length === 0 ? (
                        <p className="text-xs text-muted-dim italic px-1 py-2">
                          Tidak ada broken link. 🎉
                        </p>
                      ) : (
                        result.content.brokenLinks.map((link, i) => (
                          <div
                            key={i}
                            className="text-[11px] font-mono text-sev-high break-all px-2 py-1 rounded bg-sev-high/10 border border-sev-high/20"
                          >
                            {link}
                          </div>
                        ))
                      )}
                    </div>
                  </div>
                  <div className="min-h-0">
                    <div className="text-[10px] uppercase tracking-widest text-muted-dim px-1 pb-1.5">
                      A11y Issues
                    </div>
                    <div className="overflow-y-auto thin-scroll max-h-[30vh]">
                      <QcIssueList issues={result.content.a11yIssues} />
                    </div>
                  </div>
                </div>
              ) : (
                <p className="text-xs text-muted-dim italic px-4 py-3">
                  {isLoading ? "Sedang berjalan…" : "Modul tidak dijalankan."}
                </p>
              )}
            </Card>
          )}

          <Card
            className={`flex flex-col min-h-0 animate-fade-up ${modules.content ? "" : "md:col-span-2"}`}
            style={{ "--delay": "180ms" } as React.CSSProperties}
          >
            <CardHeader>
              <CardTitle>Log Aktivitas</CardTitle>
              <span className="text-[10px] text-muted-dim">
                {logs.length} event
              </span>
            </CardHeader>
            <div className="h-[30vh]">
              <QcTerminalLog logs={logs} />
            </div>
          </Card>
        </div>
      </main>
    </div>
  );
}

function MetricCell({ label, value }: { label: string; value: string | null }) {
  return (
    <div className="rounded-lg border border-border bg-surface-raised px-2.5 py-1.5">
      <div className="text-[9px] uppercase tracking-widest text-muted-dim">
        {label}
      </div>
      <div className="text-foreground">{value ?? "-"}</div>
    </div>
  );
}

function fmtBool(v: boolean | null): string {
  if (v === null) return "-";
  return v ? "ya" : "tidak";
}
