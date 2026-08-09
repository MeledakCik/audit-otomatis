"use client";

import { useMemo, useState } from "react";
import { Loader2, ListTree, ShieldAlert, Download, FileWarning } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Badge } from "@/components/ui/badge";
import { RiskBadge } from "./risk-badge";
import { cn } from "@/lib/utils";
import type { SubdomainWatchReport } from "@/lib/subdomain-watch/types";
import { downloadSubdomainWatchAsCsv, downloadDnsCleanupReport } from "@/lib/subdomain-watch/export";

interface ResultsTableProps {
  report: SubdomainWatchReport | null;
  checkedCount: number;
  onCheckMore: () => void;
  checkingMore: boolean;
  hasMoreToCheck: boolean;
}

function StatusCell({ status }: { status: number | null }) {
  if (status === null) return <span className="text-muted-dim">—</span>;
  const color = status >= 500 ? "text-sev-critical" : status >= 400 ? "text-sev-high" : "text-[#38d47a]";
  return <span className={color}>{status}</span>;
}

function RowState({ status }: { status: "pending" | "checking" | "checked" | "error" }) {
  if (status === "checking") {
    return (
      <span className="inline-flex items-center gap-1.5 text-[10px] font-mono text-accent">
        <Loader2 className="h-3 w-3 animate-spin" /> checking
      </span>
    );
  }
  if (status === "pending") {
    return <span className="text-[10px] font-mono text-muted-dim">not checked</span>;
  }
  if (status === "error") {
    return <span className="text-[10px] font-mono text-sev-high">skipped</span>;
  }
  return null;
}

export function ResultsTable({ report, checkedCount, onCheckMore, checkingMore, hasMoreToCheck }: ResultsTableProps) {
  const [tab, setTab] = useState("all");

  const highRiskRows = useMemo(() => report?.rows.filter((r) => r.risk === "HIGH") ?? [], [report]);

  if (!report) {
    return (
      <Card>
        <CardContent className="py-16 text-center text-sm text-muted font-mono">
          Masukkan domain lalu klik Scan untuk mulai mencari subdomain via crt.sh.
        </CardContent>
      </Card>
    );
  }

  const rowsForTab = tab === "takeover" ? highRiskRows : report.rows;

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <ListTree className="h-3.5 w-3.5 text-accent" />
          Subdomain Watch — {report.domain}
        </CardTitle>
        <div className="flex items-center gap-2">
          <Badge>Found {report.totalFound}</Badge>
          <Badge className={highRiskRows.length > 0 ? "text-sev-critical border-sev-critical/40" : ""}>
            {highRiskRows.length} potential takeover
          </Badge>
        </div>
      </CardHeader>

      <CardContent className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <Tabs value={tab} onValueChange={setTab}>
            <TabsList>
              <TabsTrigger value="all">All Subdomains ({report.rows.length})</TabsTrigger>
              <TabsTrigger
                value="takeover"
                className="data-[state=active]:!shadow-[0_0_0_1px_var(--sev-critical)] data-[state=active]:!text-sev-critical data-[state=active]:!bg-sev-critical/15"
              >
                <ShieldAlert className="h-3 w-3" /> Potential Takeover ({highRiskRows.length})
              </TabsTrigger>
            </TabsList>
          </Tabs>

          <div className="flex items-center gap-2">
            <Button size="sm" variant="outline" onClick={() => downloadSubdomainWatchAsCsv(report)}>
              <Download className="h-3.5 w-3.5" /> Export CSV
            </Button>
            <Button size="sm" variant="outline" onClick={() => downloadDnsCleanupReport(report)}>
              <FileWarning className="h-3.5 w-3.5" /> DNS Cleanup Report
            </Button>
          </div>
        </div>

        <div className="text-[11px] font-mono text-muted-dim">
          Checked {checkedCount} / {report.rows.length} subdomain untuk indikasi takeover.
          {hasMoreToCheck && (
            <Button size="sm" variant="ghost" className="ml-2 h-6 px-2" onClick={onCheckMore} disabled={checkingMore}>
              {checkingMore ? (
                <>
                  <Loader2 className="h-3 w-3 animate-spin" /> Checking...
                </>
              ) : (
                "Check next batch"
              )}
            </Button>
          )}
        </div>

        <div className="overflow-x-auto rounded-xl border border-border">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-border text-[10px] uppercase tracking-widest text-muted-dim">
                <th className="text-left px-4 py-2.5 font-semibold">Subdomain</th>
                <th className="text-left px-4 py-2.5 font-semibold">Source</th>
                <th className="text-left px-4 py-2.5 font-semibold">Status</th>
                <th className="text-left px-4 py-2.5 font-semibold">CNAME</th>
                <th className="text-left px-4 py-2.5 font-semibold">Risk</th>
                <th className="text-left px-4 py-2.5 font-semibold">Detail</th>
              </tr>
            </thead>
            <tbody>
              {rowsForTab.length === 0 && (
                <tr>
                  <td colSpan={6} className="px-4 py-8 text-center text-muted">
                    {tab === "takeover" ? "Belum ada indikasi potential takeover. 🎉" : "Tidak ada subdomain."}
                  </td>
                </tr>
              )}
              {rowsForTab.map((row) => (
                <tr
                  key={row.subdomain}
                  className={cn(
                    "border-b border-border/60 hover:bg-surface-raised/60 transition-colors align-top",
                    row.risk === "HIGH" && "bg-sev-critical/[0.04]"
                  )}
                >
                  <td className="px-4 py-2.5 text-foreground whitespace-nowrap">{row.subdomain}</td>
                  <td className="px-4 py-2.5 text-muted-dim">crt.sh</td>
                  <td className="px-4 py-2.5">
                    {row.status === "checked" || row.status === "error" ? (
                      <StatusCell status={row.httpStatus} />
                    ) : (
                      <RowState status={row.status} />
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-[#8be9a8] max-w-[220px] truncate" title={row.cname ?? undefined}>
                    {row.cname ?? "—"}
                  </td>
                  <td className="px-4 py-2.5">
                    <RiskBadge risk={row.risk} />
                  </td>
                  <td className="px-4 py-2.5 text-muted-dim max-w-[360px]">
                    {row.risk === "HIGH" && row.service && (
                      <div className="text-sev-critical">
                        CNAME points to unclaimed {row.service} — vulnerable to takeover! Fix: {row.fix}
                      </div>
                    )}
                    {row.risk !== "HIGH" && row.reason}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}
