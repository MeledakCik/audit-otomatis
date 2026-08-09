import { AlertCircle, ShieldAlert } from "lucide-react";
import { StatsRow } from "./stats-row";
import { BreachCard } from "./breach-card";
import { CleanResult } from "./clean-result";
import { ActionChecklist } from "./action-checklist";
import { DomainSummary } from "./domain-summary";
import { LoadingSkeleton } from "./loading-skeleton";
import type { DomainBreachReport, EmailBreachReport } from "@/lib/breach-check/types";

type Result =
  | { mode: "email"; report: EmailBreachReport }
  | { mode: "domain"; report: DomainBreachReport }
  | null;

export function OutputPanel({ loading, error, result }: { loading: boolean; error: string | null; result: Result }) {
  if (loading) return <LoadingSkeleton />;

  if (error) {
    return (
      <div className="rounded-2xl border border-sev-critical/40 bg-sev-critical/10 p-6 flex items-start gap-3">
        <AlertCircle className="h-5 w-5 text-sev-critical shrink-0 mt-0.5" />
        <p className="text-xs font-mono text-sev-critical">{error}</p>
      </div>
    );
  }

  if (!result) {
    return (
      <div className="rounded-2xl border border-dashed border-border p-10 flex flex-col items-center text-center gap-2 text-muted-dim">
        <ShieldAlert className="h-8 w-8" />
        <p className="text-xs font-mono">Enter an email or domain and scan to check for known breaches.</p>
      </div>
    );
  }

  if (result.mode === "email") {
    const { report } = result;
    return (
      <div className="space-y-5">
        <StatsRow
          breachCount={report.breachCount}
          dataTypeCount={report.dataTypesLeaked.length}
          firstBreachYear={report.firstBreachYear}
        />
        {report.clean ? (
          <CleanResult query={report.email} />
        ) : (
          <>
            <div className="space-y-3">
              {report.breaches.map((b) => (
                <BreachCard key={b.name} breach={b} />
              ))}
            </div>
            <ActionChecklist />
          </>
        )}
      </div>
    );
  }

  const { report } = result;
  return (
    <div className="space-y-5">
      <StatsRow
        breachCount={report.combinedBreaches.length}
        dataTypeCount={report.dataTypesLeaked.length}
        firstBreachYear={report.firstBreachYear}
      />
      <DomainSummary
        domain={report.domain}
        probes={report.probes}
        hitCount={report.hitCount}
        totalProbed={report.totalProbed}
      />
      {report.hitCount === 0 ? (
        <CleanResult query={report.domain} />
      ) : (
        <>
          <div className="space-y-3">
            {report.combinedBreaches.map((b) => (
              <BreachCard key={b.name} breach={b} />
            ))}
          </div>
          <ActionChecklist />
        </>
      )}
    </div>
  );
}
