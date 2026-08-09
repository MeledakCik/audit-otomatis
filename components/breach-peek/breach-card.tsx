import { ShieldAlert, KeyRound, CalendarDays, Users, BadgeCheck } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import type { BreachDetail } from "@/lib/breach-check/types";

export function BreachCard({ breach }: { breach: BreachDetail }) {
  const passwordExposed = breach.dataExposed.some((d) => /password/i.test(d));

  return (
    <div className="rounded-2xl border border-border bg-surface p-4 shadow-[0_12px_32px_-16px_rgba(0,0,0,0.5)]">
      <div className="flex items-start gap-3">
        <div className="h-11 w-11 shrink-0 grid place-items-center rounded-xl bg-surface-raised border border-border-strong text-muted font-bold text-sm uppercase">
          {breach.name.slice(0, 2)}
        </div>

        <div className="min-w-0 flex-1 space-y-1.5">
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-sm font-bold text-foreground truncate">{breach.name}</h3>
            {breach.verified && (
              <span className="inline-flex items-center gap-1 text-[10px] font-semibold text-sev-low">
                <BadgeCheck className="h-3 w-3" /> Verified
              </span>
            )}
            {passwordExposed && (
              <Badge className="border-sev-critical/40 bg-sev-critical/15 text-sev-critical">
                <KeyRound className="h-2.5 w-2.5 mr-1" /> Password exposed
              </Badge>
            )}
          </div>

          <div className="flex flex-wrap items-center gap-3 text-[11px] font-mono text-muted-dim">
            <span className="inline-flex items-center gap-1">
              <CalendarDays className="h-3 w-3" /> {breach.date || "Unknown date"}
            </span>
            <span className="inline-flex items-center gap-1">
              <Users className="h-3 w-3" /> {breach.records ? breach.records.toLocaleString() : "?"} records
            </span>
            {breach.domain && <span>{breach.domain}</span>}
          </div>

          {breach.description && (
            <p className="text-xs text-muted leading-relaxed line-clamp-3">{breach.description}</p>
          )}

          {breach.dataExposed.length > 0 && (
            <div className="flex flex-wrap gap-1.5 pt-1">
              {breach.dataExposed.map((d) => (
                <span
                  key={d}
                  className="inline-flex items-center gap-1 rounded-full border border-border-strong px-2 py-0.5 text-[10px] font-mono text-muted"
                >
                  <ShieldAlert className="h-2.5 w-2.5" /> {d}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
