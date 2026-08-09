import { cn } from "@/lib/utils";
import type { TakeoverRisk } from "@/lib/subdomain-watch/types";

const RISK_STYLES: Record<TakeoverRisk, string> = {
  HIGH: "text-sev-critical border-sev-critical/40 bg-sev-critical/15",
  MEDIUM: "text-sev-high border-sev-high/40 bg-sev-high/15",
  LOW: "text-sev-low border-sev-low/40 bg-sev-low/15",
  UNKNOWN: "text-sev-info border-sev-info/40 bg-sev-info/15",
};

export function RiskBadge({ risk }: { risk: TakeoverRisk }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[10px] font-bold tracking-widest uppercase shrink-0",
        RISK_STYLES[risk]
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current shrink-0" />
      {risk}
    </span>
  );
}
