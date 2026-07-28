import * as React from "react";
import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/types";

const SEVERITY_STYLES: Record<Severity, string> = {
  CRITICAL: "text-sev-critical border-sev-critical/40 bg-sev-critical/15",
  HIGH: "text-sev-high border-sev-high/40 bg-sev-high/15",
  MEDIUM: "text-sev-medium border-sev-medium/40 bg-sev-medium/15",
  LOW: "text-sev-low border-sev-low/40 bg-sev-low/15",
  INFO: "text-sev-info border-sev-info/40 bg-sev-info/15",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[10px] font-bold tracking-widest uppercase shrink-0",
        SEVERITY_STYLES[severity]
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current shrink-0" />
      {severity}
    </span>
  );
}

export function Badge({
  className,
  children,
}: {
  className?: string;
  children: React.ReactNode;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border border-border-strong px-2.5 py-0.5 text-[10px] font-medium uppercase tracking-widest text-muted",
        className
      )}
    >
      {children}
    </span>
  );
}
