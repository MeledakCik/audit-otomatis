import * as React from "react";
import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/types";

const SEVERITY_STYLES: Record<Severity, string> = {
  CRITICAL: "text-sev-critical border-sev-critical/25 bg-sev-critical/10",
  HIGH: "text-sev-high border-sev-high/25 bg-sev-high/10",
  MEDIUM: "text-sev-medium border-sev-medium/25 bg-sev-medium/10",
  LOW: "text-sev-low border-sev-low/25 bg-sev-low/10",
  INFO: "text-sev-info border-sev-info/25 bg-sev-info/10",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-semibold tracking-wide uppercase shrink-0",
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
        "inline-flex items-center rounded-md border border-border px-2 py-0.5 text-[11px] font-medium uppercase tracking-wide text-muted",
        className
      )}
    >
      {children}
    </span>
  );
}
