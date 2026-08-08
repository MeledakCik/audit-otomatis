import { cn } from "@/lib/utils";
import type { Severity } from "@/lib/types";
import { SeverityBadge } from "@/components/ui/badge";

/**
 * Wraps the shared SeverityBadge with a blinking glow for CRITICAL, so it
 * stands out immediately in the SIEM-style timeline (bonus request: severity
 * color coding — Critical=blink, High=orange, Medium=yellow, Low=green, all
 * already mapped via the --sev-* theme tokens).
 */
export function SeverityIndicator({ severity, className }: { severity: Severity; className?: string }) {
  return (
    <span className={cn("inline-flex rounded-full", severity === "CRITICAL" && "sentinel-critical-pulse", className)}>
      <SeverityBadge severity={severity} />
    </span>
  );
}
