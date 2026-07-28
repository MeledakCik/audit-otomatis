import { cn } from "@/lib/utils";
import type { QcIssue } from "@/lib/qc-types";

const LEVEL_STYLES: Record<QcIssue["level"], string> = {
  critical: "text-sev-critical border-sev-critical/40 bg-sev-critical/15",
  warning: "text-sev-high border-sev-high/40 bg-sev-high/15",
  info: "text-sev-info border-sev-info/40 bg-sev-info/15",
};

export function QcIssueList({ issues }: { issues: QcIssue[] }) {
  if (issues.length === 0) {
    return <p className="text-xs text-muted-dim italic px-1 py-2">Tidak ada issue ditemukan. 🎉</p>;
  }

  return (
    <ul className="flex flex-col gap-1.5">
      {issues.map((issue, i) => (
        <li key={i} className="flex items-start gap-2.5 px-1 py-1">
          <span
            className={cn(
              "shrink-0 mt-0.5 inline-flex items-center rounded-full border px-2 py-0.5 text-[9px] font-bold uppercase tracking-widest",
              LEVEL_STYLES[issue.level]
            )}
          >
            {issue.level}
          </span>
          <span className="text-xs text-foreground leading-relaxed">{issue.msg}</span>
        </li>
      ))}
    </ul>
  );
}
