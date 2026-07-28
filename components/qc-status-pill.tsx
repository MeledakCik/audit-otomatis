import { cn } from "@/lib/utils";
import type { QcStatus } from "@/lib/qc-types";

const LABELS: Record<QcStatus | "connecting", string> = {
  connecting: "connecting…",
  queued: "queued",
  crawling: "crawling",
  running_seo: "running seo",
  running_perf: "running perf",
  running_content: "running content",
  done: "done",
  error: "error",
};

const STYLES: Record<QcStatus | "connecting", string> = {
  connecting: "text-muted border-border-strong bg-surface-raised",
  queued: "text-muted border-border-strong bg-surface-raised",
  crawling: "text-accent border-accent/50 bg-accent/10",
  running_seo: "text-accent border-accent/50 bg-accent/10",
  running_perf: "text-accent border-accent/50 bg-accent/10",
  running_content: "text-accent border-accent/50 bg-accent/10",
  done: "text-accent-fg border-transparent bg-gradient-accent shadow-[0_0_16px_-4px_var(--accent)]",
  error: "text-sev-critical border-sev-critical/50 bg-sev-critical/10",
};

export function QcStatusPill({ status }: { status: QcStatus | "connecting" }) {
  const isActive = ["connecting", "queued", "crawling", "running_seo", "running_perf", "running_content"].includes(
    status
  );
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-[10px] font-bold uppercase tracking-widest",
        STYLES[status]
      )}
    >
      <span className={cn("h-1.5 w-1.5 rounded-full bg-current", isActive && "cursor-blink")} />
      {LABELS[status]}
    </span>
  );
}
