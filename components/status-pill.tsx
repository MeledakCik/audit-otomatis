import { cn } from "@/lib/utils";
import type { ScanStatus } from "@/lib/types";

const LABELS: Record<ScanStatus | "connecting", string> = {
  connecting: "connecting…",
  queued: "queued",
  crawling: "crawling",
  analyzing_js: "analyzing js",
  scanning_secrets: "scanning secrets",
  fingerprinting_libraries: "fingerprinting libs",
  deep_audit: "deep passive audit",
  testing: "testing",
  blocked_cloudflare: "blocked",
  done: "done",
  error: "error",
};

const STYLES: Record<ScanStatus | "connecting", string> = {
  connecting: "text-muted border-border-strong bg-surface-raised",
  queued: "text-muted border-border-strong bg-surface-raised",
  crawling: "text-accent border-accent/50 bg-accent/10",
  analyzing_js: "text-accent border-accent/50 bg-accent/10",
  scanning_secrets: "text-accent border-accent/50 bg-accent/10",
  fingerprinting_libraries: "text-accent border-accent/50 bg-accent/10",
  deep_audit: "text-accent border-accent/50 bg-accent/10",
  testing: "text-accent border-accent/50 bg-accent/10",
  blocked_cloudflare: "text-sev-high border-sev-high/50 bg-sev-high/10",
  done: "text-accent-fg border-transparent bg-gradient-accent shadow-[0_0_16px_-4px_var(--accent)]",
  error: "text-sev-critical border-sev-critical/50 bg-sev-critical/10",
};

export function StatusPill({ status }: { status: ScanStatus | "connecting" }) {
  const isActive = [
    "connecting",
    "queued",
    "crawling",
    "analyzing_js",
    "scanning_secrets",
    "fingerprinting_libraries",
    "deep_audit",
    "testing",
  ].includes(status);
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
