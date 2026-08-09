import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { DetectedStack } from "@/lib/stack-fingerprint/types";

const TIER_COLOR: Record<string, string> = {
  header: "bg-[#38d47a]",
  html: "bg-accent",
  jsHint: "bg-sev-medium",
};

function confidenceColor(confidence: number): string {
  if (confidence >= 85) return "bg-[#38d47a]";
  if (confidence >= 70) return "bg-accent";
  return "bg-sev-medium";
}

export function StackCard({ stack }: { stack: DetectedStack }) {
  return (
    <div className="rounded-xl border border-border bg-surface-raised p-3.5 space-y-2.5">
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <span className="h-8 w-8 grid place-items-center rounded-lg border border-border-strong bg-surface text-sm font-bold text-accent shrink-0">
            {stack.icon}
          </span>
          <div className="min-w-0">
            <div className="text-sm font-bold text-foreground truncate">{stack.name}</div>
            <Badge className="mt-0.5">{stack.category}</Badge>
          </div>
        </div>
        <span className="text-sm font-mono font-bold text-foreground shrink-0">{stack.confidence}%</span>
      </div>

      <div className="h-1.5 w-full rounded-full bg-border overflow-hidden">
        <div
          className={cn("h-full rounded-full transition-all", confidenceColor(stack.confidence))}
          style={{ width: `${stack.confidence}%` }}
        />
      </div>

      {stack.version && (
        <div className="text-[10px] font-mono text-muted-dim">
          Version: <span className="text-foreground">{stack.version}</span>
          <span className="block text-muted-dim/70">Version detected from public meta tag</span>
        </div>
      )}

      <ul className="space-y-1">
        {stack.evidence.map((e, i) => (
          <li key={i} className="flex items-start gap-1.5 text-[10px] font-mono text-muted-dim leading-relaxed">
            <span className={cn("h-1.5 w-1.5 rounded-full mt-1 shrink-0", TIER_COLOR[e.tier])} />
            <span className="truncate">{e.label}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}
