import { AlertTriangle } from "lucide-react";

export function RiskBanner({ highlights }: { highlights: string[] }) {
  if (highlights.length === 0) return null;
  return (
    <div className="flex flex-wrap items-start gap-2 rounded-xl border border-sev-high/30 bg-sev-high/5 px-4 py-2.5">
      <AlertTriangle className="h-4 w-4 text-sev-high shrink-0 mt-0.5" />
      <div className="flex flex-wrap gap-x-4 gap-y-1 text-[11px] font-mono text-foreground/90">
        {highlights.map((h, i) => (
          <span key={i}>{h}</span>
        ))}
      </div>
    </div>
  );
}
