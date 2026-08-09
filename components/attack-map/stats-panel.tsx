import { Boxes, Zap, ListChecks, ExternalLink } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import type { AttackMapStats } from "@/lib/attack-map/types";

export function StatsPanel({ stats }: { stats: AttackMapStats }) {
  const items = [
    { label: "Total Nodes", value: stats.totalNodes, icon: Boxes, color: "#c084fc" },
    { label: "APIs Found", value: stats.apiCount, icon: Zap, color: "#ff4d6d" },
    { label: "Forms", value: stats.formCount, icon: ListChecks, color: "#e93ee8" },
    { label: "Externals", value: stats.externalCount, icon: ExternalLink, color: "#9ca3af" },
  ];

  return (
    <Card className="w-56 shrink-0">
      <CardContent className="p-3 space-y-2">
        <div className="text-[10px] font-mono uppercase tracking-widest text-muted-dim px-1">Stats</div>
        {items.map((it) => (
          <div key={it.label} className="flex items-center justify-between rounded-lg bg-surface-raised px-2.5 py-2">
            <div className="flex items-center gap-2 text-[11px] font-mono text-muted-dim">
              <it.icon className="h-3.5 w-3.5" style={{ color: it.color }} />
              {it.label}
            </div>
            <div className="text-sm font-extrabold font-mono tabular-nums text-foreground">{it.value}</div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
