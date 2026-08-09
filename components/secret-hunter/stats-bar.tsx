import { FileCode2, ShieldAlert, Gauge } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { cn } from "@/lib/utils";
import type { RiskLevel } from "@/lib/secret-hunter/types";

const RISK_STYLE: Record<RiskLevel, string> = {
  HIGH: "text-sev-critical",
  MEDIUM: "text-sev-medium",
  LOW: "text-sev-low",
  CLEAN: "text-[#38d47a]",
};

export function StatsBar({
  filesScanned,
  findingsCount,
  riskLevel,
}: {
  filesScanned: number;
  findingsCount: number;
  riskLevel: RiskLevel;
}) {
  const stats = [
    { label: "Files Scanned", value: filesScanned, icon: FileCode2, className: "text-foreground" },
    { label: "Findings", value: findingsCount, icon: ShieldAlert, className: findingsCount > 0 ? "text-sev-high" : "text-[#38d47a]" },
    { label: "Risk Level", value: riskLevel, icon: Gauge, className: RISK_STYLE[riskLevel] },
  ];

  return (
    <div className="grid grid-cols-3 gap-3">
      {stats.map((s) => (
        <Card key={s.label}>
          <CardContent className="py-4 flex flex-col items-center gap-1 text-center">
            <s.icon className="h-4 w-4 text-muted-dim" />
            <div className={cn("text-xl font-extrabold font-mono tabular-nums", s.className)}>{s.value}</div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-dim">{s.label}</div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}
