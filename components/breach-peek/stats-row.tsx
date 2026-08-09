import { Database, Tags, CalendarClock } from "lucide-react";

export function StatsRow({
  breachCount,
  dataTypeCount,
  firstBreachYear,
}: {
  breachCount: number;
  dataTypeCount: number;
  firstBreachYear: number | null;
}) {
  return (
    <div className="grid grid-cols-3 gap-3">
      <StatCard
        icon={Database}
        label="Exposed Breaches"
        value={breachCount.toString()}
        tone={breachCount > 0 ? "critical" : "clean"}
      />
      <StatCard icon={Tags} label="Data Types Leaked" value={dataTypeCount.toString()} tone="neutral" />
      <StatCard
        icon={CalendarClock}
        label="First Breach Year"
        value={firstBreachYear ? firstBreachYear.toString() : "—"}
        tone="neutral"
      />
    </div>
  );
}

function StatCard({
  icon: Icon,
  label,
  value,
  tone,
}: {
  icon: typeof Database;
  label: string;
  value: string;
  tone: "critical" | "clean" | "neutral";
}) {
  const toneClass =
    tone === "critical" ? "text-sev-critical" : tone === "clean" ? "text-sev-low" : "text-foreground";

  return (
    <div className="rounded-2xl border border-border bg-surface p-4 flex flex-col gap-1.5 shadow-[0_12px_32px_-16px_rgba(0,0,0,0.5)]">
      <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-widest text-muted">
        <Icon className="h-3 w-3" />
        {label}
      </div>
      <div className={`text-3xl font-extrabold tabular-nums ${toneClass}`}>{value}</div>
    </div>
  );
}
