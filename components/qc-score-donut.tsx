"use client";

import { PieChart, Pie, Cell } from "recharts";

function colorForScore(score: number): string {
  if (score >= 80) return "#34d399"; // emerald
  if (score >= 50) return "#facc15"; // amber
  return "#fb7185"; // rose
}

export function QcScoreDonut({
  label,
  score,
  loading = false,
}: {
  label: string;
  score: number | null;
  loading?: boolean;
}) {
  const value = score ?? 0;
  const color = score === null ? "#453264" : colorForScore(value);
  const data = [
    { name: "score", value },
    { name: "rest", value: Math.max(0, 100 - value) },
  ];

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative h-[132px] w-[132px]">
        <PieChart width={132} height={132}>
          <Pie
            data={data}
            dataKey="value"
            cx="50%"
            cy="50%"
            innerRadius={44}
            outerRadius={58}
            startAngle={90}
            endAngle={-270}
            stroke="none"
            isAnimationActive={!loading}
          >
            <Cell fill={color} />
            <Cell fill="var(--border)" />
          </Pie>
        </PieChart>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          {score === null ? (
            <span className="text-[10px] text-muted-dim font-mono">{loading ? "…" : "N/A"}</span>
          ) : (
            <>
              <span className="text-2xl font-bold tabular-nums text-foreground">{score}</span>
              <span className="text-[9px] text-muted-dim uppercase tracking-widest">/ 100</span>
            </>
          )}
        </div>
      </div>
      <span className="text-[11px] font-mono uppercase tracking-widest text-muted">{label}</span>
    </div>
  );
}
