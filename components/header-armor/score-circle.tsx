import type { Grade } from "@/lib/header-scan/types";
import { cn } from "@/lib/utils";

const GRADE_COLOR: Record<Grade, string> = {
  "A+": "#38d47a",
  A: "#38d47a",
  B: "#38bdf8",
  C: "#ffcc33",
  D: "#ff8a2b",
  F: "#ff4d6d",
};

export function ScoreCircle({ score, grade }: { score: number; grade: Grade }) {
  const radius = 54;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = GRADE_COLOR[grade];

  return (
    <div className="relative h-36 w-36 shrink-0">
      <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
        <circle cx="60" cy="60" r={radius} fill="none" stroke="var(--border-strong)" strokeWidth="10" opacity={0.35} />
        <circle
          cx="60"
          cy="60"
          r={radius}
          fill="none"
          stroke={color}
          strokeWidth="10"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ filter: `drop-shadow(0 0 6px ${color}80)`, transition: "stroke-dashoffset 0.6s ease" }}
        />
      </svg>
      <div className="absolute inset-0 grid place-items-center">
        <div className="text-center">
          <div className="text-3xl font-extrabold font-mono tabular-nums text-foreground">{score}</div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-dim">/ 100</div>
        </div>
      </div>
    </div>
  );
}

export function GradeBadge({ grade }: { grade: Grade }) {
  const color = GRADE_COLOR[grade];
  return (
    <div
      className={cn(
        "grid place-items-center h-24 w-24 rounded-2xl border-2 shrink-0 font-mono font-extrabold text-3xl"
      )}
      style={{
        color,
        borderColor: `${color}66`,
        background: `${color}14`,
        boxShadow: `0 0 24px -6px ${color}80`,
      }}
    >
      {grade}
    </div>
  );
}
