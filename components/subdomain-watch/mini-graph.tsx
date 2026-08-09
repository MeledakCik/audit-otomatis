"use client";

import { useMemo, useState } from "react";
import { Network } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import type { SubdomainRow } from "@/lib/subdomain-watch/types";

const RISK_COLOR: Record<SubdomainRow["risk"], string> = {
  HIGH: "var(--sev-critical)",
  MEDIUM: "var(--sev-high)",
  LOW: "var(--sev-low)",
  UNKNOWN: "var(--sev-info)",
};

const MAX_NODES = 40;
const SIZE = 640;
const CENTER = SIZE / 2;
const RADIUS = 250;

export function MiniGraph({ domain, rows }: { domain: string; rows: SubdomainRow[] }) {
  const [hovered, setHovered] = useState<string | null>(null);

  const nodes = useMemo(() => {
    const visible = rows.slice(0, MAX_NODES);
    const count = visible.length || 1;
    return visible.map((row, i) => {
      const angle = (2 * Math.PI * i) / count - Math.PI / 2;
      return {
        row,
        x: CENTER + RADIUS * Math.cos(angle),
        y: CENTER + RADIUS * Math.sin(angle),
      };
    });
  }, [rows]);

  if (rows.length === 0) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <Network className="h-3.5 w-3.5 text-accent" /> Graph View
        </CardTitle>
        {rows.length > MAX_NODES && (
          <span className="text-[10px] font-mono text-muted-dim">showing {MAX_NODES} of {rows.length}</span>
        )}
      </CardHeader>
      <CardContent>
        <svg viewBox={`0 0 ${SIZE} ${SIZE}`} className="w-full h-auto max-h-[560px]">
          {nodes.map(({ row, x, y }) => (
            <line
              key={`edge-${row.subdomain}`}
              x1={CENTER}
              y1={CENTER}
              x2={x}
              y2={y}
              stroke={hovered === row.subdomain ? RISK_COLOR[row.risk] : "var(--graph-line)"}
              strokeWidth={hovered === row.subdomain ? 1.6 : 1}
            />
          ))}

          <circle cx={CENTER} cy={CENTER} r={34} fill="var(--surface-raised)" stroke="var(--accent)" strokeWidth={1.5} />
          <text x={CENTER} y={CENTER + 4} textAnchor="middle" fontSize={11} fontFamily="monospace" fill="var(--foreground)">
            {domain.length > 14 ? `${domain.slice(0, 12)}…` : domain}
          </text>

          {nodes.map(({ row, x, y }) => (
            <g
              key={row.subdomain}
              onMouseEnter={() => setHovered(row.subdomain)}
              onMouseLeave={() => setHovered((h) => (h === row.subdomain ? null : h))}
              style={{ cursor: "default" }}
            >
              <circle cx={x} cy={y} r={row.risk === "HIGH" ? 8 : 5.5} fill={RISK_COLOR[row.risk]} opacity={row.risk === "UNKNOWN" ? 0.5 : 0.9} />
              {hovered === row.subdomain && (
                <text
                  x={x}
                  y={y - 12}
                  textAnchor="middle"
                  fontSize={10}
                  fontFamily="monospace"
                  fill="var(--foreground)"
                >
                  {row.subdomain}
                </text>
              )}
            </g>
          ))}
        </svg>
      </CardContent>
    </Card>
  );
}
