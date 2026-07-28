"use client";

import { useEffect, useRef, useState, useMemo } from "react";
import Link from "next/link";
import type { GraphData, GraphNode, ScanStatus } from "@/lib/types";
import { ExternalLink, LayoutGrid, Network } from "lucide-react";

const COLORS: Record<GraphNode["type"], string> = {
  page: "#22c55e",
  js: "#3b82f6",
  endpoint: "#ef4444",
};

const COL_X: Record<GraphNode["type"], number> = {
  page: 80,
  js: 420,
  endpoint: 760,
};
const ROW_H = 34;
const MAX_PER_COL = 45;
const POLL_MS = 2500;

const TERMINAL: (ScanStatus | "connecting")[] = [
  "done",
  "error",
  "blocked_cloudflare",
];

export function GraphView({
  scanId,
  status,
}: {
  scanId: string;
  status: ScanStatus | "connecting";
}) {
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [hoverId, setHoverId] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const active = status !== "queued" && status !== "connecting";

  useEffect(() => {
    if (!active) return;
    let cancelled = false;

    async function fetchGraph() {
      try {
        const res = await fetch(`/api/scan/${scanId}/graph`, {
          cache: "no-store",
        });
        const data = await res.json();
        if (!cancelled) {
          setGraph({
            nodes: data.nodes || [],
            edges: data.edges || [],
          });
        }
      } catch {
        if (!cancelled) setError("Gagal memuat graph.json");
      }
    }

    fetchGraph();

    if (!TERMINAL.includes(status)) {
      timerRef.current = setInterval(fetchGraph, POLL_MS);
    }

    return () => {
      cancelled = true;
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [scanId, active, status]);

  const byType = useMemo(() => {
    const acc: Record<GraphNode["type"], GraphNode[]> = {
      page: [],
      js: [],
      endpoint: [],
    };
    if (!graph) return acc;
    for (const n of graph.nodes) {
      if (acc[n.type]) acc[n.type].push(n);
    }
    return acc;
  }, [graph]);

  if (!active) return null;
  if (error)
    return (
      <div className="px-4 py-6 text-xs text-red-400 bg-red-950/20 rounded-lg border border-red-900/50">
        {error}
      </div>
    );
  if (!graph || graph.nodes.length === 0) {
    return (
      <div className="px-6 py-12 text-center text-xs text-zinc-500 bg-zinc-900/40 rounded-xl border border-zinc-800/80">
        Belum ada data graph. Peta relasi muncul setelah tahap crawling/analisis
        JS berjalan.
      </div>
    );
  }

  const positions = new Map<string, { x: number; y: number }>();
  (["page", "js", "endpoint"] as const).forEach((type) => {
    byType[type].slice(0, MAX_PER_COL).forEach((n, i) => {
      positions.set(n.id, { x: COL_X[type], y: 40 + i * ROW_H });
    });
  });

  const height = Math.max(
    250,
    (Math.max(byType.page.length, byType.js.length, byType.endpoint.length, 1) +
      1) *
      ROW_H +
      50,
  );

  const truncated = (label: string, max = 38) =>
    label.length > max ? label.slice(0, max - 1) + "…" : label;

  const visibleEdges = (graph.edges || []).filter(
    (e) => positions.has(e.from) && positions.has(e.to),
  );

  return (
    <div className="flex flex-col gap-4 w-full animate-fade-in font-sans">
      <div className="flex flex-col xl:flex-row xl:items-center justify-between gap-4 bg-[#0b0f19]/85 border border-zinc-800/80 p-5 rounded-2xl shadow-xl backdrop-blur-md">
        <div className="flex flex-wrap items-center gap-2.5">
          <Link
            href={`/scan/${scanId}/nodes`}
            className="inline-flex items-center gap-2 bg-emerald-950/40 hover:bg-emerald-900/50 border border-emerald-500/40 px-3.5 py-2 rounded-xl text-xs font-mono font-medium text-emerald-300 transition-colors shadow-sm"
          >
            <LayoutGrid className="w-3.5 h-3.5 text-emerald-400" /> LIHAT
            SELENGKAPNYA
          </Link>
        </div>
      </div>

      {/* Tampilan SVG Graph Utama di Dashboard */}
      <div className="flex flex-col rounded-xl border border-zinc-800/80 bg-zinc-950/60 shadow-xl overflow-hidden backdrop-blur-md">
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 border-b border-zinc-800/80 bg-zinc-900/40">
          <div className="flex items-center gap-5 text-xs font-medium text-zinc-400">
            <Legend
              color={COLORS.page}
              label={`Pages (${byType.page.length})`}
            />
            <Legend
              color={COLORS.js}
              label={`JS Bundles (${byType.js.length})`}
            />
            <Legend
              color={COLORS.endpoint}
              label={`Endpoints (${byType.endpoint.length})`}
            />
          </div>
          <div className="text-xs font-mono text-zinc-500 bg-zinc-900 px-2.5 py-1 rounded-md border border-zinc-800">
            Total Relasi:{" "}
            <span className="text-zinc-200 font-semibold">
              {visibleEdges.length}
            </span>
          </div>
        </div>

        <div className="overflow-auto thin-scroll max-h-[50vh] px-4 py-4">
          {graph.nodes.length > 0 && visibleEdges.length === 0 && (
            <div className="mb-3 p-2.5 bg-amber-950/30 border border-amber-900/50 rounded-lg text-[11px] text-amber-400 font-mono">
              ⚠️ Node ditemukan ({graph.nodes.length}), tetapi relasi (edges)
              belum terbentuk sempurna oleh backend.
            </div>
          )}
          <svg
            width={860}
            height={height}
            className="min-w-[860px] animate-fade-in select-none"
          >
            <defs>
              <filter id="glow" x="-20%" y="-20%" width="140%" height="140%">
                <feGaussianBlur stdDeviation="3" result="blur" />
                <feComposite in="SourceGraphic" in2="blur" operator="over" />
              </filter>
            </defs>

            {visibleEdges.map((e, i) => {
              const from = positions.get(e.from);
              const to = positions.get(e.to);
              if (!from || !to) return null;

              const isConnected =
                hoverId === e.from ||
                hoverId === e.to ||
                selectedId === e.from ||
                selectedId === e.to;

              return (
                <path
                  key={i}
                  d={`M ${from.x + 6} ${from.y} C ${(from.x + to.x) / 2} ${from.y}, ${(from.x + to.x) / 2} ${to.y}, ${to.x - 6} ${to.y}`}
                  fill="none"
                  stroke={isConnected ? "#38bdf8" : "rgba(113, 113, 122, 0.25)"}
                  strokeWidth={isConnected ? 2 : 1}
                  filter={isConnected ? "url(#glow)" : undefined}
                  className="transition-all duration-200"
                />
              );
            })}

            {(["page", "js", "endpoint"] as const).map((type) =>
              byType[type].slice(0, MAX_PER_COL).map((n) => {
                const pos = positions.get(n.id);
                if (!pos) return null;

                const isHovered = hoverId === n.id;
                const isSelected = selectedId === n.id;

                return (
                  <g
                    key={n.id}
                    transform={`translate(${pos.x},${pos.y})`}
                    onMouseEnter={() => setHoverId(n.id)}
                    onMouseLeave={() => setHoverId(null)}
                    onClick={() =>
                      setSelectedId(selectedId === n.id ? null : n.id)
                    }
                    className="cursor-pointer group"
                  >
                    <circle
                      r={isHovered || isSelected ? 6 : 4.5}
                      fill={COLORS[type]}
                      className="transition-all duration-150"
                      style={{
                        filter: isHovered
                          ? "drop-shadow(0 0 6px currentColor)"
                          : undefined,
                      }}
                    />
                    <text
                      x={12}
                      y={4.5}
                      fontSize={11}
                      fill={isHovered || isSelected ? "#f4f4f5" : "#a1a1aa"}
                      fontFamily="ui-monospace, monospace"
                      className="transition-colors duration-150 font-medium"
                    >
                      {truncated(n.label)}
                      <title>{n.label}</title>
                    </text>
                  </g>
                );
              }),
            )}
          </svg>
        </div>
      </div>
    </div>
  );
}

function Legend({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-2">
      <span
        className="h-2.5 w-2.5 rounded-full shadow-sm"
        style={{ backgroundColor: color }}
      />
      <span className="text-zinc-300 font-medium">{label}</span>
    </span>
  );
}
