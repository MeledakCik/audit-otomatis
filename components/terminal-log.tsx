"use client";

import { useEffect, useRef } from "react";
import { cn } from "@/lib/utils";
import type { ScanLogEvent } from "@/lib/types";

const TYPE_COLOR: Record<ScanLogEvent["type"], string> = {
  log: "text-slate-400",
  status: "text-purple-300",
  finding: "text-amber-400",
  done: "text-emerald-400",
  error: "text-rose-400",
  blocked: "text-rose-400",
  endpoints: "text-cyan-300",
};

const TYPE_ROW_HIGHLIGHT: Record<ScanLogEvent["type"], string> = {
  log: "",
  status: "bg-purple-500/10 border-l-2 border-purple-500 rounded-r-md px-2 -mx-2 py-0.5",
  finding: "bg-amber-500/10 border-l-2 border-amber-500 rounded-r-md px-2 -mx-2 py-0.5",
  done: "bg-emerald-500/10 border-l-2 border-emerald-500 rounded-r-md px-2 -mx-2 py-0.5",
  error: "bg-rose-500/10 border-l-2 border-rose-500 rounded-r-md px-2 -mx-2 py-0.5",
  blocked: "bg-rose-500/10 border-l-2 border-rose-500 rounded-r-md px-2 -mx-2 py-0.5",
  endpoints: "bg-cyan-500/10 border-l-2 border-cyan-500 rounded-r-md px-2 -mx-2 py-0.5",
};

function timeLabel(ts: number): string {
  const d = new Date(ts);
  return d.toTimeString().slice(0, 8);
}

function lineText(evt: ScanLogEvent): string {
  switch (evt.type) {
    case "status":
      return `→ status: ${evt.status}`;
    case "finding":
      return `⚠ finding [${evt.finding?.severity}] ${evt.finding?.title}`;
    case "done":
      return `✓ ${evt.message ?? "done"}`;
    case "error":
      return `✗ ${evt.message ?? "error"}`;
    case "blocked":
      return `⛔ ${evt.message ?? "blocked"}`;
    case "endpoints": {
      const n = evt.endpoints?.length ?? 0;
      const post = evt.endpoints?.filter((e) => e.method === "POST").length ?? 0;
      return `≡ ${n} link/endpoint ditemukan (${post} POST) — lihat panel Endpoints`;
    }
    default:
      return evt.message ?? "";
  }
}

export function TerminalLog({ logs }: { logs: ScanLogEvent[] }) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [logs.length]);

  return (
    <div className="h-full flex flex-col overflow-hidden bg-[#0a0710] text-[11px] font-mono leading-relaxed">
      <div className="flex-1 overflow-y-auto thin-scroll px-4 py-3 flex flex-col gap-1">
        {logs.length === 0 && (
          <p className="text-slate-500 italic">menunggu koneksi stream…</p>
        )}
        {logs.map((evt, i) => (
          <div key={i} className={cn("flex items-start gap-3 py-0.5", TYPE_ROW_HIGHLIGHT[evt.type])}>
            <span className="text-slate-500 shrink-0 select-none">{timeLabel(evt.timestamp)}</span>
            <span className={cn("whitespace-pre-wrap break-all flex-1 min-w-0", TYPE_COLOR[evt.type])}>
              {lineText(evt)}
            </span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
    </div>
  );
}