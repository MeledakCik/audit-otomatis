"use client";

import { useEffect, useRef } from "react";
import { cn } from "@/lib/utils";
import type { QcLogEvent } from "@/lib/qc-types";

const TYPE_COLOR: Record<QcLogEvent["type"], string> = {
  log: "text-slate-400",
  status: "text-purple-300",
  module_done: "text-cyan-300",
  done: "text-emerald-400",
  error: "text-rose-400",
};

const TYPE_ROW_HIGHLIGHT: Record<QcLogEvent["type"], string> = {
  log: "",
  status: "bg-purple-500/10 border-l-2 border-purple-500 rounded-r-md px-2 -mx-2 py-0.5",
  module_done: "bg-cyan-500/10 border-l-2 border-cyan-500 rounded-r-md px-2 -mx-2 py-0.5",
  done: "bg-emerald-500/10 border-l-2 border-emerald-500 rounded-r-md px-2 -mx-2 py-0.5",
  error: "bg-rose-500/10 border-l-2 border-rose-500 rounded-r-md px-2 -mx-2 py-0.5",
};

function timeLabel(ts: number): string {
  return new Date(ts).toTimeString().slice(0, 8);
}

function lineText(evt: QcLogEvent): string {
  switch (evt.type) {
    case "status":
      return `→ status: ${evt.status}`;
    case "module_done":
      return `✓ modul selesai: ${evt.module}`;
    case "done":
      return `✓ ${evt.message ?? "done"}`;
    case "error":
      return `✗ ${evt.message ?? "error"}`;
    default:
      return evt.message ?? "";
  }
}

export function QcTerminalLog({ logs }: { logs: QcLogEvent[] }) {
  const bottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [logs.length]);

  return (
    <div className="h-full flex flex-col overflow-hidden bg-[#0a0710] text-[11px] font-mono leading-relaxed">
      <div className="flex-1 overflow-y-auto thin-scroll px-4 py-3 flex flex-col gap-1">
        {logs.length === 0 && <p className="text-slate-500 italic">menunggu koneksi stream…</p>}
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
