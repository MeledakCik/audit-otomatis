import { History, Trash2, ShieldAlert, ShieldCheck } from "lucide-react";
import type { BreachLogEntry } from "@/lib/breach-check/types";

export function HistoryPanel({
  entries,
  onClear,
}: {
  entries: BreachLogEntry[];
  onClear: () => void;
}) {
  if (entries.length === 0) return null;

  return (
    <div className="rounded-2xl border border-border bg-surface shadow-[0_12px_32px_-16px_rgba(0,0,0,0.5)] overflow-hidden">
      <div className="border-b border-border px-4 py-3.5 flex items-center justify-between">
        <h2 className="text-[11px] font-bold uppercase tracking-widest text-muted flex items-center gap-2">
          <History className="h-3.5 w-3.5" /> Scan Log
        </h2>
        <button
          onClick={onClear}
          className="text-[10px] font-mono text-muted-dim hover:text-sev-critical transition-colors flex items-center gap-1"
        >
          <Trash2 className="h-3 w-3" /> Clear
        </button>
      </div>
      <div className="max-h-64 overflow-y-auto divide-y divide-border">
        {entries.map((e) => (
          <div key={e.id} className="px-4 py-2.5 flex items-center gap-2.5 text-xs">
            {e.clean ? (
              <ShieldCheck className="h-3.5 w-3.5 text-sev-low shrink-0" />
            ) : (
              <ShieldAlert className="h-3.5 w-3.5 text-sev-critical shrink-0" />
            )}
            <span className="font-mono text-foreground truncate flex-1">{e.query}</span>
            <span className="text-[10px] text-muted-dim shrink-0">
              {new Date(e.createdAt).toLocaleDateString()}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
