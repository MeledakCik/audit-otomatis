"use client";

import { History, Trash2 } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import type { HeaderScanLogEntry } from "@/lib/header-scan/types";

const GRADE_TEXT: Record<string, string> = {
  "A+": "text-[#38d47a]",
  A: "text-[#38d47a]",
  B: "text-[#38bdf8]",
  C: "text-[#ffcc33]",
  D: "text-[#ff8a2b]",
  F: "text-sev-critical",
};

interface HistoryPanelProps {
  entries: HeaderScanLogEntry[];
  activeId?: string;
  onSelect: (entry: HeaderScanLogEntry) => void;
  onClear: () => void;
}

export function HistoryPanel({ entries, activeId, onSelect, onClear }: HistoryPanelProps) {
  if (entries.length === 0) return null;

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <History className="h-3.5 w-3.5 text-accent" /> Riwayat Scan ({entries.length})
        </CardTitle>
        <Button size="sm" variant="ghost" onClick={onClear}>
          <Trash2 className="h-3.5 w-3.5" /> Clear
        </Button>
      </CardHeader>
      <CardContent className="max-h-72 overflow-y-auto thin-scroll space-y-1.5 p-2">
        {entries.map((entry) => (
          <button
            key={entry.id}
            onClick={() => onSelect(entry)}
            className={cn(
              "w-full text-left rounded-lg border px-3 py-2 transition-colors",
              activeId === entry.id
                ? "border-accent/50 bg-accent/10"
                : "border-border bg-surface-raised hover:border-accent/30"
            )}
          >
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-mono text-foreground truncate">{entry.hostname}</span>
              <span className={cn("text-xs font-mono font-bold", GRADE_TEXT[entry.grade])}>
                {entry.grade} ({entry.score})
              </span>
            </div>
            <div className="mt-1 text-[10px] font-mono text-muted-dim truncate">
              {new Date(entry.createdAt).toLocaleString("id-ID")}
            </div>
          </button>
        ))}
      </CardContent>
    </Card>
  );
}
