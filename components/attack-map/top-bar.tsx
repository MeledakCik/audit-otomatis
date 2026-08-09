"use client";

import { useState } from "react";
import { Loader2, Search, Maximize2, Download, FileJson, ShieldHalf } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Legend } from "./legend";
import { cn } from "@/lib/utils";

interface TopBarProps {
  onScan: (domain: string) => void;
  loading: boolean;
  hasReport: boolean;
  onFitView: () => void;
  onExportPng: () => void;
  onExportJson: () => void;
  liveStatus: string | null;
}

export function TopBar({ onScan, loading, hasReport, onFitView, onExportPng, onExportJson, liveStatus }: TopBarProps) {
  const [domain, setDomain] = useState("");

  return (
    <div className="border-b border-white/[0.06] bg-[#0f0b16] px-4 sm:px-6 py-3 flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-3">
        <div className="h-8 w-8 grid place-items-center rounded-lg bg-gradient-to-br from-[#c084fc] to-[#9333ea] text-black shadow-lg shadow-purple-500/20 shrink-0">
          <ShieldHalf className="h-4 w-4 text-white" strokeWidth={2.5} />
        </div>
        <div className="mr-2">
          <div className="text-sm font-extrabold tracking-tight text-foreground">Attack Surface Map</div>
          <div className="text-[10px] font-mono text-muted-dim">Passive · GET-only · same-origin · depth 2 · max 50 nodes</div>
        </div>

        <input
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && domain.trim() && !loading) onScan(domain.trim());
          }}
          placeholder="contoh.com atau https://contoh.com"
          spellCheck={false}
          className={cn(
            "flex-1 min-w-[220px] rounded-xl border border-border bg-[#0a0710] text-[#d6d0e8] font-mono text-sm px-3.5 py-2",
            "focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent placeholder:text-muted-dim/60"
          )}
        />

        <Button size="md" disabled={!domain.trim() || loading} onClick={() => onScan(domain.trim())}>
          {loading ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" /> Mapping...
            </>
          ) : (
            <>
              <Search className="h-4 w-4" /> Scan
            </>
          )}
        </Button>

        <div className="flex items-center gap-2 ml-auto">
          <Button size="sm" variant="outline" disabled={!hasReport} onClick={onFitView}>
            <Maximize2 className="h-3.5 w-3.5" /> Fit View
          </Button>
          <Button size="sm" variant="outline" disabled={!hasReport} onClick={onExportPng}>
            <Download className="h-3.5 w-3.5" /> Export PNG
          </Button>
          <Button size="sm" variant="outline" disabled={!hasReport} onClick={onExportJson}>
            <FileJson className="h-3.5 w-3.5" /> Export JSON
          </Button>
        </div>
      </div>

      <div className="flex flex-wrap items-center justify-between gap-2">
        <Legend />
        {liveStatus && (
          <div className="flex items-center gap-2 text-[11px] font-mono text-accent">
            <span className="h-1.5 w-1.5 rounded-full bg-accent shadow-[0_0_8px_1px_var(--accent)] animate-pulse" />
            {liveStatus}
          </div>
        )}
      </div>
    </div>
  );
}
