"use client";

import { useState } from "react";
import { Loader2, ShieldHalf, Globe2, AlertTriangle } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface InputPanelProps {
  onScan: (domain: string) => void;
  loading: boolean;
  liveStatus: string | null;
}

export function InputPanel({ onScan, loading, liveStatus }: InputPanelProps) {
  const [domain, setDomain] = useState("");

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <ShieldHalf className="h-3.5 w-3.5 text-accent" />
          Target
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-1.5">
          <label className="flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider text-muted-dim">
            <Globe2 className="h-3 w-3" /> Domain / URL
          </label>
          <input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && domain.trim() && !loading) onScan(domain.trim());
            }}
            placeholder="contoh.com atau https://contoh.com"
            spellCheck={false}
            className={cn(
              "w-full rounded-xl border border-border bg-[#0a0710] text-[#d6d0e8] font-mono text-sm px-4 py-3",
              "focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent placeholder:text-muted-dim/60"
            )}
          />
        </div>

        <div className="flex items-start gap-2 rounded-lg border border-border-strong/60 bg-surface-raised px-3 py-2.5 text-[11px] font-mono leading-relaxed text-muted-dim">
          <AlertTriangle className="h-3.5 w-3.5 text-accent shrink-0 mt-0.5" />
          <span>
            100% pasif — hanya 1 request <span className="text-foreground">GET</span>, baca response header saja.
            Tidak ada payload, fuzzing, atau exploit. Domain privat/internal (localhost, IP privat) otomatis diblokir.
          </span>
        </div>

        <Button className="w-full" disabled={!domain.trim() || loading} onClick={() => onScan(domain.trim())}>
          {loading ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" /> Scanning...
            </>
          ) : (
            <>
              <ShieldHalf className="h-4 w-4" /> Scan Headers
            </>
          )}
        </Button>

        {liveStatus && (
          <div className="flex items-center gap-2 text-[11px] font-mono text-accent">
            <span className="h-1.5 w-1.5 rounded-full bg-accent shadow-[0_0_8px_1px_var(--accent)] animate-pulse" />
            {liveStatus}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
