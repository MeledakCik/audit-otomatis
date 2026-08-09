"use client";

import { useEffect, useState } from "react";
import { Loader2, Radar, Globe2, AlertTriangle } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface InputPanelProps {
  onScan: (domain: string) => void;
  loading: boolean;
  liveStatus: string | null;
  cooldownMs: number;
  initialDomain?: string;
}

export function InputPanel({ onScan, loading, liveStatus, cooldownMs, initialDomain }: InputPanelProps) {
  const [domain, setDomain] = useState(initialDomain ?? "");
  const [tick, setTick] = useState(0);

  useEffect(() => {
    if (cooldownMs <= 0) return;
    const t = setInterval(() => setTick((n) => n + 1), 250);
    return () => clearInterval(t);
  }, [cooldownMs]);

  const remainingMs = Math.max(0, cooldownMs - tick * 250);
  const onCooldown = remainingMs > 0;

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <Radar className="h-3.5 w-3.5 text-accent" />
          Target Domain
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="space-y-1.5">
          <label className="flex items-center gap-1.5 text-[11px] font-mono uppercase tracking-wider text-muted-dim">
            <Globe2 className="h-3 w-3" /> Domain
          </label>
          <input
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && domain.trim() && !loading && !onCooldown) onScan(domain.trim());
            }}
            placeholder="sentinel-id.net"
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
            Passive CT log only, no DNS bruteforce. Subdomain diambil dari crt.sh (Certificate Transparency), dicek
            via DNS-over-HTTPS + satu GET request biasa. Maks 100 subdomain, 1 scan domain baru per 10 detik.
          </span>
        </div>

        <Button className="w-full" disabled={!domain.trim() || loading || onCooldown} onClick={() => onScan(domain.trim())}>
          {loading ? (
            <>
              <Loader2 className="h-4 w-4 animate-spin" /> Scanning...
            </>
          ) : onCooldown ? (
            <>Tunggu {Math.ceil(remainingMs / 1000)}s...</>
          ) : (
            <>
              <Radar className="h-4 w-4" /> Scan
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
