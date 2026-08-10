"use client";

import { useState } from "react";
import { Loader2, Radar, Globe2, AlertTriangle } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

interface InputPanelProps {
  onScan: (domain: string) => void;
  loading: boolean;
}

export function InputPanel({ onScan, loading }: InputPanelProps) {
  const [domain, setDomain] = useState("");

  return (
    <Card>
      <CardContent className="py-4 space-y-3">
        <div className="flex flex-wrap items-center gap-3">
          <div className="flex-1 min-w-[220px] relative">
            <Globe2 className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-dim" />
            <input
              value={domain}
              onChange={(e) => setDomain(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && domain.trim() && !loading) onScan(domain.trim());
              }}
              placeholder="example.com"
              spellCheck={false}
              className={cn(
                "w-full rounded-xl border border-border bg-[#0a0710] text-[#d6d0e8] font-mono text-sm pl-9 pr-3.5 py-2.5",
                "focus:outline-none focus:ring-2 focus:ring-accent/50 focus:border-accent placeholder:text-muted-dim/60"
              )}
            />
          </div>
          <Button disabled={!domain.trim() || loading} onClick={() => onScan(domain.trim())}>
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" /> Scanning...
              </>
            ) : (
              <>
                <Radar className="h-4 w-4" /> SCAN DNS
              </>
            )}
          </Button>
        </div>

        <div className="flex items-start gap-2 rounded-lg border border-border-strong/60 bg-surface-raised px-3 py-2.5 text-[11px] font-mono leading-relaxed text-muted-dim">
          <AlertTriangle className="h-3.5 w-3.5 text-accent shrink-0 mt-0.5" />
          <span>
            100% pasif — standard DNS query lewat DoH (Cloudflare), tidak ada zone transfer (AXFR), tidak ada bruteforce
            subdomain. Dibatasi 10 request/menit per IP.
          </span>
        </div>
      </CardContent>
    </Card>
  );
}
