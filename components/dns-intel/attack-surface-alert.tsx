import { ShieldAlert, ShieldCheck } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { SeverityBadge } from "@/components/ui/badge";
import type { TakeoverHint } from "@/lib/dns-intel/types";

export function AttackSurfaceAlert({ hints }: { hints: TakeoverHint[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <ShieldAlert className="h-3.5 w-3.5 text-accent" /> Attack Surface Alerts
        </CardTitle>
      </CardHeader>
      <CardContent>
        {hints.length === 0 ? (
          <div className="py-8 text-center space-y-2">
            <ShieldCheck className="h-6 w-6 text-[#38d47a] mx-auto" />
            <p className="text-xs font-mono text-muted-dim">Tidak ada pola subdomain takeover yang terdeteksi dari CNAME.</p>
          </div>
        ) : (
          <div className="space-y-3">
            {hints.map((h, i) => (
              <div key={i} className="rounded-lg border border-sev-medium/30 bg-sev-medium/5 px-3.5 py-3 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-bold font-mono text-sev-medium uppercase tracking-wide">
                    [POTENTIAL TAKEOVER]
                  </span>
                  <SeverityBadge severity={h.risk} />
                </div>
                <div className="text-[11px] font-mono text-foreground">
                  CNAME → <span className="text-sev-medium break-all">{h.cname}</span>
                </div>
                <div className="text-[10px] font-mono text-muted-dim">Pola cocok: {h.matchedService}</div>
                <p className="text-[11px] font-mono text-muted-dim leading-relaxed">{h.note}</p>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
