import { ShieldAlert, ShieldCheck, ShieldQuestion } from "lucide-react";
import type { DomainProbeResult } from "@/lib/breach-check/types";

export function DomainSummary({ domain, probes, hitCount, totalProbed }: {
  domain: string;
  probes: DomainProbeResult[];
  hitCount: number;
  totalProbed: number;
}) {
  return (
    <div className="rounded-2xl border border-border bg-surface shadow-[0_12px_32px_-16px_rgba(0,0,0,0.5)] overflow-hidden">
      <div className="border-b border-border px-4 py-3.5">
        <h2 className="text-[11px] font-bold uppercase tracking-widest text-muted">
          {hitCount} of {totalProbed} common emails at {domain} found in breaches
        </h2>
      </div>
      <div className="divide-y divide-border">
        {probes.map((p) => {
          const r = p.result;
          const rateLimited = !r.ok && r.rateLimited;
          const errored = !r.ok && !r.rateLimited;
          const clean = r.ok && r.clean;
          const hit = r.ok && !r.clean;

          return (
            <div key={p.email} className="px-4 py-2.5 flex items-center gap-2.5 text-xs">
              {hit && <ShieldAlert className="h-3.5 w-3.5 text-sev-critical shrink-0" />}
              {clean && <ShieldCheck className="h-3.5 w-3.5 text-sev-low shrink-0" />}
              {(rateLimited || errored) && <ShieldQuestion className="h-3.5 w-3.5 text-sev-medium shrink-0" />}
              <span className="font-mono text-foreground truncate flex-1">{p.email}</span>
              <span className="text-[10px] font-mono text-muted-dim shrink-0">
                {hit && `${r.breachCount} breach${r.breachCount === 1 ? "" : "es"}`}
                {clean && "clean"}
                {rateLimited && "rate limited"}
                {errored && "check failed"}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
