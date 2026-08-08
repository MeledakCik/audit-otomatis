"use client";

import { useState } from "react";
import { MapPin, ShieldAlert, ListChecks, ChevronDown, Terminal } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { SeverityIndicator } from "./severity-indicator";
import { cn } from "@/lib/utils";
import type { SecurityFinding } from "@/lib/maintenance/types";

interface FindingCardProps {
  finding: SecurityFinding;
  index: number;
  onToggleStep: (findingId: string, stepIndex: number) => void;
}

export function FindingCard({ finding, index, onToggleStep }: FindingCardProps) {
  const [open, setOpen] = useState(index === 0);
  const loc = finding.leakLocation;
  const locationLabel = [loc.file, loc.line ? `:${loc.line}${loc.column ? `:${loc.column}` : ""}` : ""]
    .filter(Boolean)
    .join("");

  return (
    <Card className="animate-fade-up" style={{ ["--delay" as string]: `${index * 60}ms` }}>
      <div className="cursor-pointer" onClick={() => setOpen((o) => !o)}>
        <CardHeader>
          <CardTitle className="normal-case text-[13px] text-foreground font-semibold tracking-normal">
            <SeverityIndicator severity={finding.severity} />
            <span className="truncate">{finding.title}</span>
          </CardTitle>
          <div className="flex items-center gap-2 shrink-0">
            <Badge>{finding.vulnerabilityType}</Badge>
            <ChevronDown className={cn("h-4 w-4 text-muted-dim transition-transform", open && "rotate-180")} />
          </div>
        </CardHeader>
      </div>

      {open && (
        <CardContent className="space-y-5">
          {/* Leak Location Map */}
          <div className="space-y-1.5">
            <div className="flex items-center gap-1.5 text-[11px] font-mono font-bold uppercase tracking-widest text-muted">
              <MapPin className="h-3.5 w-3.5 text-accent" /> Leak Location Map
            </div>
            <div className="rounded-lg border border-border bg-surface-raised p-3 space-y-1.5 text-xs font-mono">
              {locationLabel && (
                <div>
                  <span className="text-muted-dim">File: </span>
                  <span className="text-foreground">{locationLabel}</span>
                </div>
              )}
              {loc.endpoint && (
                <div>
                  <span className="text-muted-dim">Endpoint: </span>
                  <span className="text-foreground">{loc.endpoint}</span>
                </div>
              )}
              <div>
                <span className="text-muted-dim">Jenis: </span>
                <span className="text-foreground">{finding.owaspCategory}</span>
              </div>
              {finding.codeSnippet && (
                <pre className="mt-2 overflow-x-auto rounded-md border border-sev-critical/30 bg-sev-critical/10 p-2.5 text-[11.5px] leading-relaxed text-sev-critical whitespace-pre-wrap">
                  {finding.codeSnippet}
                </pre>
              )}
            </div>
          </div>

          {/* Attack Vector */}
          <div className="space-y-1.5">
            <div className="flex items-center gap-1.5 text-[11px] font-mono font-bold uppercase tracking-widest text-muted">
              <ShieldAlert className="h-3.5 w-3.5 text-sev-high" /> Attack Vector
            </div>
            <p className="text-[13px] leading-relaxed text-foreground/90">{finding.attackVector}</p>
            {finding.payloadExample && (
              <div className="flex items-start gap-1.5 rounded-lg border border-border bg-[#0a0710] px-3 py-2">
                <Terminal className="h-3.5 w-3.5 text-accent mt-0.5 shrink-0" />
                <code className="text-[11.5px] font-mono text-accent break-all">{finding.payloadExample}</code>
              </div>
            )}
          </div>

          {/* Remediation Steps */}
          <div className="space-y-1.5">
            <div className="flex items-center gap-1.5 text-[11px] font-mono font-bold uppercase tracking-widest text-muted">
              <ListChecks className="h-3.5 w-3.5 text-emerald-400" /> Remediation Steps
            </div>
            <div className="space-y-2.5">
              {finding.remediationSteps.map((step, i) => (
                <div key={i} className="rounded-lg border border-border bg-surface-raised p-3 space-y-2">
                  <label className="flex items-start gap-2.5 cursor-pointer text-[13px]">
                    <input
                      type="checkbox"
                      checked={!!step.done}
                      onChange={() => onToggleStep(finding.id, i)}
                      className="mt-0.5 h-3.5 w-3.5 accent-[var(--accent)] shrink-0"
                    />
                    <span className={cn("text-foreground/90", step.done && "line-through text-muted-dim")}>
                      Fix {i + 1}: {step.step}
                    </span>
                  </label>
                  {(step.codeBefore || step.codeAfter) && (
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 pl-6">
                      {step.codeBefore && (
                        <pre className="overflow-x-auto rounded-md bg-sev-critical/10 border border-sev-critical/30 p-2 text-[11px] leading-relaxed text-sev-critical whitespace-pre-wrap">
                          <span className="block text-[9px] uppercase tracking-wider text-sev-critical/70 mb-1">
                            − before
                          </span>
                          {step.codeBefore}
                        </pre>
                      )}
                      {step.codeAfter && (
                        <pre className="overflow-x-auto rounded-md bg-emerald-500/10 border border-emerald-500/30 p-2 text-[11px] leading-relaxed text-emerald-400 whitespace-pre-wrap">
                          <span className="block text-[9px] uppercase tracking-wider text-emerald-400/70 mb-1">
                            + after
                          </span>
                          {step.codeAfter}
                        </pre>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>

          <div className="rounded-lg border border-accent/20 bg-accent/5 p-3 text-[12px] leading-relaxed text-foreground/80">
            <span className="font-bold text-accent">Prevention: </span>
            {finding.prevention}
          </div>
        </CardContent>
      )}
    </Card>
  );
}
