"use client";

import { useState } from "react";
import { ChevronDown } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { DetectedStack, EvidenceTier } from "@/lib/stack-fingerprint/types";

const TIER_META: Record<EvidenceTier, { dot: string; label: string; text: string }> = {
  header: { dot: "bg-[#38d47a]", label: "HEADER", text: "text-[#38d47a]" },
  html: { dot: "bg-accent", label: "HTML", text: "text-accent" },
  jsHint: { dot: "bg-sev-medium", label: "JS HINT", text: "text-sev-medium" },
};

function confidenceTone(confidence: number): { bar: string; text: string } {
  if (confidence >= 85) return { bar: "bg-[#38d47a]", text: "text-[#38d47a]" };
  if (confidence >= 70) return { bar: "bg-accent", text: "text-accent" };
  return { bar: "bg-sev-medium", text: "text-sev-medium" };
}

export function StackCard({ stack }: { stack: DetectedStack }) {
  const [expanded, setExpanded] = useState(false);
  const tone = confidenceTone(stack.confidence);
  const visibleEvidence = expanded ? stack.evidence : stack.evidence.slice(0, 2);
  const hiddenCount = stack.evidence.length - visibleEvidence.length;

  return (
    <div className="rounded-xl border border-border bg-surface-raised p-4 space-y-3">
      <div className="flex items-start gap-3">
        <span className="h-10 w-10 grid place-items-center rounded-lg border border-border-strong bg-surface text-base font-bold text-accent shrink-0">
          {stack.icon}
        </span>
        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex items-start justify-between gap-2">
            <h4 className="text-sm font-bold text-foreground leading-snug break-words">{stack.name}</h4>
            <span className={cn("text-sm font-mono font-bold shrink-0", tone.text)}>{stack.confidence}%</span>
          </div>
          <Badge>{stack.category}</Badge>
        </div>
      </div>

      <div className="h-1.5 w-full rounded-full bg-border overflow-hidden">
        <div className={cn("h-full rounded-full transition-all", tone.bar)} style={{ width: `${stack.confidence}%` }} />
      </div>

      {stack.version && (
        <div className="rounded-lg border border-border-strong/60 bg-surface px-2.5 py-1.5 text-[10px] font-mono leading-relaxed">
          <div className="text-foreground">
            Version: <span className="font-bold">{stack.version}</span>
          </div>
          <div className="text-muted-dim/70">Detected from public meta tag</div>
        </div>
      )}

      <ul className="space-y-1.5">
        {visibleEvidence.map((e, i) => (
          <li key={i} className="flex items-start gap-1.5 text-[10px] font-mono leading-relaxed">
            <span className={cn("h-1.5 w-1.5 rounded-full mt-1 shrink-0", TIER_META[e.tier].dot)} />
            <span className="min-w-0">
              <span className={cn("font-bold mr-1", TIER_META[e.tier].text)}>{TIER_META[e.tier].label}</span>
              <span className="text-muted-dim break-words">{e.label}</span>
            </span>
          </li>
        ))}
      </ul>

      {stack.evidence.length > 2 && (
        <button
          onClick={() => setExpanded((v) => !v)}
          className="flex items-center gap-1 text-[10px] font-mono uppercase tracking-wider text-accent hover:text-accent/80 transition-colors"
        >
          <ChevronDown className={cn("h-3 w-3 transition-transform", expanded && "rotate-180")} />
          {expanded ? "Show less" : `+${hiddenCount} more evidence`}
        </button>
      )}
    </div>
  );
}