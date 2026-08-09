"use client";

import { useState } from "react";
import { Check, X, ChevronDown, ChevronUp, Copy, Check as CheckIcon } from "lucide-react";
import { SeverityBadge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { HeaderCheckResult } from "@/lib/header-scan/types";

export function HeaderCheckRow({ check }: { check: HeaderCheckResult }) {
  const [open, setOpen] = useState(!check.pass);
  const [copied, setCopied] = useState(false);

  function handleCopy() {
    navigator.clipboard?.writeText(check.fixNextConfig).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    });
  }

  return (
    <div className={cn("rounded-xl border overflow-hidden", check.pass ? "border-border" : "border-sev-critical/25")}>
      <button
        onClick={() => setOpen((o) => !o)}
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-surface-raised/60 transition-colors"
      >
        <span
          className={cn(
            "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-bold tracking-widest uppercase shrink-0",
            check.pass
              ? "text-[#38d47a] border-[#38d47a]/40 bg-[#38d47a]/10"
              : "text-sev-critical border-sev-critical/40 bg-sev-critical/10"
          )}
        >
          {check.pass ? <Check className="h-3 w-3" /> : <X className="h-3 w-3" />}
          {check.pass ? "PASS" : "MISS"}
        </span>

        <div className="min-w-0 flex-1">
          <div className="text-sm font-semibold font-mono text-foreground truncate">{check.headerName}</div>
          <div className="text-[11px] font-mono text-muted-dim truncate">
            {check.value ? check.value : "Header tidak ditemukan pada response"}
          </div>
        </div>

        <span className="text-[10px] font-mono text-muted-dim shrink-0">{check.weight} pts</span>
        {!check.pass && <SeverityBadge severity={check.severity} />}

        {open ? (
          <ChevronUp className="h-4 w-4 text-muted-dim shrink-0" />
        ) : (
          <ChevronDown className="h-4 w-4 text-muted-dim shrink-0" />
        )}
      </button>

      {open && !check.pass && (
        <div className="px-4 pb-4 pt-1 space-y-3 border-t border-border bg-surface-raised/40">
          <p className="text-xs leading-relaxed text-foreground/90">{check.risk}</p>
          <div className="relative">
            <pre className="rounded-lg bg-[#0a0710] border border-border text-[11px] font-mono text-[#8be9a8] p-3 overflow-x-auto leading-relaxed">
              {check.fixNextConfig}
            </pre>
            <button
              onClick={handleCopy}
              className="absolute top-2 right-2 h-7 w-7 grid place-items-center rounded-md bg-white/5 text-muted-dim hover:text-accent hover:bg-white/10 transition-colors"
              title="Copy fix"
            >
              {copied ? <CheckIcon className="h-3.5 w-3.5 text-[#38d47a]" /> : <Copy className="h-3.5 w-3.5" />}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
