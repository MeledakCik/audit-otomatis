"use client";

import { useState } from "react";
import { SeverityBadge, Badge } from "@/components/ui/badge";
import type { Finding, Severity } from "@/lib/types";
import { cn } from "@/lib/utils";

const ORDER: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];

const CATEGORY_LABELS: Record<NonNullable<Finding["category"]>, string> = {
  secret: "secret",
  "outdated-library": "outdated lib",
  generic: "generic",
  "dom-xss-sink": "dom xss sink",
  "open-redirect": "open redirect",
  ssrf: "ssrf",
  "idor-candidate": "idor candidate",
  "auth-bypass": "auth bypass",
  "missing-rate-limit": "no rate limit",
  "passive-discovery": "discovery",
};

export function FindingsTable({ findings }: { findings: Finding[] }) {
  const [openId, setOpenId] = useState<string | null>(null);

  if (findings.length === 0) {
    return (
      <div className="px-4 py-10 text-center text-xs text-muted-dim">
        Belum ada temuan. Temuan akan muncul di sini seiring scan berjalan.
      </div>
    );
  }

  const sorted = [...findings].sort(
    (a, b) => ORDER.indexOf(a.severity) - ORDER.indexOf(b.severity)
  );

  return (
    <div className="divide-y divide-border">
      {sorted.map((f) => {
        const isOpen = openId === f.id;
        return (
          <div key={f.id}>
            <button
              onClick={() => setOpenId(isOpen ? null : f.id)}
              className="w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-surface-raised transition-colors"
              aria-expanded={isOpen}
            >
              <SeverityBadge severity={f.severity} />
              {f.category && (
                <Badge className="hidden md:inline-flex shrink-0">{CATEGORY_LABELS[f.category]}</Badge>
              )}
              <span className="flex-1 min-w-0 text-xs text-foreground truncate">{f.title}</span>
              <span className="text-[11px] text-muted-dim truncate max-w-[30%] hidden sm:block">
                {f.endpoint}
              </span>
              <span className={cn("text-muted-dim text-xs transition-transform duration-200 shrink-0", isOpen && "rotate-90")}>
                ›
              </span>
            </button>
            <div className={cn("accordion-rows", isOpen && "is-open")}>
              <div className="accordion-inner">
                <div className="px-4 pb-4 pt-1 bg-surface-raised/40 flex flex-col gap-2 text-xs">
                  <Row label="Endpoint" value={f.endpoint} mono />
                  {f.category && <Row label="Kategori" value={CATEGORY_LABELS[f.category]} />}
                  <Row label="Bukti" value={f.evidence} mono />
                  {typeof f.cvss === "number" && (
                    <Row label="CVSS" value={`${f.cvss.toFixed(1)}${f.cwe ? ` · ${f.cwe}` : ""}`} mono />
                  )}
                  <Row label="Dampak" value={f.impact} />
                  {f.poc && <Row label="PoC (non-destruktif)" value={f.poc} mono />}
                  <Row label="Fix" value={f.fix} accent />
                </div>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function Row({
  label,
  value,
  mono,
  accent,
}: {
  label: string;
  value: string;
  mono?: boolean;
  accent?: boolean;
}) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[10px] uppercase tracking-widest text-muted-dim">{label}</span>
      <span
        className={cn(
          "leading-relaxed break-words",
          mono && "font-mono text-muted",
          accent ? "text-accent" : !mono && "text-foreground"
        )}
      >
        {value}
      </span>
    </div>
  );
}
