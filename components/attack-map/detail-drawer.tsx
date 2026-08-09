"use client";

import Link from "next/link";
import { X, ShieldHalf, KeyRound, ExternalLink as ExternalLinkIcon } from "lucide-react";
import { NODE_COLORS } from "./map-node";
import type { AttackMapNode } from "@/lib/attack-map/types";

export function DetailDrawer({
  node,
  hostname,
  onClose,
}: {
  node: AttackMapNode | null;
  hostname: string;
  onClose: () => void;
}) {
  if (!node) return null;
  const color = NODE_COLORS[node.type];

  return (
    <div className="absolute top-0 right-0 h-full w-full sm:w-80 bg-[#0f0b16] border-l border-white/[0.08] shadow-2xl z-20 flex flex-col">
      <div className="flex items-center justify-between px-4 py-3.5 border-b border-white/[0.06]">
        <div className="flex items-center gap-2 min-w-0">
          <span className="h-2.5 w-2.5 rounded-full shrink-0" style={{ background: color, boxShadow: `0 0 6px 1px ${color}90` }} />
          <span className="text-[11px] font-mono font-bold uppercase tracking-widest" style={{ color }}>
            {node.type}
          </span>
        </div>
        <button onClick={onClose} className="text-muted-dim hover:text-white transition-colors">
          <X className="h-4 w-4" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto thin-scroll p-4 space-y-4">
        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-dim mb-1">Label</div>
          <div className="text-sm font-semibold text-foreground break-all font-mono">{node.label}</div>
        </div>

        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-dim mb-1">URL</div>
          <div className="text-xs font-mono text-muted break-all">{node.url}</div>
        </div>

        {node.methods && node.methods.length > 0 && (
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-dim mb-1">Methods Found</div>
            <div className="flex flex-wrap gap-1.5">
              {node.methods.map((m) => (
                <span
                  key={m}
                  className="rounded-full border border-sev-critical/40 bg-sev-critical/10 text-sev-critical px-2 py-0.5 text-[10px] font-mono font-bold"
                >
                  {m}
                </span>
              ))}
            </div>
          </div>
        )}

        {node.formMethod && (
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-dim mb-1">Form Method</div>
            <span className="rounded-full border border-accent/40 bg-accent/10 text-accent px-2 py-0.5 text-[10px] font-mono font-bold">
              {node.formMethod}
            </span>
          </div>
        )}

        {node.inputs && node.inputs.length > 0 && (
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-muted-dim mb-1">Form Inputs</div>
            <div className="flex flex-wrap gap-1.5">
              {node.inputs.map((inp) => (
                <span key={inp} className="rounded-md bg-surface-raised border border-border px-2 py-0.5 text-[10px] font-mono text-muted-dim">
                  {inp}
                </span>
              ))}
            </div>
          </div>
        )}

        <div>
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-dim mb-1">Depth</div>
          <div className="text-xs font-mono text-muted">{node.depth}</div>
        </div>
      </div>

      {node.type !== "EXTERNAL" && (
        <div className="p-4 border-t border-white/[0.06] space-y-2">
          <div className="text-[10px] font-mono uppercase tracking-widest text-muted-dim">Deep-dive tools</div>
          <Link
            href={`/scan/headers?domain=${encodeURIComponent(hostname)}`}
            className="flex items-center gap-2 rounded-lg border border-border-strong px-3 py-2 text-xs font-mono text-foreground hover:border-accent hover:text-accent transition-colors"
          >
            <ShieldHalf className="h-3.5 w-3.5" /> Check headers for {hostname}
          </Link>
          <Link
            href={`/scan/secrets?domain=${encodeURIComponent(hostname)}`}
            className="flex items-center gap-2 rounded-lg border border-border-strong px-3 py-2 text-xs font-mono text-foreground hover:border-accent hover:text-accent transition-colors"
          >
            <KeyRound className="h-3.5 w-3.5" /> Hunt secrets on {hostname}
          </Link>
        </div>
      )}
      {node.type === "EXTERNAL" && (
        <div className="p-4 border-t border-white/[0.06]">
          <a
            href={node.url}
            target="_blank"
            rel="noreferrer noopener"
            className="flex items-center gap-2 rounded-lg border border-border-strong px-3 py-2 text-xs font-mono text-foreground hover:border-accent hover:text-accent transition-colors"
          >
            <ExternalLinkIcon className="h-3.5 w-3.5" /> Open {node.label}
          </a>
        </div>
      )}
    </div>
  );
}
