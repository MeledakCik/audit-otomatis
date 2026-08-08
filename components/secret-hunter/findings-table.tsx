"use client";

import { useState } from "react";
import { Copy, Check, KeyRound } from "lucide-react";
import { SeverityBadge } from "@/components/ui/badge";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import type { SecretFinding } from "@/lib/secret-hunter/types";

function CopyPathButton({ path }: { path: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => {
        navigator.clipboard?.writeText(path).then(() => {
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        });
      }}
      className="inline-flex items-center gap-1 rounded-md px-2 py-1 text-[10px] font-mono text-muted-dim hover:text-accent hover:bg-white/5 transition-colors shrink-0"
      title="Copy path"
    >
      {copied ? <Check className="h-3 w-3 text-[#38d47a]" /> : <Copy className="h-3 w-3" />}
      {copied ? "Copied" : "Copy path"}
    </button>
  );
}

export function FindingsTable({ findings }: { findings: SecretFinding[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <KeyRound className="h-3.5 w-3.5 text-accent" /> Findings ({findings.length})
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        {findings.length === 0 ? (
          <div className="py-10 text-center text-sm text-muted">Tidak ada pola secret yang terdeteksi. 🎉</div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="border-b border-border text-[10px] uppercase tracking-widest text-muted-dim">
                  <th className="text-left px-4 py-2.5 font-semibold">Severity</th>
                  <th className="text-left px-4 py-2.5 font-semibold">Type</th>
                  <th className="text-left px-4 py-2.5 font-semibold">File</th>
                  <th className="text-left px-4 py-2.5 font-semibold">Snippet (redacted)</th>
                  <th className="text-right px-4 py-2.5 font-semibold"> </th>
                </tr>
              </thead>
              <tbody>
                {findings.map((f) => (
                  <tr key={f.id} className="border-b border-border/60 hover:bg-surface-raised/60 transition-colors align-top">
                    <td className="px-4 py-2.5">
                      <SeverityBadge severity={f.severity} />
                    </td>
                    <td className="px-4 py-2.5 text-foreground whitespace-nowrap">{f.type}</td>
                    <td className="px-4 py-2.5 text-muted-dim">{f.file}</td>
                    <td className="px-4 py-2.5 text-[#8be9a8] max-w-[280px] truncate" title={f.redactedSnippet}>
                      {f.redactedSnippet}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <CopyPathButton path={f.file} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
