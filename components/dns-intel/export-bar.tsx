"use client";

import { useState } from "react";
import { FileJson, Copy, Check, Clock, Info } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { downloadDnsIntelAsJson, copyDnsIntelAsJson } from "@/lib/dns-intel/export";
import type { DnsIntelReport } from "@/lib/dns-intel/types";

export function ExportBar({ report }: { report: DnsIntelReport }) {
  const [copied, setCopied] = useState(false);

  async function handleCopy() {
    const ok = await copyDnsIntelAsJson(report);
    if (ok) {
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  }

  return (
    <Card>
      <CardContent className="py-3.5 flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-4 text-[11px] font-mono text-muted-dim">
          <span className="flex items-center gap-1.5">
            <Clock className="h-3.5 w-3.5" /> Scan time: {report.scanDurationMs}ms · {new Date(report.createdAt).toLocaleString("id-ID")}
          </span>
        </div>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={handleCopy}>
            {copied ? <Check className="h-3.5 w-3.5 text-[#38d47a]" /> : <Copy className="h-3.5 w-3.5" />}
            {copied ? "Copied" : "Copy JSON"}
          </Button>
          <Button size="sm" onClick={() => downloadDnsIntelAsJson(report)}>
            <FileJson className="h-3.5 w-3.5" /> Export JSON
          </Button>
        </div>
      </CardContent>
      <div className="border-t border-border px-4 py-2.5 flex items-start gap-2 text-[10px] font-mono text-muted-dim">
        <Info className="h-3 w-3 shrink-0 mt-0.5" />
        <span>
          Data dari standard DNS query publik (DoH Cloudflare) — 100% pasif, tidak ada zone transfer/bruteforce. Hint
          takeover &amp; DKIM di atas perlu verifikasi manual sebelum dianggap temuan konklusif.
        </span>
      </div>
    </Card>
  );
}
