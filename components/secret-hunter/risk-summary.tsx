"use client";

import { ShieldCheck, ShieldAlert, ShieldX, Wrench, FileJson } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { downloadHardeningKit, downloadSecretHuntAsJson } from "@/lib/secret-hunter/export";
import type { SecretHuntReport } from "@/lib/secret-hunter/types";
import { cn } from "@/lib/utils";

const RISK_COPY: Record<SecretHuntReport["riskLevel"], { title: string; desc: string; icon: typeof ShieldCheck; className: string }> = {
  HIGH: {
    title: "Risk Level: HIGH",
    desc: "Ditemukan pola credential kritikal (mis. AWS/Slack key) di JS same-origin. Rotate & pindahkan ke server-side secepatnya.",
    icon: ShieldX,
    className: "text-sev-critical border-sev-critical/40 bg-sev-critical/10",
  },
  MEDIUM: {
    title: "Risk Level: MEDIUM",
    desc: "Ada indikasi credential/API key yang perlu ditinjau, atau env var publik dengan nama mencurigakan.",
    icon: ShieldAlert,
    className: "text-sev-medium border-sev-medium/40 bg-sev-medium/10",
  },
  LOW: {
    title: "Risk Level: LOW",
    desc: "Hanya info-disclosure minor (mis. URL Supabase/Firebase, IP privat) — bukan credential langsung.",
    icon: ShieldAlert,
    className: "text-sev-low border-sev-low/40 bg-sev-low/10",
  },
  CLEAN: {
    title: "Risk Level: CLEAN",
    desc: "Tidak ada pola secret/credential yang terdeteksi pada file yang berhasil di-scan.",
    icon: ShieldCheck,
    className: "text-[#38d47a] border-[#38d47a]/40 bg-[#38d47a]/10",
  },
};

export function RiskSummary({ report }: { report: SecretHuntReport }) {
  const copy = RISK_COPY[report.riskLevel];
  const Icon = copy.icon;

  return (
    <Card>
      <CardContent className="py-6 space-y-4">
        <div className={cn("flex items-start gap-3 rounded-xl border px-4 py-3", copy.className)}>
          <Icon className="h-5 w-5 shrink-0 mt-0.5" />
          <div>
            <div className="text-sm font-bold font-mono">{copy.title}</div>
            <p className="text-xs mt-1 leading-relaxed opacity-90">{copy.desc}</p>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
          <div className="text-[11px] font-mono text-muted-dim">
            {report.filesScanned} file di-scan
            {report.filesSkipped > 0 && <> · {report.filesSkipped} dilewati (limit ukuran/jumlah)</>}
          </div>
          <div className="flex flex-wrap gap-2">
            <Button size="sm" variant="outline" onClick={() => downloadSecretHuntAsJson(report)}>
              <FileJson className="h-3.5 w-3.5" /> Export JSON
            </Button>
            <Button size="sm" onClick={() => downloadHardeningKit(report)}>
              <Wrench className="h-3.5 w-3.5" /> Generate .gitignore &amp; env.example hardening
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
