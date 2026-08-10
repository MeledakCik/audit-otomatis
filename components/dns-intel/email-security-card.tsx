import { Mail, Check, X, Info } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { SeverityBadge } from "@/components/ui/badge";
import type { DnsSecurity } from "@/lib/dns-intel/types";

function StatusRow({
  label,
  pass,
  risk,
  value,
  note,
}: {
  label: string;
  pass: boolean;
  risk?: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  value?: string | null;
  note: string;
}) {
  return (
    <div className="rounded-lg border border-border bg-surface-raised/50 px-3.5 py-3 space-y-2">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <span
            className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-bold tracking-widest uppercase ${
              pass ? "text-[#38d47a] border-[#38d47a]/40 bg-[#38d47a]/10" : "text-sev-critical border-sev-critical/40 bg-sev-critical/10"
            }`}
          >
            {pass ? <Check className="h-3 w-3" /> : <X className="h-3 w-3" />}
            {pass ? "PASS" : "FAIL"}
          </span>
          <span className="text-sm font-bold font-mono text-foreground">{label}</span>
        </div>
        {risk && <SeverityBadge severity={risk} />}
      </div>
      {value && (
        <div className="rounded-md bg-[#0a0710] border border-border px-2.5 py-1.5 text-[11px] font-mono text-[#8be9a8] break-all">
          {value}
        </div>
      )}
      <p className="text-[11px] font-mono text-muted-dim leading-relaxed">{note}</p>
    </div>
  );
}

export function EmailSecurityCard({ security }: { security: DnsSecurity }) {
  const { spf, dmarc, dkimHint, mxProvider } = security;

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <Mail className="h-3.5 w-3.5 text-accent" /> Email Security
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <StatusRow label="SPF" pass={spf.found && spf.risk === "LOW"} risk={spf.risk} value={spf.value} note={spf.note} />
        <StatusRow
          label="DMARC"
          pass={dmarc.found && dmarc.risk === "LOW"}
          risk={dmarc.risk}
          value={dmarc.value}
          note={dmarc.note}
        />

        <div className="rounded-lg border border-border bg-surface-raised/50 px-3.5 py-3 space-y-1.5">
          <div className="flex items-center gap-2">
            <Info className="h-3.5 w-3.5 text-muted-dim" />
            <span className="text-sm font-bold font-mono text-foreground">DKIM Hint</span>
          </div>
          <p className="text-[11px] font-mono text-muted-dim leading-relaxed">{dkimHint.note}</p>
        </div>

        <div className="rounded-lg border border-border bg-surface-raised/50 px-3.5 py-3 space-y-1.5">
          <div className="flex items-center justify-between gap-2">
            <span className="text-sm font-bold font-mono text-foreground">MX Provider</span>
            {mxProvider && (
              <span className="rounded-full border border-accent/40 bg-accent/10 text-accent px-2 py-0.5 text-[10px] font-mono font-bold">
                {mxProvider.confidence}
              </span>
            )}
          </div>
          <p className="text-[11px] font-mono text-muted-dim">
            {mxProvider ? mxProvider.provider : "Tidak ada MX record — domain ini kemungkinan tidak menerima email."}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
