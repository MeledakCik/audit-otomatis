import { Table2, TriangleAlert } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import type { DnsRecordRow } from "@/lib/dns-intel/types";

const TYPE_COLORS: Record<string, string> = {
  A: "#22d3ee",
  AAAA: "#22d3ee",
  NS: "#c084fc",
  MX: "#e93ee8",
  TXT: "#38bdf8",
  CNAME: "#ffcc33",
  SOA: "#9ca3af",
};

export function RecordsTable({ rows, queryErrors }: { rows: DnsRecordRow[]; queryErrors: string[] }) {
  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <Table2 className="h-3.5 w-3.5 text-accent" /> DNS Records ({rows.length})
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        {queryErrors.length > 0 && (
          <div className="flex items-start gap-2 px-4 py-2.5 border-b border-border text-[11px] font-mono text-sev-medium">
            <TriangleAlert className="h-3.5 w-3.5 shrink-0 mt-0.5" />
            <span>Gagal resolve: {queryErrors.join(", ")} (timeout/error — bukan berarti record-nya kosong).</span>
          </div>
        )}
        {rows.length === 0 ? (
          <div className="py-10 text-center text-sm text-muted">Tidak ada record ditemukan.</div>
        ) : (
          <div className="overflow-x-auto max-h-[420px] overflow-y-auto thin-scroll">
            <table className="w-full text-xs font-mono">
              <thead className="sticky top-0 bg-surface">
                <tr className="border-b border-border text-[10px] uppercase tracking-widest text-muted-dim">
                  <th className="text-left px-4 py-2.5 font-semibold">Type</th>
                  <th className="text-left px-4 py-2.5 font-semibold">Value</th>
                  <th className="text-left px-4 py-2.5 font-semibold">TTL</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r, i) => (
                  <tr key={i} className="border-b border-border/60 hover:bg-surface-raised/60 transition-colors align-top">
                    <td className="px-4 py-2.5">
                      <span
                        className="rounded-full border px-2 py-0.5 text-[10px] font-bold"
                        style={{ color: TYPE_COLORS[r.type] ?? "#9ca3af", borderColor: `${TYPE_COLORS[r.type] ?? "#9ca3af"}55` }}
                      >
                        {r.type}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 text-foreground break-all max-w-[280px]">{r.value}</td>
                    <td className="px-4 py-2.5 text-muted-dim">{r.ttl !== null ? `${r.ttl}s` : "—"}</td>
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
