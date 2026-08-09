import { Layers, Download } from "lucide-react";
import { Card, CardHeader, CardTitle, CardContent } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { StackCard } from "./stack-card";
import type { StackCategory, StackFingerprintReport } from "@/lib/stack-fingerprint/types";
import { downloadStackFingerprintAsJson } from "@/lib/stack-fingerprint/export";

const CATEGORY_ORDER: StackCategory[] = ["Frontend", "CMS", "Backend", "BaaS", "CDN", "Hosting", "Analytics", "Payments", "Auth"];

export function ResultsGrid({ report }: { report: StackFingerprintReport | null }) {
  if (!report) {
    return (
      <Card>
        <CardContent className="py-16 text-center text-sm text-muted font-mono">
          Masukkan domain lalu klik Fingerprint untuk mendeteksi tech stack dari homepage.
        </CardContent>
      </Card>
    );
  }

  const grouped = CATEGORY_ORDER.map((cat) => ({
    category: cat,
    stacks: report.stacks.filter((s) => s.category === cat),
  })).filter((g) => g.stacks.length > 0);

  return (
    <Card>
      <CardHeader>
        <CardTitle>
          <Layers className="h-3.5 w-3.5 text-accent" />
          Tech Stack — {report.domain}
        </CardTitle>
        <div className="flex items-center gap-2">
          <Badge>{report.stacks.length} detected</Badge>
          <Button size="sm" variant="outline" onClick={() => downloadStackFingerprintAsJson(report)}>
            <Download className="h-3.5 w-3.5" /> Export JSON
          </Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-6">
        {grouped.length === 0 && (
          <div className="py-8 text-center text-sm text-muted font-mono">
            Tidak ada marker tech stack yang terdeteksi di homepage ini.
          </div>
        )}

        {grouped.map((g) => (
          <div key={g.category} className="space-y-2.5">
            <h3 className="text-[11px] font-bold uppercase tracking-widest text-muted-dim">
              {g.category} <span className="text-muted-dim/60">({g.stacks.length})</span>
            </h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3">
              {g.stacks.map((s) => (
                <StackCard key={s.id} stack={s} />
              ))}
            </div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
