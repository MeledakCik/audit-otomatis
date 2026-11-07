import { SentinelAudit } from "@/components/sentinel/sentinel-audit";
import { VerifiedBadge } from "@/components/verified-badge";
import { buildPageMetadata } from "@/lib/seo-master";
import Link from "next/link";
import { ArrowLeft, ShieldCheck } from "lucide-react";

export const metadata = buildPageMetadata("/scan/sentinel");

export default function ScanSentinelPage() {
  return (
    <div className="w-full min-h-full">
      <div className="mx-auto max-w-5xl px-6 lg:px-8 py-8 space-y-6">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="inline-flex items-center gap-1.5 rounded-xl border border-white/10 bg-white/[0.03] hover:bg-white/[0.08] px-3 py-1.5 text-xs font-mono text-slate-300 transition-colors"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              Kembali ke Scan Utama
            </Link>
            <span className="inline-flex items-center gap-1.5 rounded-full bg-purple-500/15 border border-purple-500/30 px-3 py-1 text-xs font-mono text-purple-300">
              <ShieldCheck className="h-3.5 w-3.5 text-purple-400" />
              Modul Scan / Sentinel Vault
            </span>
          </div>
          <VerifiedBadge variant="header" />
        </div>

        <SentinelAudit embedded />
      </div>
    </div>
  );
}
