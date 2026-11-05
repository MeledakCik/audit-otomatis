"use client";

import { useActionState, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { startScanAction, type StartScanResult } from "@/lib/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { SentinelAudit } from "@/components/sentinel/sentinel-audit";
import { Globe, Lock, Radar, ShieldCheck, Sparkles, ArrowRight, KeyRound, ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";

const initialState: StartScanResult = { ok: false };

export function ScanForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const initialTab = searchParams?.get("tab") === "sentinel" ? "sentinel" : "full";
  const [mode, setMode] = useState<"full" | "sentinel">(initialTab);
  const [checked, setChecked] = useState(false);
  const [domainVal, setDomainVal] = useState("");
  const [showWafOpts, setShowWafOpts] = useState(false);
  const [cfClearance, setCfClearance] = useState("");
  const [state, formAction, pending] = useActionState(
    (_p: StartScanResult, fd: FormData) => startScanAction(fd),
    initialState
  );

  useEffect(() => {
    if (searchParams?.get("tab") === "sentinel") {
      setMode("sentinel");
    }
  }, [searchParams]);

  useEffect(() => {
    if (state.ok && state.scanId) router.push(`/scan/${state.scanId}`);
  }, [state, router]);

  return (
    <div className="space-y-5">
      {/* Mode Switcher Tabs inside Scan Box */}
      <div className="grid grid-cols-2 gap-1.5 rounded-xl bg-black/40 p-1.5 border border-white/[0.08]">
        <button
          type="button"
          onClick={() => setMode("full")}
          className={cn(
            "flex items-center justify-center gap-2 rounded-lg py-2 px-3 text-xs font-mono font-bold transition-all cursor-pointer",
            mode === "full"
              ? "bg-gradient-to-r from-purple-600 to-indigo-600 text-white shadow-md shadow-purple-600/25"
              : "text-slate-400 hover:text-white"
          )}
        >
          <Radar className="h-3.5 w-3.5" />
          <span>Full Scan + Deep Shell/Vault</span>
        </button>
        <button
          type="button"
          onClick={() => setMode("sentinel")}
          className={cn(
            "flex items-center justify-center gap-2 rounded-lg py-2 px-3 text-xs font-mono font-bold transition-all cursor-pointer",
            mode === "sentinel"
              ? "bg-gradient-to-r from-purple-600 to-pink-600 text-white shadow-md shadow-pink-600/25"
              : "text-slate-400 hover:text-white"
          )}
        >
          <Lock className="h-3.5 w-3.5" />
          <span>Brankas AES-256-GCM &amp; Klaim</span>
        </button>
      </div>

      {mode === "full" ? (
        <form action={formAction} className="flex flex-col gap-4">
          <div className="space-y-1.5">
            <label
              htmlFor="scan-domain-input"
              className="text-xs font-mono uppercase tracking-wider text-purple-300/90 font-semibold flex items-center justify-between"
            >
              <span>Domain / URL Target</span>
              <span className="text-[11px] text-emerald-400 font-normal">
                WAF &amp; CF Resilient · GDG Bandung Verified
              </span>
            </label>
            <div className="relative">
              <Globe className="h-4 w-4 text-purple-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <Input
                id="scan-domain-input"
                name="domain"
                value={domainVal}
                onChange={(e) => setDomainVal(e.target.value)}
                placeholder="contoh: sentinel-id.net"
                className="h-11 pl-10 bg-black/40 border-white/15 text-white placeholder:text-slate-500 rounded-xl focus:border-purple-400"
                required
                disabled={pending}
              />
            </div>
          </div>

          <input type="hidden" name="permission" value={checked ? "on" : ""} />
          <input type="hidden" name="cfClearance" value={cfClearance} />

          {/* Optional WAF / Cloudflare Owner Token Settings */}
          <div className="rounded-xl border border-emerald-500/25 bg-emerald-500/[0.04] p-3 space-y-2">
            <button
              type="button"
              onClick={() => setShowWafOpts((v) => !v)}
              className="w-full flex items-center justify-between text-left text-xs font-mono text-emerald-300 cursor-pointer"
            >
              <span className="flex items-center gap-1.5 font-semibold">
                <ShieldCheck className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                <span>Mode Audit Tangguh Cloudflare / WAF Aktif (Edge + DNS/DoH + Static)</span>
              </span>
              <ChevronDown
                className={cn("h-3.5 w-3.5 transition-transform", showWafOpts && "rotate-180")}
              />
            </button>
            <p className="text-[11px] text-slate-400 leading-relaxed">
              Tetap memeriksa Header Edge, <code className="text-purple-300">CF-RAY</code>, DNS/SPF/DMARC, well-known files, serta path statis walau domain dilindungi Cloudflare/WAF.
            </p>
            {showWafOpts && (
              <div className="pt-1.5 space-y-1.5 border-t border-white/10">
                <label
                  htmlFor="cf-clearance-input"
                  className="text-[11px] font-mono text-slate-300 flex items-center gap-1.5"
                >
                  <KeyRound className="h-3 w-3 text-purple-400" />
                  <span>CF Clearance Token Pemilik Domain (Opsional):</span>
                </label>
                <Input
                  id="cf-clearance-input"
                  value={cfClearance}
                  onChange={(e) => setCfClearance(e.target.value)}
                  placeholder="Masukkan nilai cookie cf_clearance jika ingin mengaudit di balik Interactive Challenge"
                  className="h-9 bg-black/50 border-white/15 text-xs font-mono text-white placeholder:text-slate-500 rounded-lg"
                  disabled={pending}
                />
              </div>
            )}
          </div>

          {/* Included Modules Pill Strip */}
          <div className="rounded-xl border border-white/[0.07] bg-white/[0.02] p-3 space-y-2">
            <div className="text-[11px] font-mono text-slate-400 flex items-center gap-1.5">
              <Sparkles className="h-3 w-3 text-purple-400" />
              <span>Otomatis menjalankan 7 engine keamanan mendalam sekaligus:</span>
            </div>
            <div className="flex flex-wrap gap-1.5 text-[10px] font-mono">
              <span className="rounded-md bg-purple-500/15 border border-purple-500/30 px-2 py-0.5 text-purple-200">
                1. Multi-Page &amp; Edge Crawler
              </span>
              <span className="rounded-md bg-purple-500/15 border border-purple-500/30 px-2 py-0.5 text-purple-200">
                2. AST JS &amp; Secret Scan
              </span>
              <span className="rounded-md bg-pink-500/15 border border-pink-500/30 px-2 py-0.5 text-pink-200">
                3. wp2shell · php2shell · node2shell · go2shell · py2shell
              </span>
              <span className="rounded-md bg-amber-500/15 border border-amber-500/30 px-2 py-0.5 text-amber-200">
                4. Node Out-of-Bounds (OOB) &amp; Heap
              </span>
              <span className="rounded-md bg-emerald-500/15 border border-emerald-500/30 px-2 py-0.5 text-emerald-200">
                5. Audit File Sensitif &amp; Vault AES-256-GCM
              </span>
              <span className="rounded-md bg-sky-500/15 border border-sky-500/30 px-2 py-0.5 text-sky-200">
                6. Cloudflare/WAF Edge &amp; DNS/DoH Intel
              </span>
              <span className="rounded-md bg-purple-500/15 border border-purple-500/30 px-2 py-0.5 text-purple-200">
                7. Header &amp; OSV/NVD CVE Intel
              </span>
            </div>
          </div>

          <label className="flex items-start gap-2.5 cursor-pointer group rounded-xl border border-white/[0.06] bg-black/20 p-3 hover:border-purple-500/30 transition-colors">
            <Checkbox
              checked={checked}
              onCheckedChange={(v) => setChecked(v === true)}
              className="mt-0.5"
            />
            <span className="text-xs leading-relaxed text-slate-300 group-hover:text-white">
              Saya adalah pemilik sah atau memiliki izin tertulis untuk mengaudit domain ini secara pasif.
            </span>
          </label>

          {state.error && (
            <div className="rounded-xl border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-300">
              {state.error}
            </div>
          )}

          <Button
            disabled={pending || !checked}
            className="w-full h-11 bg-gradient-to-r from-purple-600 via-fuchsia-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-white font-bold tracking-wider rounded-xl shadow-[0_0_25px_-5px_rgba(168,85,247,0.6)] cursor-pointer"
          >
            {pending ? (
              "MENYIAPKAN ENGINE AUDIT MENDALAM..."
            ) : (
              <span className="inline-flex items-center gap-2">
                <span>MULAI FULL DEEP AUDIT &amp; VAULT SCAN</span>
                <ArrowRight className="h-4 w-4" />
              </span>
            )}
          </Button>

          <div className="flex items-center justify-center gap-2 text-[11px] font-mono text-slate-400 text-center">
            <ShieldCheck className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
            <span>
              100% Passive GET-Only · Tetap berjalan walau ada Cloudflare/WAF · Terverifikasi Google Developer Bandung
            </span>
          </div>
        </form>
      ) : (
        <div className="pt-1">
          <SentinelAudit embedded />
        </div>
      )}
    </div>
  );
}
