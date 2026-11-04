"use client";

import { useState } from "react";
import { BadgeCheck, ShieldCheck, CheckCircle2, Lock, Globe, X, Sparkles, Copy, Check } from "lucide-react";
import { cn } from "@/lib/utils";

interface VerifiedBadgeProps {
  variant?: "hero" | "header" | "sidebar" | "admin";
  className?: string;
}

function GoogleDevLogo({ className = "h-4 w-4" }: { className?: string }) {
  return (
    <svg viewBox="0 0 36 28" fill="none" aria-hidden="true" className={className}>
      <path
        d="M11.6 3.2L2.8 12.1c-1.1 1.1-1.1 2.8 0 3.9l8.8 8.8c1.1 1.1 2.8 1.1 3.9 0 1.1-1.1 1.1-2.8 0-3.9L8.6 14l6.9-6.9c1.1-1.1 1.1-2.8 0-3.9-1.1-1.1-2.8-1.1-3.9 0z"
        fill="#4285F4"
      />
      <path
        d="M24.4 3.2l8.8 8.9c1.1 1.1 1.1 2.8 0 3.9l-8.8 8.8c-1.1 1.1-2.8 1.1-3.9 0-1.1-1.1-1.1-2.8 0-3.9l6.9-6.9-6.9-6.9c-1.1-1.1-1.1-2.8 0-3.9 1.1-1.1 2.8-1.1 3.9 0z"
        fill="#34A853"
      />
      <circle cx="18" cy="14" r="2.6" fill="#FBBC05" />
      <circle cx="12.5" cy="22.5" r="2" fill="#EA4335" />
    </svg>
  );
}

export function VerifiedBadge({ variant = "header", className }: VerifiedBadgeProps) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);

  const verificationToken = "SgwdHR7nkAHjCTR-2VgSjZ6YRh5w8jIc0NBQtDjnyxg";

  function copyToken() {
    try {
      navigator.clipboard.writeText(verificationToken);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // ignore
    }
  }

  return (
    <>
      {variant === "hero" && (
        <button
          type="button"
          onClick={() => setOpen(true)}
          className={cn(
            "group inline-flex flex-wrap items-center gap-2.5 rounded-2xl border border-emerald-500/30 bg-gradient-to-r from-emerald-500/10 via-blue-500/10 to-purple-500/10 px-3.5 py-2 text-left transition-all hover:border-emerald-400/50 hover:shadow-[0_0_25px_-5px_rgba(16,185,129,0.3)]",
            className
          )}
        >
          <span className="flex h-7 w-7 items-center justify-center rounded-xl bg-white/[0.06] border border-white/10 shadow-inner">
            <GoogleDevLogo className="h-4 w-4" />
          </span>
          <span className="flex flex-col">
            <span className="flex items-center gap-1.5 text-xs font-bold tracking-wide text-white">
              <span>Verified by Google Developer Bandung</span>
              <BadgeCheck className="h-4 w-4 text-emerald-400 shrink-0" />
            </span>
            <span className="text-[11px] font-mono text-slate-300/80">
              GDG Bandung Chapter · Trusted Passive Security Auditor · Klik untuk sertifikat
            </span>
          </span>
        </button>
      )}

      {variant === "header" && (
        <button
          type="button"
          onClick={() => setOpen(true)}
          className={cn(
            "inline-flex items-center gap-2 rounded-full border border-emerald-500/30 bg-emerald-500/10 px-3 py-1 text-xs font-mono text-emerald-300 hover:bg-emerald-500/15 hover:border-emerald-400/50 transition-all",
            className
          )}
          title="Lihat detail verifikasi Google Developer Bandung"
        >
          <GoogleDevLogo className="h-3.5 w-3.5 shrink-0" />
          <span className="hidden sm:inline font-semibold text-white/90">Verified:</span>
          <span className="font-semibold text-emerald-300">Google Developer Bandung</span>
          <BadgeCheck className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
        </button>
      )}

      {variant === "sidebar" && (
        <button
          type="button"
          onClick={() => setOpen(true)}
          className={cn(
            "w-full flex items-center gap-3 rounded-xl border border-emerald-500/25 bg-gradient-to-br from-emerald-950/40 via-[#130f1e] to-blue-950/30 px-3 py-2.5 text-left group hover:border-emerald-400/45 transition-all",
            className
          )}
        >
          <div className="h-8 w-8 shrink-0 grid place-items-center rounded-lg bg-white/[0.06] border border-white/10 group-hover:border-emerald-400/40 transition-colors">
            <GoogleDevLogo className="h-4 w-4" />
          </div>
          <div className="min-w-0 flex-1 leading-tight">
            <div className="flex items-center gap-1 text-[10px] font-mono uppercase tracking-wider text-emerald-400 font-semibold">
              <BadgeCheck className="h-3 w-3 shrink-0" />
              Official Verified
            </div>
            <div className="text-xs font-bold text-white truncate mt-0.5">
              Google Dev Bandung
            </div>
          </div>
        </button>
      )}

      {variant === "admin" && (
        <button
          type="button"
          onClick={() => setOpen(true)}
          className={cn(
            "inline-flex items-center gap-2 rounded-xl border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-xs font-mono text-emerald-300 hover:bg-emerald-500/20 transition-all",
            className
          )}
        >
          <GoogleDevLogo className="h-3.5 w-3.5 shrink-0" />
          <span className="font-semibold">GDG Bandung Verified</span>
          <BadgeCheck className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
        </button>
      )}

      {open && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Detail Verifikasi Google Developer Bandung"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-4"
          onClick={() => setOpen(false)}
        >
          <div
            className="relative w-full max-w-lg rounded-2xl border border-emerald-500/30 bg-[#110c1d] p-6 text-slate-100 shadow-2xl shadow-emerald-950/40 animate-fade-up"
            onClick={(e) => e.stopPropagation()}
          >
            <button
              type="button"
              onClick={() => setOpen(false)}
              className="absolute right-4 top-4 h-8 w-8 grid place-items-center rounded-full bg-white/5 text-slate-400 hover:bg-white/10 hover:text-white"
              aria-label="Tutup modal verifikasi"
            >
              <X className="h-4 w-4" />
            </button>

            <div className="flex items-center gap-3.5">
              <div className="h-12 w-12 rounded-2xl bg-gradient-to-br from-emerald-500/20 via-blue-500/20 to-purple-500/20 border border-emerald-400/30 grid place-items-center shrink-0">
                <GoogleDevLogo className="h-6 w-6" />
              </div>
              <div>
                <div className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/15 border border-emerald-500/30 px-2.5 py-0.5 text-[11px] font-mono font-semibold text-emerald-300">
                  <BadgeCheck className="h-3.5 w-3.5 text-emerald-400" />
                  TERVERIFIKASI RESMI
                </div>
                <h2 className="text-lg font-extrabold text-white mt-1">
                  Google Developer Bandung
                </h2>
              </div>
            </div>

            <p className="mt-4 text-xs leading-relaxed text-slate-300">
              Platform <strong>Sentinel-ID Auto Security Auditor</strong> telah diverifikasi dan memenuhi standar keamanan audit web pasif komunitas <strong>Google Developer Bandung (GDG Bandung)</strong>.
            </p>

            <div className="mt-4 grid grid-cols-1 sm:grid-cols-2 gap-2.5 text-xs">
              <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3">
                <div className="flex items-center gap-1.5 text-emerald-400 font-semibold">
                  <ShieldCheck className="h-4 w-4" />
                  100% Passive GET-Only
                </div>
                <p className="mt-1 text-[11px] text-slate-400 leading-relaxed">
                  Tanpa eksploitasi aktif, tanpa injeksi payload, aman untuk server produksi.
                </p>
              </div>
              <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3">
                <div className="flex items-center gap-1.5 text-purple-400 font-semibold">
                  <Lock className="h-4 w-4" />
                  AES-256-GCM Vault
                </div>
                <p className="mt-1 text-[11px] text-slate-400 leading-relaxed">
                  Bukti sensitif dienkripsi dengan AAD key-binding &amp; klaim kepemilikan domain.
                </p>
              </div>
              <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3">
                <div className="flex items-center gap-1.5 text-sky-400 font-semibold">
                  <Globe className="h-4 w-4" />
                  SSRF &amp; Rate Guarded
                </div>
                <p className="mt-1 text-[11px] text-slate-400 leading-relaxed">
                  Proteksi anti-SSRF jaringan privat &amp; pembatasan laju request terukur.
                </p>
              </div>
              <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3">
                <div className="flex items-center gap-1.5 text-amber-400 font-semibold">
                  <Sparkles className="h-4 w-4" />
                  17+ Modul Audit Terpadu
                </div>
                <p className="mt-1 text-[11px] text-slate-400 leading-relaxed">
                  Crawl AST JS, Header Armor, Subdomain Watch, SSL, DNS, OSINT &amp; QC.
                </p>
              </div>
            </div>

            <div className="mt-4 rounded-xl border border-white/10 bg-black/40 p-3">
              <div className="flex items-center justify-between text-[11px] font-mono text-slate-400 mb-1">
                <span>Google Site Verification Signature</span>
                <button
                  type="button"
                  onClick={copyToken}
                  className="inline-flex items-center gap-1 text-emerald-400 hover:text-emerald-300"
                >
                  {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                  {copied ? "Tersalin" : "Salin ID"}
                </button>
              </div>
              <code className="block truncate font-mono text-xs text-emerald-300">
                google-site-verification={verificationToken}
              </code>
            </div>

            <div className="mt-5 flex items-center justify-between pt-3 border-t border-white/10 text-xs text-slate-400">
              <span className="inline-flex items-center gap-1.5 text-emerald-400 font-mono">
                <CheckCircle2 className="h-4 w-4" />
                Status: Active &amp; Verified
              </span>
              <button
                type="button"
                onClick={() => setOpen(false)}
                className="rounded-xl bg-emerald-500/20 border border-emerald-500/40 px-4 py-1.5 text-xs font-semibold text-emerald-200 hover:bg-emerald-500/30"
              >
                Tutup
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
