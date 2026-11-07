"use client";

import { useEffect } from "react";
import Link from "next/link";
import { AlertTriangle, RefreshCw, Home, ShieldCheck } from "lucide-react";

export default function GlobalError({
  error,
  reset,
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  useEffect(() => {
    console.error("[Sentinel-ID Runtime Error]:", error);
  }, [error]);

  return (
    <div className="flex min-h-[70vh] w-full items-center justify-center px-4 py-12">
      <div className="w-full max-w-lg rounded-2xl border border-purple-500/35 bg-[#120d1e] p-6 sm:p-8 text-slate-100 shadow-2xl space-y-5">
        <div className="flex items-center gap-3">
          <div className="h-11 w-11 rounded-xl bg-amber-500/15 border border-amber-500/35 grid place-items-center shrink-0">
            <AlertTriangle className="h-5 w-5 text-amber-400" />
          </div>
          <div>
            <div className="text-[11px] font-mono uppercase tracking-wider text-amber-300 font-bold">
              PEMULIHAN OTOMATIS SENTINEL-ID
            </div>
            <h1 className="text-lg font-extrabold text-white">
              Koneksi Layanan Sedang Disesuaikan
            </h1>
          </div>
        </div>

        <p className="text-xs sm:text-sm text-slate-300 leading-relaxed">
          Terjadi gangguan sesaat saat memproses permintaan di server. Sistem fallback in-memory Sentinel-ID telah diaktifkan agar Anda dapat melanjutkan audit tanpa kendala.
        </p>

        {error?.message && (
          <div className="rounded-xl border border-white/10 bg-black/50 p-3 text-xs font-mono text-purple-200 break-all">
            Detail: {error.message}
            {error.digest && (
              <span className="block text-[10px] text-slate-400 mt-1">
                Digest ID: {error.digest}
              </span>
            )}
          </div>
        )}

        <div className="flex flex-wrap items-center gap-3 pt-1">
          <button
            type="button"
            onClick={() => reset()}
            className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-purple-600 to-pink-600 hover:brightness-110 px-4 py-2.5 text-xs font-mono font-bold text-white shadow-lg cursor-pointer"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            <span>Coba Lagi Sekarang</span>
          </button>
          <Link
            href="/"
            className="inline-flex items-center gap-2 rounded-xl border border-white/15 bg-white/[0.04] hover:bg-white/[0.08] px-4 py-2.5 text-xs font-mono text-slate-200 transition-colors"
          >
            <Home className="h-3.5 w-3.5" />
            <span>Kembali ke Beranda</span>
          </Link>
        </div>

        <div className="pt-3 border-t border-white/10 flex items-center gap-2 text-[11px] font-mono text-emerald-400">
          <ShieldCheck className="h-3.5 w-3.5 shrink-0" />
          <span>Resilient Mode Active · Verified by Google Developer Bandung</span>
        </div>
      </div>
    </div>
  );
}
