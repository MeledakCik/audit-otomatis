"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { ThemeToggle } from "@/components/theme-toggle";

/**
 * Kenapa komponen ini butuh JS buat ngatur tinggi iframe (bukan cuma
 * `className="h-full"` doang):
 *
 * iframe itu "replaced element" — tinggi persentase (100%/h-full) padanya
 * cuma valid kalau containing block-nya punya tinggi yang eksplisit
 * (bukan hasil `flex-grow`). Di banyak browser, tinggi flex item yang
 * didapat dari flex-grow TIDAK dihitung sebagai "definite height" buat
 * resolusi persentase anak yang replaced element — jadi `h-full` di
 * iframe diam-diam gagal dan iframe balik ke tinggi default browser
 * (150px), walau parent-nya (`<main>`) sendiri sudah punya tinggi yang
 * benar. Ini yang bikin report keliatan "kepotong jadi hitam": iframe
 * cuma setinggi 150px, sisa area `<main>` yang jauh lebih tinggi cuma
 * nampilin background gelap app-nya doang.
 *
 * Fix paling reliable lintas-browser & lintas-context-embed (termasuk
 * kalau halaman ini sendiri di-embed di iframe platform lain) adalah
 * ukur tinggi header secara langsung lewat ResizeObserver, lalu set
 * tinggi iframe eksplisit dalam px lewat inline style — nggak
 * bergantung sama resolusi persentase CSS sama sekali.
 */
export function ReportFrame({ id, domain }: { id: string; domain: string }) {
  const headerRef = useRef<HTMLElement>(null);
  const [iframeHeight, setIframeHeight] = useState<number | null>(null);

  useEffect(() => {
    const headerEl = headerRef.current;
    if (!headerEl) return;

    function recompute() {
      const headerH = headerEl?.getBoundingClientRect().height ?? 0;
      setIframeHeight(Math.max(200, window.innerHeight - headerH));
    }

    recompute();

    const ro = new ResizeObserver(recompute);
    ro.observe(headerEl);
    window.addEventListener("resize", recompute);
    return () => {
      ro.disconnect();
      window.removeEventListener("resize", recompute);
    };
  }, []);

  return (
    <div className="flex flex-1 flex-col overflow-hidden">
      <header
        ref={headerRef}
        className="border-b border-white/10 bg-[#120e1b]/80 backdrop-blur-sm shrink-0"
      >
        <div className="mx-auto max-w-7xl px-4 sm:px-6 py-3.5 flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3 min-w-0">
            <Link
              href={`/scan/${id}`}
              className="flex items-center justify-center h-8 w-8 rounded-lg border border-white/10 bg-white/[0.02] hover:bg-white/[0.06] text-slate-300 transition-colors shrink-0"
              title="Kembali ke Scan"
            >
              <span className="text-sm">←</span>
            </Link>
            <span className="text-sm font-semibold tracking-tight truncate text-slate-200">
              {domain} — <span className="text-purple-400">Report</span>
            </span>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <a
              href={`/api/scan/${id}/report?download=1`}
              download
              className="inline-flex items-center justify-center rounded-lg border border-white/10 bg-[#1a1426] px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-200 hover:border-purple-500/50 hover:bg-purple-500/10 transition-all shadow-sm"
            >
              Export .HTML
            </a>
            <a
              href={`/api/scan/${id}/export`}
              download
              className="inline-flex items-center justify-center rounded-lg border border-white/10 bg-[#1a1426] px-3 py-1.5 text-[11px] font-semibold uppercase tracking-wider text-slate-200 hover:border-purple-500/50 hover:bg-purple-500/10 transition-all shadow-sm"
            >
              Export .MD
            </a>
            <a
              href={`/api/scan/${id}/graph`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center justify-center rounded-lg border border-purple-500/50 bg-purple-600 px-3.5 py-1.5 text-[11px] font-bold uppercase tracking-wider text-white hover:bg-purple-500 hover:shadow-[0_0_12px_rgba(168,85,247,0.4)] transition-all shadow-sm"
            >
              View Graph.json
            </a>
            <div className="border-l border-white/10 pl-2 ml-1">
              <ThemeToggle />
            </div>
          </div>
        </div>
      </header>

      {/* report.html sudah berupa dokumen lengkap (punya <html>/<head> sendiri
          dengan styling gelap khusus pentest report), jadi ditampilkan lewat
          iframe ke route yang sama persis dengan yang diunduh — supaya yang
          dilihat di preview identik dengan file yang di-export, tidak ada
          versi ganda yang bisa beda.

          Tinggi diset eksplisit dalam px lewat state di atas (bukan
          className h-full) supaya nggak kena masalah resolusi persentase
          tinggi pada iframe di dalam flex container — lihat komentar di
          atas komponen ini. Sebelum ResizeObserver sempat jalan, fallback
          minHeight 70dvh dipakai supaya nggak kelihatan kosong sama sekali. */}
      <iframe
        src={`/api/scan/${id}/report`}
        title={`Pentest report — ${domain}`}
        className="w-full border-0 bg-[#0a0710] block"
        style={{
          height: iframeHeight != null ? `${iframeHeight}px` : undefined,
          minHeight: iframeHeight != null ? undefined : "70dvh",
        }}
      />
    </div>
  );
}
