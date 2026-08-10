import type { Metadata } from "next";
import ScanExposureClient from "@/components/ScanExposureClient";

export const metadata: Metadata = {
  title: "Cloud Exposure & Misconfig Check — Sentinel-ID",
  description:
    "Passive scan for leaked headers, exposed cloud storage, and accidental .env/.git exposure — one read-only pass, no brute forcing.",
};

export default function ExposureScanPage() {
  return (
    <main className="min-h-screen bg-[#0B0F19] text-[#EAF0FA]">
      {/* ---- Hero: a single sweeping scan-line stands in for the whole
          product idea — this tool listens once, it doesn't probe. ---- */}
      <section className="relative overflow-hidden border-b border-[#232B3D] px-6 pb-16 pt-20">
        <div className="pointer-events-none absolute inset-0 opacity-[0.35]">
          <div className="scan-sweep" />
        </div>
        <div className="relative mx-auto max-w-3xl">
          <p className="font-mono text-xs uppercase tracking-[0.25em] text-[#3FA796]">
            Sentinel-ID / Passive Recon
          </p>
          <h1 className="mt-4 text-4xl font-semibold leading-tight tracking-tight sm:text-5xl">
            Cloud exposure &amp; misconfig check
          </h1>
          <p className="mt-4 max-w-xl text-lg text-[#A9B4CC]">
            One read-only request to a homepage you choose. We read what's already public — response
            headers and page source — and tell you what a stranger could see.
          </p>
        </div>
      </section>

      <div className="pt-12">
        <ScanExposureClient />
      </div>

      <style>{`
        .scan-sweep {
          position: absolute;
          top: 0;
          left: -20%;
          width: 40%;
          height: 100%;
          background: linear-gradient(
            90deg,
            transparent,
            rgba(63, 167, 150, 0.35),
            transparent
          );
          animation: sweep 6s ease-in-out infinite;
        }
        @keyframes sweep {
          0% { transform: translateX(0%); }
          50% { transform: translateX(300%); }
          100% { transform: translateX(0%); }
        }
        @media (prefers-reduced-motion: reduce) {
          .scan-sweep { animation: none; }
        }
      `}</style>
    </main>
  );
}
