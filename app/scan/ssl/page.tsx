import { Suspense } from "react";
import SSLScannerClient from "@/components/SSLScannerClient";
import { buildPageMetadata } from "@/lib/seo-master";

export const metadata = buildPageMetadata("/scan/ssl");

export default function SSLScanPage() {
  return (
    <div className="min-h-dvh bg-sunken text-foreground">
      <section className="relative overflow-hidden border-b border-line px-6 pb-12 pt-16">
        <div className="pointer-events-none absolute inset-0 opacity-[0.15]">
          <div className="ssl-sweep" />
        </div>
        <div className="relative mx-auto max-w-5xl">
          <div className="flex items-center gap-3 mb-3">
            <span className="font-mono text-xs uppercase tracking-[0.25em] text-ok">
              Sentinel-ID / Security Intel
            </span>
          </div>
          <h1 className="text-3xl font-semibold leading-tight tracking-tight sm:text-4xl">
            SSL/TLS &amp; Certificate Intel Scanner
          </h1>
          <p className="mt-2 max-w-2xl text-soft">
            Passive SSL/TLS handshake analyzer. Extract certificate details,
            security grade, and TLS configuration with zero exploitation.
          </p>
        </div>
      </section>

      <div className="pt-10 pb-24">
        <Suspense
          fallback={
            <div className="mx-auto max-w-5xl px-6 py-12 text-center text-xs font-mono text-muted">
              Loading SSL Scanner...
            </div>
          }
        >
          <SSLScannerClient />
        </Suspense>
      </div>

      <style>{`
        .ssl-sweep {
          position: absolute;
          top: 0;
          left: -20%;
          width: 40%;
          height: 100%;
          background: linear-gradient(
            90deg,
            transparent,
            rgba(63, 167, 150, 0.2),
            transparent
          );
          animation: sweep 8s ease-in-out infinite;
        }
        @keyframes sweep {
          0% { transform: translateX(0%); }
          50% { transform: translateX(300%); }
          100% { transform: translateX(0%); }
        }
        @media (prefers-reduced-motion: reduce) {
          .ssl-sweep { animation: none; }
        }
      `}</style>
    </div>
  );
}