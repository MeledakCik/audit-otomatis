import type { Metadata } from "next";
import { Suspense } from "react";
import JSScannerClient from "@/components/JSScannerClient";

export const metadata: Metadata = {
  title: "JS Library & 3rd-party Tracker Fingerprint — Sentinel-ID",
  description:
    "Scan JavaScript dependencies and third-party trackers. Detect outdated libraries, known vulnerabilities, and privacy risks in your supply chain.",
};

export default function JSScanPage() {
  return (
    <main className="min-h-screen bg-[#0B0F19] text-[#EAF0FA]">
      {/* Hero Section - Minimalis seperti gambar kedua */}
      <section className="border-b border-[#232B3D] px-6 pb-12 pt-16">
        <div className="mx-auto max-w-4xl">
          <div className="flex items-center gap-3 mb-3">
            <span className="font-mono text-xs uppercase tracking-[0.25em] text-[#3FA796]">
              Sentinel-ID / Supply Chain
            </span>
          </div>
          <h1 className="text-3xl font-semibold leading-tight tracking-tight sm:text-4xl">
            JS Library &amp; 3rd-party Tracker Fingerprint
          </h1>
          <p className="mt-2 max-w-2xl text-[#A9B4CC]">
            Scan JavaScript dependencies and third-party trackers. Detect
            outdated libraries, known vulnerabilities, and privacy risks in your
            supply chain.
          </p>
        </div>
      </section>

      <div className="pt-10 pb-24">
        <Suspense
          fallback={
            <div className="mx-auto max-w-4xl px-6 py-12 text-center text-xs font-mono text-[#7C89A6]">
              Loading JS Scanner...
            </div>
          }
        >
          <JSScannerClient />
        </Suspense>
      </div>
    </main>
  );
}