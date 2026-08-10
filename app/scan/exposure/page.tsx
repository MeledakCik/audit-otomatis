import { Suspense } from "react";
import ScanExposureClient from "@/components/ScanExposureClient";
import { Metadata } from "next";

export const dynamic = "force-dynamic";
export const metadata: Metadata = {
  title: "Cloud Exposure & Misconfig Check — Sentinel-ID",
  description:
    "Passive scan for leaked headers, exposed cloud storage, and accidental .env/.git exposure — one read-only pass, no brute forcing.",
};

export default function ExposureScanPage() {
  return (
    <Suspense fallback={null}>
      <ScanExposureClient />
    </Suspense>
  );
}
