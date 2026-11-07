import { Suspense } from "react";
import ScanExposureClient from "@/components/ScanExposureClient";
import { buildPageMetadata } from "@/lib/seo-master";

export const dynamic = "force-dynamic";
export const metadata = buildPageMetadata("/scan/exposure");

export default function ExposureScanPage() {
  return (
    <Suspense fallback={null}>
      <ScanExposureClient />
    </Suspense>
  );
}
