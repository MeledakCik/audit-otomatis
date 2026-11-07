import { Suspense } from "react";
import ThreatLab from "@/components/shield-status/thread";
import { buildPageMetadata } from "@/lib/seo-master";

export const dynamic = "force-dynamic";

export const metadata = buildPageMetadata("/scan/shield-status");

export default function ShieldStatusPage() {
  return (
    <Suspense fallback={null}>
      <ThreatLab />
    </Suspense>
  );
}
