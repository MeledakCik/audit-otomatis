import { Suspense } from "react";
import { StackFingerprintView } from "@/components/stack-fingerprint/stack-fingerprint-view";
import { buildPageMetadata } from "@/lib/seo-master";

export const dynamic = "force-dynamic";

export const metadata = buildPageMetadata("/scan/stack");

export default function StackFingerprintPage() {
  return (
    <Suspense fallback={null}>
      <StackFingerprintView />
    </Suspense>
  );
}
