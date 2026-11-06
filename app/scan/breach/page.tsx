import { Suspense } from "react";
import { BreachPeekView } from "@/components/breach-peek/breach-peek-view";
import { buildPageMetadata } from "@/lib/seo-master";

export const dynamic = "force-dynamic";

export const metadata = buildPageMetadata("/scan/breach");

export default function BreachPeekPage() {
  return (
    <Suspense fallback={null}>
      <BreachPeekView />
    </Suspense>
  );
}
