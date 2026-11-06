import { Suspense } from "react";
import { HeaderArmorView } from "@/components/header-armor/header-armor-view";
import { buildPageMetadata } from "@/lib/seo-master";

export const dynamic = "force-dynamic";

export const metadata = buildPageMetadata("/scan/headers");

export default function HeaderArmorPage() {
  return (
    <Suspense fallback={null}>
      <HeaderArmorView />
    </Suspense>
  );
}
