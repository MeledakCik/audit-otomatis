import { Suspense } from "react";
import { SubdomainWatchView } from "@/components/subdomain-watch/subdomain-watch-view";
import { buildPageMetadata } from "@/lib/seo-master";

export const dynamic = "force-dynamic";

export const metadata = buildPageMetadata("/scan/subdomain");

export default function SubdomainWatchPage() {
  return (
    <Suspense fallback={null}>
      <SubdomainWatchView />
    </Suspense>
  );
}
