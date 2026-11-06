import { Suspense } from "react";
import { SecretHunterView } from "@/components/secret-hunter/secret-hunter-view";
import { buildPageMetadata } from "@/lib/seo-master";

export const dynamic = "force-dynamic";

export const metadata = buildPageMetadata("/scan/secrets");

export default function SecretHunterPage() {
  return (
    <Suspense fallback={null}>
      <SecretHunterView />
    </Suspense>
  );
}
