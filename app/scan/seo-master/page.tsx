import { Suspense } from "react";
import { SeoMasterView } from "@/components/seo-master/seo-master-view";
import { buildPageMetadata } from "@/lib/seo-master";

export const dynamic = "force-dynamic";

export const metadata = buildPageMetadata("/scan/seo-master");

export default function SeoMasterPage() {
  return (
    <Suspense fallback={<div className="p-8 text-xs font-mono text-slate-400">Memuat SEO Master Engine...</div>}>
      <SeoMasterView />
    </Suspense>
  );
}
