import { SourceAuditView } from "@/components/source-audit/source-audit-view";
import { buildPageMetadata } from "@/lib/seo-master";

export const metadata = buildPageMetadata("/scan/source");

export default function SourceAuditPage() {
  return <SourceAuditView />;
}
