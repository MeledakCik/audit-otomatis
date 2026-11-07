import { ScanHistoryList } from "@/components/scan-history-list";
import { buildPageMetadata } from "@/lib/seo-master";

export const dynamic = "force-dynamic";

export const metadata = buildPageMetadata("/history");

export default function HistoryPage() {
  return <ScanHistoryList />;
}
