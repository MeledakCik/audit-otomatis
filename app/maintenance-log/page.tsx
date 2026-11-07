import { MaintenanceLogView } from "@/components/maintenance/maintenance-log-view";
import { buildPageMetadata } from "@/lib/seo-master";

export const dynamic = "force-dynamic";

export const metadata = buildPageMetadata("/maintenance-log");

export default function MaintenanceLogPage() {
  return <MaintenanceLogView />;
}
