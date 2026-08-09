import { AttackMapView } from "@/components/attack-map/attack-map-view";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "Attack Surface Map",
  description: "Peta visual attack surface domain kamu — crawl same-origin pasif, GET-only, max depth 2.",
};

export default function AttackSurfaceMapPage() {
  return <AttackMapView />;
}
