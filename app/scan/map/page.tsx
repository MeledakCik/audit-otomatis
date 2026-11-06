import { AttackMapLazy } from "@/components/attack-map/attack-map-lazy";
import { buildPageMetadata } from "@/lib/seo-master";

export const dynamic = "force-dynamic";

export const metadata = buildPageMetadata("/scan/map");

export default function AttackSurfaceMapPage() {
  return <AttackMapLazy />;
}
