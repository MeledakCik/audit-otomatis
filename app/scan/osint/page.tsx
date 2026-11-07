import { OsintView } from "@/components/osint/osint-view";
import { buildPageMetadata } from "@/lib/seo-master";

export const dynamic = "force-dynamic";

export const metadata = buildPageMetadata("/scan/osint");

export default function OsintPage() {
  return <OsintView />;
}
