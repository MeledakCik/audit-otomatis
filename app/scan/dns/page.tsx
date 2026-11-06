import { DnsIntelView } from "@/components/dns-intel/dns-intel-view";
import { buildPageMetadata } from "@/lib/seo-master";

export const dynamic = "force-dynamic";

export const metadata = buildPageMetadata("/scan/dns");

export default function DnsIntelPage() {
  return <DnsIntelView />;
}
