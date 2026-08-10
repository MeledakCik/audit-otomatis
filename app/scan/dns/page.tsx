import { DnsIntelView } from "@/components/dns-intel/dns-intel-view";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "DNS Intel & Surface Scanner",
  description: "Passive DNS reconnaissance — email security posture & subdomain takeover hints. GET-only, no AXFR.",
};

export default function DnsIntelPage() {
  return <DnsIntelView />;
}
