import { Suspense } from "react";
import { SubdomainWatchView } from "@/components/subdomain-watch/subdomain-watch-view";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "Subdomain Takeover Watch",
  description: "Temukan subdomain via crt.sh dan cek indikasi subdomain takeover secara pasif — tanpa DNS bruteforce.",
};

export default function SubdomainWatchPage() {
  return (
    <Suspense fallback={null}>
      <SubdomainWatchView />
    </Suspense>
  );
}
