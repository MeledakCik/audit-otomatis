import { Suspense } from "react";
import  ThreatLab  from "@/components/shield-status/thread";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "Threat Lab",
  description: "Pantau status proteksi dan keamanan aplikasi web Anda secara real-time. Lihat apakah ada masalah dengan Shield, latency, dan status guard.",
};

export default function SubdomainWatchPage() {
  return (
    <Suspense fallback={null}>
      <ThreatLab />
    </Suspense>
  );
}
