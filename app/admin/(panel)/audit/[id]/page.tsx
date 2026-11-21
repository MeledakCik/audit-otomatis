import { notFound } from "next/navigation";
import { ScanDashboard } from "@/components/scan-dashboard";
import { getScan } from "@/lib/scan-store";

export const dynamic = "force-dynamic";
export const metadata = { title: "Hasil Audit Keamanan | Admin Sentinel-ID" };

export default async function AdminAuditResultPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const scan = await getScan(id);
  if (!scan?.adminOnly) notFound();
  return <ScanDashboard scanId={id} domain={scan.domain} adminMode />;
}
