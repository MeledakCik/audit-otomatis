import { notFound } from "next/navigation";
import { getScan } from "@/lib/scan-store";
import { ScanDashboard } from "@/components/scan-dashboard";

export default async function ScanPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const scan = await getScan(id);

  if (!scan) {
    notFound();
  }

  return <ScanDashboard scanId={id} domain={scan.domain} />;
}
