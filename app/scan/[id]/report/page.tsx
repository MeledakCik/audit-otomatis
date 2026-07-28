import { notFound } from "next/navigation";
import { getScan } from "@/lib/scan-store";
import { ReportFrame } from "@/components/report-frame";

export default async function ScanReportPage({
  params,
}: {
  params: Promise<{ id: string }>;
}) {
  const { id } = await params;
  const scan = await getScan(id);

  if (!scan) {
    notFound();
  }

  return <ReportFrame id={id} domain={scan.domain} />;
}