import { notFound } from "next/navigation";
import { getScan, createScan } from "@/lib/scan-store";
import { ScanDashboard } from "@/components/scan-dashboard";

export const dynamic = "force-dynamic";

export default async function ScanPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ domain?: string }>;
}) {
  const { id } = await params;
  const sp = await searchParams;
  let scan = await getScan(id);

  if (!scan && sp?.domain) {
    const cleanDomain = sp.domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (cleanDomain) {
      scan = await createScan(id, cleanDomain, `https://${cleanDomain}`);
    }
  }

  if (!scan) {
    notFound();
  }

  return <ScanDashboard scanId={id} domain={scan.domain} />;
}
