import { notFound } from "next/navigation";
import { getQc } from "@/lib/qc-store";
import { QcDashboard } from "@/components/qc-dashboard";

export default async function QcReportPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const qc = await getQc(id);

  if (!qc) {
    notFound();
  }

  return <QcDashboard qcId={id} domain={qc.domain} modules={qc.modules} />;
}
