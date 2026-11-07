import { notFound } from "next/navigation";
import { getQc, createQc } from "@/lib/qc-store";
import { QcDashboard } from "@/components/qc-dashboard";

export const dynamic = "force-dynamic";

export default async function QcReportPage({
  params,
  searchParams,
}: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ domain?: string }>;
}) {
  const { id } = await params;
  const sp = await searchParams;
  let qc = await getQc(id);

  if (!qc && sp?.domain) {
    const cleanDomain = sp.domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (cleanDomain) {
      qc = await createQc(id, cleanDomain, `https://${cleanDomain}`, {
        seo: true,
        perf: true,
        content: true,
      });
    }
  }

  if (!qc) {
    notFound();
  }

  return <QcDashboard qcId={id} domain={qc.domain} modules={qc.modules} />;
}
