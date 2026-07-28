import { getQc } from "@/lib/qc-store";

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const qc = await getQc(id);

  if (!qc) {
    return Response.json({ error: "QC tidak ditemukan." }, { status: 404 });
  }

  return Response.json({
    id: qc.id,
    domain: qc.domain,
    origin: qc.origin,
    modules: qc.modules,
    status: qc.status,
    createdAt: qc.createdAt,
    requestsMade: qc.requestsMade,
    result: qc.result,
    error: qc.error,
  });
}
