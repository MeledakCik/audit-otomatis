import { getScan } from "@/lib/scan-store";


export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const scan = await getScan(id);

  if (!scan) {
    return Response.json({ error: "Scan tidak ditemukan." }, { status: 404 });
  }

  return Response.json({
    id: scan.id,
    domain: scan.domain,
    status: scan.status,
    createdAt: scan.createdAt,
    requestsMade: scan.requestsMade,
    endpointsDiscovered: scan.endpointsDiscovered,
    pagesCrawled: scan.pagesCrawled,
    jsFilesScanned: scan.jsFilesScanned,
    findingsCount: scan.findings.length,
    blockedReason: scan.blockedReason,
  });
}
