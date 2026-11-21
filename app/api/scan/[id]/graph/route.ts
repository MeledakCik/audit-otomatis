import { getScan } from "@/lib/scan-store";
import { guardPrivateScan } from "@/lib/sentinel/scan-access";

export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const scan = await getScan(id);

  if (!scan) {
    return new Response(JSON.stringify({ error: "Scan tidak ditemukan." }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  }
  const denied = await guardPrivateScan(req, scan);
  if (denied) return denied;

  const filename = `graph-${scan.domain}-${scan.id}.json`;

  return new Response(JSON.stringify(scan.graph, null, 2), {
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Content-Disposition": `inline; filename="${filename}"`,
    },
  });
}
