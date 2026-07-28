import { getScan } from "@/lib/scan-store";
import { exportScanToObsidianMarkdown } from "@/lib/export-markdown";

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const scan = await getScan(id);

  if (!scan) {
    return new Response("Scan tidak ditemukan.", { status: 404 });
  }

  const markdown = exportScanToObsidianMarkdown(scan);
  const filename = `audit-${scan.domain}-${scan.id}.md`;

  return new Response(markdown, {
    headers: {
      "Content-Type": "text/markdown; charset=utf-8",
      "Content-Disposition": `attachment; filename="${filename}"`,
    },
  });
}
