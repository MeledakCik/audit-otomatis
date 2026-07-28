import { getQc } from "@/lib/qc-store";
import { exportQcToObsidianMarkdown } from "@/lib/qc-export-markdown";

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const qc = await getQc(id);

  if (!qc) {
    return new Response("QC tidak ditemukan.", { status: 404 });
  }

  const markdown = exportQcToObsidianMarkdown(qc);
  const filename = `qc-${qc.domain}-${qc.id}.md`;

  return new Response(markdown, {
    headers: {
      "Content-Type": "text/markdown; charset=utf-8",
      "Content-Disposition": `attachment; filename="${filename}"`,
    },
  });
}
