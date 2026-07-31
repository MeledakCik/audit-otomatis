import { getScan } from "@/lib/scan-store";
import { detectTechStack } from "@/lib/detect-tech";

export const dynamic = "force-dynamic";

export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;

  try {
    const scan = await getScan(id);

    if (!scan) {
      return Response.json({ error: `scan:${id}: not found` }, { status: 404 });
    }

    const pages = scan.pages ?? [];
    const techStack = detectTechStack(pages);

    return Response.json({
      meta: {
        id: scan.id,
        hostname: scan.domain,
        url: scan.origin,
        createdAt: scan.createdAt,
        status: scan.status,
      },
      pages,
      techStack,
    });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error(`[api/requests/${id}] gagal ambil detail scan:`, err);
    const message = err instanceof Error ? err.message : "Gagal ambil detail scan.";
    return Response.json({ error: message }, { status: 500 });
  }
}
