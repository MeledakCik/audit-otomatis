import { listScans } from "@/lib/scan-store";

export const dynamic = "force-dynamic";

export async function GET() {
  try {
    const scans = await listScans(50);
    return Response.json({ scans });
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error("[api/history] gagal ambil riwayat scan:", err);
    const message = err instanceof Error ? err.message : "Gagal ambil riwayat scan.";
    return Response.json({ error: message }, { status: 500 });
  }
}
