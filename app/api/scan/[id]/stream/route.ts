import { getScan, subscribe } from "@/lib/scan-store";
import type { ScanLogEvent } from "@/lib/types";

export const dynamic = "force-dynamic";

function sseFrame(event: ScanLogEvent): string {
  return `data: ${JSON.stringify(event)}\n\n`;
}

/**
 * Server-Sent Events endpoint untuk progress scan realtime.
 * Route handler dipakai (bukan Server Action) karena SSE butuh
 * streaming response yang tetap terbuka — Server Action tidak cocok
 * untuk ini.
 */
export async function GET(
  _req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const scan = getScan(id);

  if (!scan) {
    return new Response(`event: error\ndata: ${JSON.stringify({ message: "Scan tidak ditemukan." })}\n\n`, {
      status: 404,
      headers: { "Content-Type": "text/event-stream" },
    });
  }

  const encoder = new TextEncoder();
  let unsubscribe: () => void = () => {};

  const stream = new ReadableStream({
    start(controller) {
      // Replay log yang sudah ada dulu supaya client yang connect
      // belakangan tetap dapat state lengkap.
      for (const evt of scan.logs) {
        controller.enqueue(encoder.encode(sseFrame(evt)));
      }

      // Kalau scan sudah selesai/blocked/error sebelum client connect,
      // langsung tutup stream setelah replay.
      if (["done", "error", "blocked_cloudflare"].includes(scan.status)) {
        controller.close();
        return;
      }

      unsubscribe = subscribe(id, (evt) => {
        controller.enqueue(encoder.encode(sseFrame(evt)));
        if (evt.type === "done" || evt.type === "error" || evt.type === "blocked") {
          controller.close();
        }
      });
    },
    cancel() {
      unsubscribe();
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    },
  });
}
