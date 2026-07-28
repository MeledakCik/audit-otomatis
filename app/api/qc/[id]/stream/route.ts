import { getQc, getQcLogsSince } from "@/lib/qc-store";
import type { QcLogEvent } from "@/lib/qc-types";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
export const maxDuration = 300;

const POLL_INTERVAL_MS = 1000;
const HEARTBEAT_INTERVAL_MS = 15000;
const MAX_STREAM_MS = 280_000;

const TERMINAL_STATUSES = new Set(["done", "error"]);

function sseFrame(id: number, event: QcLogEvent): string {
  return `id: ${id}\ndata: ${JSON.stringify(event)}\n\n`;
}

export async function GET(req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const qc = await getQc(id);

  if (!qc) {
    return new Response(
      `event: error\ndata: ${JSON.stringify({
        message: "QC tidak ditemukan (ID salah, atau sudah kedaluwarsa setelah 30 menit).",
      })}\n\n`,
      { status: 404, headers: { "Content-Type": "text/event-stream" } }
    );
  }

  const lastEventIdHeader = req.headers.get("last-event-id");
  const parsedCursor = lastEventIdHeader ? parseInt(lastEventIdHeader, 10) + 1 : 0;
  let cursor = Number.isFinite(parsedCursor) && parsedCursor >= 0 ? parsedCursor : 0;

  const encoder = new TextEncoder();
  const startedAt = Date.now();
  let cancelled = false;

  const stream = new ReadableStream({
    async start(controller) {
      let closed = false;
      const safeClose = () => {
        if (closed) return;
        closed = true;
        try {
          controller.close();
        } catch {
          // ignore
        }
      };

      let lastHeartbeat = Date.now();

      try {
        while (!closed && !cancelled) {
          const logs = await getQcLogsSince(id, cursor);

          for (const evt of logs) {
            controller.enqueue(encoder.encode(sseFrame(cursor, evt)));
            cursor++;
            if (evt.type === "done" || evt.type === "error") {
              safeClose();
              return;
            }
          }

          if (closed || cancelled) return;

          const current = await getQc(id);
          if (!current || TERMINAL_STATUSES.has(current.status)) {
            safeClose();
            return;
          }

          if (Date.now() - startedAt > MAX_STREAM_MS) {
            safeClose();
            return;
          }

          if (Date.now() - lastHeartbeat > HEARTBEAT_INTERVAL_MS) {
            controller.enqueue(encoder.encode(`: heartbeat\n\n`));
            lastHeartbeat = Date.now();
          }

          await new Promise((resolve) => setTimeout(resolve, POLL_INTERVAL_MS));
        }
      } catch (err) {
        if (!closed) {
          try {
            controller.enqueue(
              encoder.encode(
                `event: error\ndata: ${JSON.stringify({
                  message: err instanceof Error ? err.message : "Stream error tidak diketahui.",
                })}\n\n`
              )
            );
          } catch {
            // ignore
          }
          safeClose();
        }
      }
    },
    cancel() {
      cancelled = true;
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
