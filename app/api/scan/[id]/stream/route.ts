import { getScan, getLogsSince } from "@/lib/scan-store";
import type { ScanLogEvent } from "@/lib/types";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";
// Fluid Compute default max di semua plan Vercel per 2026 adalah 300s.
// Kalaupun scan belum selesai saat batas ini tercapai, stream ditutup rapi
// (lihat MAX_STREAM_MS) — browser (EventSource) otomatis reconnect dan
// lanjut dari log terakhir lewat header Last-Event-ID, jadi tidak masalah.
export const maxDuration = 300;

const POLL_INTERVAL_MS = 1000;
const HEARTBEAT_INTERVAL_MS = 15000;
const MAX_STREAM_MS = 280_000; // tutup sedikit sebelum maxDuration

const TERMINAL_STATUSES = new Set(["done", "error", "blocked_cloudflare"]);

function sseFrame(id: number, event: ScanLogEvent): string {
  return `id: ${id}\ndata: ${JSON.stringify(event)}\n\n`;
}

/**
 * Server-Sent Events endpoint untuk progress scan realtime.
 *
 * PENTING: implementasi ini poll ke store (Redis) tiap 1 detik, BUKAN
 * subscribe ke event-emitter in-process seperti sebelumnya — karena di
 * Vercel, request yang membuat scan (Server Action) dan request stream ini
 * bisa (dan sering) dieksekusi di instance serverless yang berbeda, jadi
 * event-emitter in-memory tidak akan pernah ke-trigger dari instance lain.
 * Polling ke storage eksternal adalah pendekatan yang aktual bisa jalan di
 * lingkungan serverless/multi-instance seperti ini.
 */
export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const scan = await getScan(id);

  if (!scan) {
    return new Response(
      `event: error\ndata: ${JSON.stringify({
        message: "Scan tidak ditemukan (ID salah, atau sudah kedaluwarsa setelah 30 menit).",
      })}\n\n`,
      {
        status: 404,
        headers: { "Content-Type": "text/event-stream" },
      }
    );
  }

  // Dukung resume: kalau browser reconnect (mis. karena stream sebelumnya
  // ditutup di batas MAX_STREAM_MS), EventSource otomatis kirim header ini
  // dengan id event terakhir yang diterima, supaya tidak replay dari awal.
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
          // stream mungkin sudah ditutup client-side, aman diabaikan
        }
      };

      let lastHeartbeat = Date.now();

      try {
        // Replay log yang sudah ada dulu (dari cursor) supaya client yang
        // connect belakangan / reconnect tetap dapat state lengkap.
        while (!closed && !cancelled) {
          const logs = await getLogsSince(id, cursor);

          for (const evt of logs) {
            controller.enqueue(encoder.encode(sseFrame(cursor, evt)));
            cursor++;
            if (evt.type === "done" || evt.type === "error" || evt.type === "blocked") {
              safeClose();
              return;
            }
          }

          if (closed || cancelled) return;

          // Kalau tidak ada log baru, cek status langsung — jaga-jaga kalau
          // proses scan crash sebelum sempat emit event "done"/"error".
          const current = await getScan(id);
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
      // Client disconnect (tab ditutup, dsb). Loop polling di atas akan
      // berhenti paling lambat di iterasi berikutnya.
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
