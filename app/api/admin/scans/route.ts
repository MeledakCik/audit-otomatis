import { NextResponse } from "next/server";
import { guardAdmin, noStore } from "@/lib/sentinel/admin-auth";
import { deleteScan, getScan, markStopped, requestStop, stopAllRunning } from "@/lib/scan-store";
import { deleteQc, stopAllRunningQcs, stopQc } from "@/lib/qc-store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

const ID_RE = /^[A-Za-z0-9_-]{6,32}$/;
const ADMIN_STOP_REASON = "Dihentikan oleh admin.";

/**
 * Kontrol sesi scan/QC oleh admin (hemat Redis: hentikan scan macet atau hapus datanya).
 * Body: { action: "stop" | "delete" | "stop_all", kind?: "scan" | "qc", id?: string }
 */
export async function POST(req: Request) {
  const denied = await guardAdmin(req);
  if (denied) return denied;

  const body = await req.json().catch(() => null);
  const action = body?.action;
  const kind = body?.kind === "qc" ? "qc" : "scan";
  const id = typeof body?.id === "string" ? body.id : "";

  try {
    if (action === "stop_all") {
      const [scans, qcs] = await Promise.all([stopAllRunning(ADMIN_STOP_REASON), stopAllRunningQcs(ADMIN_STOP_REASON)]);
      return NextResponse.json({ ok: true, stopped: { scans, qcs } }, { headers: noStore });
    }

    if (!["stop", "delete"].includes(action) || !ID_RE.test(id)) {
      return NextResponse.json({ error: "Request tidak valid" }, { status: 400, headers: noStore });
    }

    if (kind === "qc") {
      if (action === "stop") await stopQc(id, ADMIN_STOP_REASON);
      else await deleteQc(id);
      return NextResponse.json({ ok: true, action, kind, id }, { headers: noStore });
    }

    if (action === "stop") {
      const scan = await getScan(id);
      if (!scan) return NextResponse.json({ error: "Scan tidak ditemukan" }, { status: 404, headers: noStore });
      await requestStop(id, ADMIN_STOP_REASON); // sinyal ke runner di instance mana pun
      await markStopped(id, ADMIN_STOP_REASON); // langsung terminal → stream/polling client berhenti
    } else {
      await deleteScan(id);
    }
    return NextResponse.json({ ok: true, action, kind, id }, { headers: noStore });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Gagal memproses permintaan" },
      { status: 500, headers: noStore }
    );
  }
}
