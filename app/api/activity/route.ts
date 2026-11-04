import { NextResponse } from "next/server";
import { logUserActivity, type ActivityModule, type ActivityStatus } from "@/lib/activity-store";

export const runtime = "nodejs";

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => null);
    if (!body || typeof body.module !== "string") {
      return NextResponse.json({ ok: false, error: "Invalid payload" }, { status: 400 });
    }
    const rec = await logUserActivity({
      req,
      module: body.module as ActivityModule,
      action: String(body.action || "Aktivitas Pengguna"),
      target: String(body.target || "-").slice(0, 200),
      status: (body.status as ActivityStatus) || "SUCCESS",
      summary: String(body.summary || "").slice(0, 300),
      meta: typeof body.meta === "object" && body.meta ? body.meta : undefined,
    });
    return NextResponse.json({ ok: true, id: rec.id });
  } catch {
    return NextResponse.json({ ok: false }, { status: 500 });
  }
}
