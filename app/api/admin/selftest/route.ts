import { NextResponse } from "next/server";
import { guardAdmin, noStore } from "@/lib/sentinel/admin-auth";
import { runSelfTest } from "@/lib/sentinel/selftest";

export const runtime = "nodejs";

/**
 * Self-test mesin Audit File Sensitif — TANPA jaringan, TANPA menyentuh domain manapun.
 * Hanya menjalankan fixture tetap lewat kode produksi yang sama, untuk memverifikasi
 * engine masih bekerja sebelum admin memakainya untuk pelaporan ke pihak domain.
 */
export async function POST(req: Request) {
  const denied = await guardAdmin(req);
  if (denied) return denied;
  try {
    const result = runSelfTest();
    return NextResponse.json(result, { headers: noStore });
  } catch (e) {
    return NextResponse.json({ error: e instanceof Error ? e.message : "Self-test gagal dijalankan" }, { status: 500, headers: noStore });
  }
}
