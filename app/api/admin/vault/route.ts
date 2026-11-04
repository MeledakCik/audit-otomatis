import { NextResponse } from "next/server";
import { guardAdmin, noStore } from "@/lib/sentinel/admin-auth";
import { listVault, readVault } from "@/lib/sentinel/store";

export const runtime = "nodejs";

// List: hanya metadata (domain, id, sisa TTL). Tidak ada plaintext.
export async function GET(req: Request) {
  const denied = await guardAdmin(req);
  if (denied) return denied;
  return NextResponse.json({ items: await listVault() }, { headers: noStore });
}

// Decrypt & View: key divalidasi regex ketat → admin tidak bisa dipakai membaca key Redis lain.
export async function POST(req: Request) {
  const denied = await guardAdmin(req);
  if (denied) return denied;
  const body = await req.json().catch(() => null);
  try {
    const ev = await readVault(String(body?.key ?? ""));
    if (!ev) return NextResponse.json({ error: "Entry sudah kedaluwarsa" }, { status: 404, headers: noStore });
    console.info(`[vault] decrypt key=${body.key}`); // hanya nama key, TIDAK PERNAH isi
    return NextResponse.json({ evidence: ev }, { headers: noStore });
  } catch {
    return NextResponse.json({ error: "Gagal decrypt" }, { status: 400, headers: noStore });
  }
}
