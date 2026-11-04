import { NextResponse } from "next/server";
import { DOMAIN_RE, getPublic } from "@/lib/sentinel/store";

export const runtime = "nodejs";

export async function GET(_req: Request, ctx: { params: Promise<{ domain: string }> }) {
  const domain = (await ctx.params).domain.toLowerCase();
  if (!DOMAIN_RE.test(domain)) return NextResponse.json({ error: "domain tidak valid" }, { status: 400 });
  const rec = await getPublic(domain);
  return rec ? NextResponse.json(rec) : NextResponse.json({ error: "belum ada hasil audit" }, { status: 404 });
}
