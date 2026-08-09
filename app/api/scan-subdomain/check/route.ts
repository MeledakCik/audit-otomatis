import { checkSubdomainTakeover } from "@/lib/subdomain-watch/takeover-check";

interface CheckBody {
  subdomain?: string;
  rootDomain?: string;
}

/**
 * Cek heuristik takeover untuk SATU subdomain: CNAME lookup via DNS-over-HTTPS
 * + satu GET request pasif untuk cocokkan fingerprint. Dijalankan per-item dari
 * client (dengan concurrency terbatas) supaya tidak membanjiri target maupun
 * resolver DoH.
 */
export async function POST(req: Request) {
  let body: CheckBody;
  try {
    body = (await req.json()) as CheckBody;
  } catch {
    return Response.json({ ok: false, error: "Body request tidak valid (harus JSON)." }, { status: 400 });
  }

  const subdomain = (body.subdomain ?? "").trim().toLowerCase();
  const rootDomain = (body.rootDomain ?? "").trim().toLowerCase();

  if (!subdomain || !rootDomain) {
    return Response.json({ ok: false, error: "subdomain dan rootDomain wajib diisi." }, { status: 400 });
  }

  const row = await checkSubdomainTakeover(subdomain, rootDomain);
  return Response.json({ ok: true, row });
}
