import { isPrivateOrReservedHost } from "@/lib/validate-domain";
import { lookupSubdomainsFromCrtSh } from "@/lib/subdomain-watch/crt";

interface ScanBody {
  domain?: string;
}

const BARE_DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,}$/i;

/**
 * Proxy ke crt.sh untuk menghindari CORS di browser. 100% pasif: satu request
 * GET ke Certificate Transparency log publik, tidak ada bruteforce DNS.
 */
export async function POST(req: Request) {
  let body: ScanBody;
  try {
    body = (await req.json()) as ScanBody;
  } catch {
    return Response.json({ ok: false, error: "Body request tidak valid (harus JSON)." }, { status: 400 });
  }

  const domain = (body.domain ?? "").trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");

  if (!domain || !BARE_DOMAIN_RE.test(domain)) {
    return Response.json({ ok: false, error: "Format domain tidak valid. Contoh: sentinel-id.net" }, { status: 400 });
  }

  if (isPrivateOrReservedHost(domain)) {
    return Response.json(
      { ok: false, error: "Domain ini termasuk jaringan privat/internal dan diblokir untuk mencegah SSRF." },
      { status: 400 }
    );
  }

  const result = await lookupSubdomainsFromCrtSh(domain);
  if (!result.ok) {
    return Response.json({ ok: false, error: result.error }, { status: 502 });
  }

  return Response.json({
    ok: true,
    domain,
    subdomains: result.subdomains,
    totalFound: result.totalBeforeLimit,
    truncated: result.truncated,
  });
}
