import { normalizeDnsDomainInput } from "@/lib/dns-intel/validate";
import { buildDnsIntelReport } from "@/lib/dns-intel/build-report";
import { checkDnsRateLimit } from "@/lib/dns-intel/rate-limit";
import { logUserActivity } from "@/lib/activity-store";

export const dynamic = "force-dynamic";

function getClientIp(req: Request): string {
  const xff = req.headers.get("x-forwarded-for");
  if (xff) return xff.split(",")[0].trim();
  return req.headers.get("x-real-ip") || "anonymous";
}

export async function GET(req: Request) {
  const ip = getClientIp(req);
  const rl = await checkDnsRateLimit(ip);
  if (!rl.allowed) {
    return Response.json(
      {
        ok: false,
        error: `Rate limit tercapai (maks 10 request/menit). Coba lagi dalam ${Math.ceil(rl.retryAfterMs / 1000)} detik.`,
      },
      { status: 429 }
    );
  }

  const { searchParams } = new URL(req.url);
  const raw = searchParams.get("domain") ?? "";

  const v = normalizeDnsDomainInput(raw);
  if (!v.ok || !v.domain) {
    return Response.json({ ok: false, error: v.error ?? "Domain tidak valid." }, { status: 400 });
  }

  try {
    const report = await buildDnsIntelReport(v.domain);
    await logUserActivity({
      req,
      module: "DNS_INTEL",
      action: "Analisis DNS & Email Security (SPF/DMARC/DKIM)",
      target: v.domain,
      status: "SUCCESS",
      summary: `DNS lookup selesai untuk ${v.domain}`,
    });
    return Response.json({ ok: true, report });
  } catch {
    return Response.json({ ok: false, error: "Gagal melakukan DNS lookup. Coba lagi." }, { status: 502 });
  }
}
