import {
  normalizeDomain,
  normalizeEmail,
  normalizeName,
  normalizeUsername,
  osintDomain,
  osintEmail,
  osintName,
  osintUsername,
} from "@/lib/osint/run";

export const dynamic = "force-dynamic";
export const maxDuration = 30;

// Rate limit sederhana per-IP (in-memory): 10 request / menit.
const hits = new Map<string, number[]>();
const WINDOW = 60_000;
const MAX = 10;

function allow(ip: string): { ok: boolean; retryMs: number } {
  const now = Date.now();
  const list = (hits.get(ip) ?? []).filter((t) => now - t < WINDOW);
  if (list.length >= MAX) return { ok: false, retryMs: WINDOW - (now - list[0]) };
  list.push(now);
  hits.set(ip, list);
  return { ok: true, retryMs: 0 };
}

function clientIp(req: Request): string {
  const xff = req.headers.get("x-forwarded-for");
  if (xff) return xff.split(",")[0].trim();
  return req.headers.get("x-real-ip") || "anonymous";
}

export async function GET(req: Request) {
  const rl = allow(clientIp(req));
  if (!rl.ok) {
    return Response.json(
      { ok: false, error: `Rate limit (10 req/menit). Coba lagi ${Math.ceil(rl.retryMs / 1000)} detik.` },
      { status: 429 }
    );
  }

  const { searchParams } = new URL(req.url);
  const type = searchParams.get("type") ?? "";
  const q = searchParams.get("q") ?? "";

  try {
    switch (type) {
      case "domain": {
        const d = normalizeDomain(q);
        if (!d) return Response.json({ ok: false, error: "Domain tidak valid." }, { status: 400 });
        return Response.json({ ok: true, result: await osintDomain(d) });
      }
      case "email": {
        const e = normalizeEmail(q);
        if (!e) return Response.json({ ok: false, error: "Email tidak valid." }, { status: 400 });
        return Response.json({ ok: true, result: await osintEmail(e) });
      }
      case "username": {
        const u = normalizeUsername(q);
        if (!u) {
          return Response.json(
            { ok: false, error: "Username tidak valid (2-40 karakter: huruf, angka, . _ -)." },
            { status: 400 }
          );
        }
        return Response.json({ ok: true, result: await osintUsername(u) });
      }
      case "name": {
        const n = normalizeName(q);
        if (!n) return Response.json({ ok: false, error: "Nama tidak valid (3-80 karakter huruf)." }, { status: 400 });
        return Response.json({ ok: true, result: osintName(n) });
      }
      default:
        return Response.json({ ok: false, error: "type harus: domain | email | username | name" }, { status: 400 });
    }
  } catch {
    return Response.json({ ok: false, error: "Gagal memproses OSINT. Coba lagi." }, { status: 502 });
  }
}
