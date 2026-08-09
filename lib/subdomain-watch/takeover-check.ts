import { isPrivateOrReservedHost } from "@/lib/validate-domain";
import { matchSignatureByCname, bodyMatchesFingerprint } from "./signatures";
import type { SubdomainRow } from "./types";

const DOH_TIMEOUT_MS = 6_000;
const HTTP_TIMEOUT_MS = 7_000;
const BODY_SNIPPET_LIMIT = 4_000;

interface DohAnswer {
  name: string;
  type: number;
  data: string;
}

interface DohResponse {
  Status: number;
  Answer?: DohAnswer[];
}

/**
 * Resolusi CNAME murni pasif via DNS-over-HTTPS (Cloudflare) — tidak ada
 * DNS query langsung dari server ini, tidak ada bruteforce record apa pun,
 * hanya satu lookup CNAME untuk hostname yang sudah ditemukan dari crt.sh.
 */
async function resolveCname(hostname: string): Promise<string | null> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), DOH_TIMEOUT_MS);
  try {
    const res = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=CNAME`, {
      signal: controller.signal,
      headers: { accept: "application/dns-json" },
    });
    clearTimeout(timeout);
    if (!res.ok) return null;
    const data = (await res.json()) as DohResponse;
    const answer = data.Answer?.find((a) => a.type === 5); // type 5 = CNAME
    return answer?.data ?? null;
  } catch {
    clearTimeout(timeout);
    return null;
  }
}

async function fetchBodySnippet(hostname: string): Promise<{ status: number | null; snippet: string }> {
  for (const scheme of ["https", "http"] as const) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), HTTP_TIMEOUT_MS);
    try {
      const res = await fetch(`${scheme}://${hostname}/`, {
        method: "GET",
        redirect: "follow",
        signal: controller.signal,
        headers: { "User-Agent": "Sentinel-ID-SubdomainWatch/1.0 (+https://www.sentinel-id.net)" },
      });
      clearTimeout(timeout);
      const text = await res.text();
      return { status: res.status, snippet: text.slice(0, BODY_SNIPPET_LIMIT) };
    } catch {
      clearTimeout(timeout);
      // coba skema berikutnya (http fallback) sebelum menyerah
    }
  }
  return { status: null, snippet: "" };
}

/**
 * Cek heuristik takeover satu subdomain — 100% pasif:
 * 1) CNAME lookup via DoH Cloudflare.
 * 2) Kalau CNAME cocok pola layanan pihak-ketiga yang dikenal rentan,
 *    lakukan satu GET request biasa (sama seperti membuka di browser) untuk
 *    mencocokkan fingerprint body "resource belum diklaim".
 * Tidak ada exploit, tidak ada payload, tidak ada bruteforce.
 */
export async function checkSubdomainTakeover(subdomain: string, rootDomain: string): Promise<SubdomainRow> {
  const base: SubdomainRow = {
    subdomain,
    status: "checked",
    cname: null,
    httpStatus: null,
    risk: "UNKNOWN",
    service: null,
    reason: null,
    fix: null,
  };

  const lower = subdomain.toLowerCase().replace(/\.$/, "");
  const rootLower = rootDomain.toLowerCase();
  if (lower !== rootLower && !lower.endsWith(`.${rootLower}`)) {
    return { ...base, status: "error", errorMessage: "Subdomain di luar domain yang di-scan — dilewati." };
  }
  if (isPrivateOrReservedHost(lower)) {
    return { ...base, status: "error", errorMessage: "Hostname mengarah ke jaringan privat/internal — dilewati." };
  }

  const cname = await resolveCname(lower);
  if (!cname) {
    return {
      ...base,
      cname: null,
      risk: "LOW",
      reason: "Tidak ada record CNAME (atau tidak resolve) — kecil kemungkinan rentan takeover jenis ini.",
    };
  }

  const sig = matchSignatureByCname(cname);
  if (!sig) {
    return {
      ...base,
      cname,
      risk: "LOW",
      reason: "CNAME tidak cocok dengan pola layanan pihak-ketiga yang dikenal rentan takeover.",
    };
  }

  const { status, snippet } = await fetchBodySnippet(lower);
  const bodyMatch = snippet ? bodyMatchesFingerprint(snippet, sig) : false;
  const looksDead = status === 404 || status === null;

  if (bodyMatch) {
    return {
      ...base,
      cname,
      httpStatus: status,
      service: sig.service,
      risk: "HIGH",
      reason: `CNAME mengarah ke ${sig.service} yang belum/tidak lagi diklaim — rentan subdomain takeover!`,
      fix: sig.fix,
    };
  }

  if (looksDead) {
    return {
      ...base,
      cname,
      httpStatus: status,
      service: sig.service,
      risk: "MEDIUM",
      reason: `CNAME mengarah ke ${sig.service} tapi fingerprint response tidak bisa dipastikan (dangling CNAME, perlu verifikasi manual).`,
      fix: sig.fix,
    };
  }

  return {
    ...base,
    cname,
    httpStatus: status,
    service: sig.service,
    risk: "LOW",
    reason: `CNAME mengarah ke ${sig.service} dan resource tampak masih aktif/diklaim.`,
  };
}
