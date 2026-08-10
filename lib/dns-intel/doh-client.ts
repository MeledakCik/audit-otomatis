const DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query";
const FETCH_TIMEOUT_MS = 6_000;

export interface DohAnswer {
  name: string;
  type: number;
  TTL: number;
  data: string;
}

export interface DohResponse {
  Status: number; // 0 = NOERROR, 3 = NXDOMAIN, dst (kode RCODE standar DNS)
  Answer?: DohAnswer[];
}

/**
 * Query DNS record lewat Cloudflare DoH (DNS-over-HTTPS, JSON format).
 * Ini HANYA melakukan standard recursive query seperti resolver publik biasa
 * — API ini secara fisik tidak bisa dipakai untuk zone transfer (AXFR),
 * jadi "no AXFR" terjamin oleh desain transport-nya sendiri, bukan cuma
 * janji di kode.
 */
export async function dohQuery(name: string, type: string): Promise<DohResponse | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);

  try {
    const url = `${DOH_ENDPOINT}?name=${encodeURIComponent(name)}&type=${encodeURIComponent(type)}`;
    const res = await fetch(url, {
      method: "GET",
      signal: controller.signal,
      headers: {
        Accept: "application/dns-json",
        "User-Agent": "Sentinel-ID-DnsIntel/1.0 (+https://www.sentinel-id.net)",
      },
      cache: "no-store",
    });
    clearTimeout(timer);
    if (!res.ok) return null;
    return (await res.json()) as DohResponse;
  } catch {
    clearTimeout(timer);
    return null;
  }
}

/** Buang trailing dot yang lazim ada di response DNS ("example.com." -> "example.com") */
export function stripTrailingDot(value: string): string {
  return value.endsWith(".") ? value.slice(0, -1) : value;
}

/** TXT record dari DoH datang terbungkus tanda kutip literal, mis. "\"v=spf1 ...\"" */
export function unquoteTxt(value: string): string {
  const trimmed = value.trim();
  if (trimmed.startsWith('"') && trimmed.endsWith('"')) {
    return trimmed.slice(1, -1).replace(/\\"/g, '"');
  }
  return trimmed;
}
