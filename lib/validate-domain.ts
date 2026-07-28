/**
 * Validasi domain input dari user.
 * - Harus berupa hostname/URL yang valid
 * - Blokir IP privat/loopback/link-local supaya tool ini tidak dipakai
 *   untuk menyerang jaringan internal (SSRF guard).
 */

const PRIVATE_IPV4_RANGES: Array<[number, number]> = [
  ipRange("10.0.0.0", "10.255.255.255"),
  ipRange("127.0.0.0", "127.255.255.255"),
  ipRange("169.254.0.0", "169.254.255.255"),
  ipRange("172.16.0.0", "172.31.255.255"),
  ipRange("192.168.0.0", "192.168.255.255"),
  ipRange("0.0.0.0", "0.255.255.255"),
  ipRange("100.64.0.0", "100.127.255.255"), // CGNAT
];

function ipToInt(ip: string): number {
  return ip
    .split(".")
    .reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

function ipRange(start: string, end: string): [number, number] {
  return [ipToInt(start), ipToInt(end)];
}

function isIPv4(host: string): boolean {
  return /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.test(host);
}

export function isPrivateOrReservedHost(hostname: string): boolean {
  const host = hostname.toLowerCase();

  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (host === "0.0.0.0") return true;

  // IPv6 loopback / link-local / unique-local
  if (host === "::1") return true;
  if (host.startsWith("fe80:")) return true;
  if (host.startsWith("fc") || host.startsWith("fd")) return true;

  if (isIPv4(host)) {
    const n = ipToInt(host);
    return PRIVATE_IPV4_RANGES.some(([start, end]) => n >= start && n <= end);
  }

  return false;
}

export interface DomainValidationResult {
  ok: boolean;
  error?: string;
  normalizedUrl?: string;
  hostname?: string;
}

export function validateDomainInput(rawInput: string): DomainValidationResult {
  const trimmed = rawInput.trim();
  if (!trimmed) {
    return { ok: false, error: "Domain tidak boleh kosong." };
  }

  // Kalau user tidak sertakan protokol, asumsikan https
  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;

  let url: URL;
  try {
    url = new URL(candidate);
  } catch {
    return { ok: false, error: "Format domain/URL tidak valid." };
  }

  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return { ok: false, error: "Hanya protokol http/https yang diizinkan." };
  }

  if (isPrivateOrReservedHost(url.hostname)) {
    return {
      ok: false,
      error:
        "Domain/IP ini termasuk jaringan privat atau internal dan diblokir untuk mencegah SSRF.",
    };
  }

  // Paksa https untuk audit (lebih representatif untuk produksi)
  url.protocol = "https:";
  url.pathname = "/";
  url.search = "";
  url.hash = "";

  return { ok: true, normalizedUrl: url.origin, hostname: url.hostname };
}
