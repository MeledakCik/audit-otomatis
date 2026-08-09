const TIMEOUT_MS = 20_000;
const MAX_SUBDOMAINS = 100;

interface CrtShEntry {
  name_value?: string;
}

export interface CrtShLookupResult {
  ok: boolean;
  error?: string;
  subdomains: string[];
  totalBeforeLimit: number;
  truncated: boolean;
  source?: string;
}

async function fetchWithTimeout(url: string, timeoutMs: number): Promise<Response> {
  const controller = new AbortController();
  const t = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "Sentinel-ID-SubdomainWatch/1.0 (+https://www.sentinel-id.net)",
        Accept: "application/json",
      },
      // cache 1 jam biar gak hammer crt.sh
      next: { revalidate: 3600 } as any,
    });
    return res;
  } finally {
    clearTimeout(t);
  }
}

function cleanAndFilter(names: string[], rootDomain: string): string[] {
  const rootLower = rootDomain.toLowerCase();
  const out = new Set<string>();
  for (let raw of names) {
    if (!raw) continue;
    let name = raw.trim().toLowerCase().replace(/^\*\./, "");
    // buang wildcard, email, spasi
    if (!name || name.includes("@") || name.includes(" ") || name.includes("*")) continue;
    if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(name)) continue;
    if (name === rootLower || name.endsWith(`.${rootLower}`)) {
      out.add(name);
    }
  }
  return Array.from(out).sort();
}

/**
 * Ambil subdomain dari CT log - 100% pasif
 * Urutan: 1. crt.sh (utama) 2. certspotter 3. alienvault OTX
 */
export async function lookupSubdomainsFromCrtSh(rootDomain: string): Promise<CrtShLookupResult> {
  const domain = rootDomain.toLowerCase().trim();
  
  // 1. COBA CRT.SH DULU (retry 2x)
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetchWithTimeout(
        `https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`,
        TIMEOUT_MS
      );

      if (!res.ok) {
        if (attempt === 1) throw new Error(`crt.sh status ${res.status}`);
        continue;
      }

      const raw = await res.text();
      let entries: CrtShEntry[];
      try {
        entries = JSON.parse(raw) as CrtShEntry[];
      } catch {
        try {
          // fix crt.sh yang kadang return NDJSON tanpa koma
          entries = JSON.parse(`[${raw.trim().replace(/}\s*{/g, "},{")}]`) as CrtShEntry[];
        } catch {
          throw new Error("crt.sh JSON invalid");
        }
      }

      const names = entries.flatMap(e => e.name_value?.split("\n") || []);
      const cleaned = cleanAndFilter(names, domain);

      if (cleaned.length > 0) {
        return {
          ok: true,
          subdomains: cleaned.slice(0, MAX_SUBDOMAINS),
          totalBeforeLimit: cleaned.length,
          truncated: cleaned.length > MAX_SUBDOMAINS,
          source: "crt.sh",
        };
      }
      // kalo 0 tapi response ok, jangan langsung fail, coba source lain
      break;
    } catch (err) {
      const isAbort = err instanceof Error && err.name === "AbortError";
      if (attempt === 1) {
        console.warn(`[crt.sh] attempt ${attempt+1} failed:`, err);
      }
      if (isAbort && attempt === 0) continue; // retry sekali kalau timeout
    }
  }

  // 2. FALLBACK: Certspotter (jauh lebih cepat, 2 detik)
  try {
    const res = await fetchWithTimeout(
      `https://api.certspotter.com/v1/issuances?domain=${encodeURIComponent(domain)}&include_subdomains=true&expand=dns_names`,
      10_000
    );
    if (res.ok) {
      const data = await res.json() as Array<{ dns_names: string[] }>;
      const names = data.flatMap(d => d.dns_names || []);
      const cleaned = cleanAndFilter(names, domain);
      if (cleaned.length > 0) {
        return {
          ok: true,
          subdomains: cleaned.slice(0, MAX_SUBDOMAINS),
          totalBeforeLimit: cleaned.length,
          truncated: cleaned.length > MAX_SUBDOMAINS,
          source: "certspotter",
        };
      }
    }
  } catch {}

  // 3. FALLBACK: AlienVault OTX (free, no key)
  try {
    const res = await fetchWithTimeout(
      `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}/passive_dns`,
      10_000
    );
    if (res.ok) {
      const data = await res.json() as { passive_dns: Array<{ hostname: string }> };
      const names = (data.passive_dns || []).map(d => d.hostname);
      const cleaned = cleanAndFilter(names, domain);
      if (cleaned.length > 0) {
        return {
          ok: true,
          subdomains: cleaned.slice(0, MAX_SUBDOMAINS),
          totalBeforeLimit: cleaned.length,
          truncated: cleaned.length > MAX_SUBDOMAINS,
          source: "alienvault",
        };
      }
    }
  } catch {}

  // Semua gagal
  return {
    ok: false,
    error: "CT log lagi sibuk semua (crt.sh timeout). Coba lagi 30 detik atau test domain populer dulu seperti hackerone.com untuk cek koneksi.",
    subdomains: [],
    totalBeforeLimit: 0,
    truncated: false,
  };
}