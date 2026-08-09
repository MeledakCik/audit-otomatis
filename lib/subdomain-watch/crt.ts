const CRT_SH_TIMEOUT_MS = 15_000;
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
}

/**
 * Ambil semua nama dari Certificate Transparency log via crt.sh — 100% pasif,
 * satu request GET ke API publik crt.sh, tidak ada bruteforce DNS sama sekali.
 */
export async function lookupSubdomainsFromCrtSh(rootDomain: string): Promise<CrtShLookupResult> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), CRT_SH_TIMEOUT_MS);

  try {
    const res = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(rootDomain)}&output=json`, {
      method: "GET",
      signal: controller.signal,
      headers: {
        "User-Agent": "Sentinel-ID-SubdomainWatch/1.0 (+https://www.sentinel-id.net)",
        Accept: "application/json",
      },
    });
    clearTimeout(timeout);

    if (!res.ok) {
      return {
        ok: false,
        error: `crt.sh membalas status ${res.status}. Layanan mungkin sedang sibuk, coba lagi beberapa saat lagi.`,
        subdomains: [],
        totalBeforeLimit: 0,
        truncated: false,
      };
    }

    const raw = await res.text();
    let entries: CrtShEntry[];
    try {
      entries = JSON.parse(raw) as CrtShEntry[];
    } catch {
      // crt.sh kadang mengembalikan beberapa JSON object yang digabung tanpa
      // koma saat load tinggi — coba perbaiki dengan membungkus jadi array.
      try {
        entries = JSON.parse(`[${raw.trim().replace(/}\s*{/g, "},{")}]`) as CrtShEntry[];
      } catch {
        return {
          ok: false,
          error: "Gagal membaca respons crt.sh (bukan JSON valid). Coba lagi beberapa saat lagi.",
          subdomains: [],
          totalBeforeLimit: 0,
          truncated: false,
        };
      }
    }

    if (!Array.isArray(entries)) {
      return { ok: true, subdomains: [], totalBeforeLimit: 0, truncated: false };
    }

    const rootLower = rootDomain.toLowerCase();
    const found = new Set<string>();

    for (const entry of entries) {
      const nameValue = entry.name_value;
      if (!nameValue) continue;
      for (const line of nameValue.split("\n")) {
        const name = line.trim().toLowerCase().replace(/^\*\./, "");
        if (!name) continue;
        if (!/^[a-z0-9.*-]+$/.test(name)) continue; // buang entri aneh/wildcard email dsb.
        if (name === rootLower || name.endsWith(`.${rootLower}`)) {
          found.add(name);
        }
      }
    }

    const all = Array.from(found).sort();
    const truncated = all.length > MAX_SUBDOMAINS;
    return {
      ok: true,
      subdomains: all.slice(0, MAX_SUBDOMAINS),
      totalBeforeLimit: all.length,
      truncated,
    };
  } catch (err) {
    clearTimeout(timeout);
    const aborted = err instanceof Error && err.name === "AbortError";
    return {
      ok: false,
      error: aborted
        ? "Timeout — crt.sh tidak merespons dalam 15 detik."
        : "Gagal menghubungi crt.sh. Coba lagi beberapa saat lagi.",
      subdomains: [],
      totalBeforeLimit: 0,
      truncated: false,
    };
  }
}
