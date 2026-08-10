import { validateDomainInput } from "@/lib/validate-domain";

export interface DnsDomainValidation {
  ok: boolean;
  domain?: string;
  error?: string;
}

/**
 * Normalisasi input domain khusus buat DNS lookup: strip https://, path,
 * dan (beda dari validate-domain.ts yang generik) juga strip prefix "www."
 * supaya query DNS jalan ke apex domain, bukan subdomain www-nya.
 * SSRF guard (blokir IP privat/internal) tetap dipakai dari validator utama.
 */
export function normalizeDnsDomainInput(raw: string): DnsDomainValidation {
  const v = validateDomainInput(raw);
  if (!v.ok || !v.hostname) {
    return { ok: false, error: v.error ?? "Domain tidak valid." };
  }
  const domain = v.hostname.replace(/^www\./i, "");
  return { ok: true, domain };
}
