import type { DkimHint, DmarcResult, MxProvider, MxRecord, SpfResult, TakeoverHint } from "./types";

export function analyzeSpf(apexTxt: string[]): SpfResult {
  const spf = apexTxt.find((t) => /^v=spf1/i.test(t.trim()));
  if (!spf) {
    return {
      found: false,
      value: null,
      risk: "HIGH",
      note: "Tidak ada SPF record — domain ini rentan email spoofing (siapa saja bisa kirim email mengatasnamakan domain ini tanpa terdeteksi).",
    };
  }
  if (/\+all\b/i.test(spf)) {
    return {
      found: true,
      value: spf,
      risk: "HIGH",
      note: 'SPF ditemukan tapi pakai "+all" (allow all) — ini sama longgarnya dengan tidak punya SPF sama sekali.',
    };
  }
  return {
    found: true,
    value: spf,
    risk: "LOW",
    note: "SPF record ditemukan dan terlihat wajar.",
  };
}

export function analyzeDmarc(dmarcTxt: string[]): DmarcResult {
  const dmarc = dmarcTxt.find((t) => /^v=dmarc1/i.test(t.trim()));
  if (!dmarc) {
    return {
      found: false,
      value: null,
      policy: null,
      risk: "MEDIUM",
      note: "Tidak ada DMARC record di _dmarc — tanpa DMARC, penerima email tidak tahu harus apa kalau ada email spoofing yang lolos SPF/DKIM.",
    };
  }

  const policyMatch = /p=(reject|quarantine|none)/i.exec(dmarc);
  const policy = (policyMatch?.[1]?.toLowerCase() as DmarcResult["policy"]) ?? null;

  if (policy === "none" || policy === null) {
    return {
      found: true,
      value: dmarc,
      policy,
      risk: "MEDIUM",
      note: 'DMARC ada tapi policy-nya "none" (atau tidak terbaca) — cuma mode monitoring, tidak benar-benar memblokir email palsu.',
    };
  }

  return {
    found: true,
    value: dmarc,
    policy,
    risk: "LOW",
    note: `DMARC ditemukan dengan policy "${policy}" — sudah cukup ketat.`,
  };
}

/**
 * Hint DKIM dari TXT record apex saja (v=DKIM1 / k=rsa). Ini BUKAN
 * pengecekan konklusif — DKIM key sebenarnya biasanya ada di
 * {selector}._domainkey.{domain}, dan kita tidak menebak-nebak selector
 * (itu akan jadi bruteforce, di luar scope pasif tool ini). Anggap ini
 * cuma sinyal tambahan kalau kebetulan ada jejak DKIM di TXT record utama.
 */
export function analyzeDkimHint(apexTxt: string[]): DkimHint {
  const matched = apexTxt.filter((t) => /v=dkim1/i.test(t) || /k=rsa/i.test(t));
  return {
    found: matched.length > 0,
    matchedRecords: matched,
    note:
      matched.length > 0
        ? "Ada jejak DKIM di TXT record utama domain — bukan konfirmasi DKIM aktif di semua selector, cuma hint."
        : "Tidak ada jejak DKIM di TXT record utama. DKIM asli ada di {selector}._domainkey — cek manual kalau perlu (tool ini tidak menebak selector).",
  };
}

const MX_PROVIDER_PATTERNS: { pattern: RegExp; provider: string }[] = [
  { pattern: /\.google\.com$|\.googlemail\.com$|smtp\.google\.com$/i, provider: "Google Workspace" },
  { pattern: /\.outlook\.com$|protection\.outlook\.com$|mail\.protection\.outlook\.com$/i, provider: "Microsoft 365 / Outlook" },
  { pattern: /\.zoho\.com$|\.zohomail\.com$/i, provider: "Zoho Mail" },
  { pattern: /pphosted\.com$/i, provider: "Proofpoint" },
  { pattern: /mimecast\.com$/i, provider: "Mimecast" },
  { pattern: /amazonses\.com$/i, provider: "Amazon SES" },
  { pattern: /yahoodns\.net$/i, provider: "Yahoo Mail" },
  { pattern: /\.qq\.com$/i, provider: "Tencent QQ Mail" },
  { pattern: /mailgun\.org$/i, provider: "Mailgun" },
  { pattern: /sendgrid\.net$/i, provider: "SendGrid" },
];

export function detectMxProvider(mx: MxRecord[]): MxProvider | null {
  if (mx.length === 0) return null;
  for (const { pattern, provider } of MX_PROVIDER_PATTERNS) {
    if (mx.some((m) => pattern.test(m.exchange))) {
      return { provider, confidence: "HIGH" };
    }
  }
  return { provider: `Custom / tidak dikenali (${mx[0].exchange})`, confidence: "LOW" };
}

// Pola layanan yang dikenal luas rawan subdomain takeover kalau CNAME masih
// nunjuk ke sana padahal resource-nya sudah tidak diklaim. Sumber: daftar
// publik "can-i-take-over-xyz". Ini CUMA pattern match terhadap CNAME yang
// SUDAH di-resolve secara pasif — tidak ada percobaan claim/exploit apa pun.
const TAKEOVER_PATTERNS: { pattern: RegExp; service: string }[] = [
  { pattern: /\.github\.io$/i, service: "GitHub Pages" },
  { pattern: /\.herokuapp\.com$/i, service: "Heroku" },
  { pattern: /\.s3(-website)?[.-][a-z0-9-]*\.amazonaws\.com$/i, service: "AWS S3" },
  { pattern: /\.azurewebsites\.net$/i, service: "Azure App Service" },
  { pattern: /\.cloudfront\.net$/i, service: "AWS CloudFront" },
  { pattern: /\.wordpress\.com$/i, service: "WordPress.com" },
  { pattern: /\.zendesk\.com$/i, service: "Zendesk" },
  { pattern: /\.freshdesk\.com$/i, service: "Freshdesk" },
  { pattern: /\.pantheonsite\.io$/i, service: "Pantheon" },
  { pattern: /\.surge\.sh$/i, service: "Surge.sh" },
  { pattern: /\.bitbucket\.io$/i, service: "Bitbucket Pages" },
  { pattern: /\.unbouncepages\.com$/i, service: "Unbounce" },
];

export function detectTakeoverHints(cname: string[]): TakeoverHint[] {
  const hints: TakeoverHint[] = [];
  for (const c of cname) {
    for (const { pattern, service } of TAKEOVER_PATTERNS) {
      if (pattern.test(c)) {
        hints.push({
          cname: c,
          matchedService: service,
          risk: "MEDIUM",
          note: `CNAME mengarah ke ${service} (${c}). Ini CUMA HINT pola — perlu verifikasi manual apakah resource di sisi ${service} benar-benar belum diklaim sebelum dianggap kerentanan nyata.`,
        });
      }
    }
  }
  return hints;
}
