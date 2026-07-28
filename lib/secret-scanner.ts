import type { Finding, Severity } from "./types";

/**
 * Deteksi secret/API key/token yang ke-hardcode di JS. PASIF MURNI:
 * hanya regex + entropy check terhadap source text yang sudah diunduh oleh
 * js-analyzer/site-crawler, tidak ada request tambahan, tidak ada percobaan
 * memakai key yang ditemukan.
 */

interface SecretRule {
  id: string;
  label: string;
  pattern: RegExp;
  severity: Severity;
  cvss: number;
  cwe: string;
  impact: string;
  fix: string;
  pocTemplate?: (value: string) => string;
}

// Koleksi pola ala TruffleHog + tambahan custom sesuai spesifikasi.
const RULES: SecretRule[] = [
  {
    id: "stripe-live-key",
    label: "Stripe Live Secret Key",
    pattern: /\b(sk_live_[A-Za-z0-9]{16,})\b/g,
    severity: "CRITICAL",
    cvss: 9.8,
    cwe: "CWE-798",
    impact: "Kunci Stripe live memberi akses penuh ke transaksi pembayaran, bisa dipakai untuk refund/charge palsu atau membaca data pelanggan.",
    fix: "Cabut (rotate) key ini di dashboard Stripe, pindahkan ke environment variable server-side, jangan pernah sertakan di bundle client.",
    pocTemplate: (v) => `curl -H "Authorization: Bearer ${v}" https://api.stripe.com/v1/charges`,
  },
  {
    id: "stripe-restricted-key",
    label: "Stripe Restricted Key",
    pattern: /\b(rk_live_[A-Za-z0-9]{16,})\b/g,
    severity: "HIGH",
    cvss: 8.1,
    cwe: "CWE-798",
    impact: "Restricted key tetap memberi akses API Stripe sesuai scope yang di-assign; bocor ke client tetap berisiko penyalahgunaan.",
    fix: "Rotate key, pindahkan ke server-side, batasi scope seminimal mungkin.",
  },
  {
    id: "github-pat",
    label: "GitHub Personal Access Token",
    pattern: /\b(ghp_[A-Za-z0-9]{36})\b/g,
    severity: "CRITICAL",
    cvss: 9.1,
    cwe: "CWE-798",
    impact: "Token GitHub bisa dipakai membaca/menulis repository privat sesuai scope token, termasuk mengubah source code atau mencuri secret lain di repo.",
    fix: "Revoke token di GitHub Settings > Developer settings, generate ulang, simpan hanya di CI secret store / server env.",
    pocTemplate: (v) => `curl -H "Authorization: token ${v}" https://api.github.com/user`,
  },
  {
    id: "aws-access-key",
    label: "AWS Access Key ID",
    pattern: /\b(AKIA[0-9A-Z]{16})\b/g,
    severity: "CRITICAL",
    cvss: 9.1,
    cwe: "CWE-798",
    impact: "Access Key AWS yang bocor (apalagi berpasangan dengan secret key) bisa dipakai mengakses resource cloud (S3, EC2, dll) sesuai IAM policy yang melekat.",
    fix: "Nonaktifkan/rotate access key di IAM console, audit CloudTrail untuk aktivitas mencurigakan, jangan hardcode credential AWS di client bundle.",
  },
  {
    id: "google-api-key",
    label: "Google/Firebase API Key",
    pattern: /\b(AIza[0-9A-Za-z\-_]{35})\b/g,
    severity: "MEDIUM",
    cvss: 5.3,
    cwe: "CWE-798",
    impact: "API key Google/Firebase yang di-hardcode di client umumnya memang dipakai dari browser, tapi tetap berisiko kalau tidak dibatasi HTTP referrer / API restriction, memungkinkan abuse kuota atau akses service lain.",
    fix: "Batasi key di Google Cloud Console (HTTP referrer restriction + API restriction per service), pertimbangkan pindah operasi sensitif ke server-side.",
  },
  {
    id: "jwt-like",
    label: "Kemungkinan JWT ter-hardcode",
    pattern: /\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b/g,
    severity: "MEDIUM",
    cvss: 6.5,
    cwe: "CWE-798",
    impact: "JWT yang di-hardcode (bukan token session milik user saat runtime) bisa jadi credential statis yang bisa dipakai ulang oleh siapa saja yang membaca bundle JS.",
    fix: "Pastikan token ini bukan credential statis; kalau memang statis, pindahkan ke server-side dan jangan sertakan di bundle client.",
  },
  {
    id: "supabase-url-anon",
    label: "Supabase Project Reference / Anon Key Pattern",
    pattern: /(?:supabase)[^\n]{0,80}["']([A-Za-z0-9_\-.]{20,})["']/gi,
    severity: "HIGH",
    cvss: 7.5,
    cwe: "CWE-798",
    impact: "Kalau ini anon/service key Supabase tanpa Row Level Security yang benar, attacker bisa membaca/menulis langsung ke tabel database lewat REST API PostgREST.",
    fix: "Pastikan Row Level Security (RLS) aktif di semua tabel, gunakan anon key hanya untuk operasi yang memang publik, rotate service_role key kalau ikut bocor.",
    pocTemplate: (v) => `curl -H "apikey: ${redact(v)}" https://<project-ref>.supabase.co/rest/v1/`,
  },
  {
    id: "next-public-secretish",
    label: "NEXT_PUBLIC_* var berisi nilai mirip secret",
    pattern: /NEXT_PUBLIC_[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD)[A-Z0-9_]*\s*[:=]\s*["']([A-Za-z0-9_\-]{8,})["']/g,
    severity: "MEDIUM",
    cvss: 5.9,
    cwe: "CWE-798",
    impact: "Variable NEXT_PUBLIC_* SELALU ikut ter-bundle ke client (by design Next.js) — kalau namanya mengandung KEY/SECRET/TOKEN, kemungkinan besar developer salah kira ini rahasia server.",
    fix: "Pindahkan nilai sensitif ke variable tanpa prefix NEXT_PUBLIC_ dan akses hanya dari server component/API route, bukan client bundle.",
  },
  {
    id: "generic-secret-assignment",
    label: "Kemungkinan credential hardcode (pattern generik)",
    pattern: /\b(?:password|passwd|secret|api[_-]?key)\s*[:=]\s*["']([^"'\s]{4,})["']/gi,
    severity: "LOW",
    cvss: 4.0,
    cwe: "CWE-798",
    impact: "Pattern generik ini bisa jadi false-positive (mis. label form/placeholder), tapi kalau memang credential asli, dampaknya tergantung sistem yang dilindungi.",
    fix: "Verifikasi manual apakah ini benar credential aktif; kalau ya, cabut/rotate dan pindahkan ke server-side env.",
  },
];

function redact(value: string): string {
  if (value.length <= 8) return "*".repeat(value.length);
  const keepStart = Math.max(4, Math.floor(value.length * 0.25));
  const keepEnd = Math.max(4, Math.floor(value.length * 0.25));
  const middle = "*".repeat(Math.max(4, value.length - keepStart - keepEnd));
  return value.slice(0, keepStart) + middle + value.slice(value.length - keepEnd);
}

/** Shannon entropy — dipakai sebagai sinyal tambahan (bukan trigger utama)
 * untuk membedakan string acak (kemungkinan key/secret asli) dari kata biasa. */
function shannonEntropy(value: string): number {
  const freq = new Map<string, number>();
  for (const ch of value) freq.set(ch, (freq.get(ch) ?? 0) + 1);
  let entropy = 0;
  for (const count of freq.values()) {
    const p = count / value.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

function newId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

function lineOf(source: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < source.length; i++) {
    if (source[i] === "\n") line++;
  }
  return line;
}

/**
 * Scan satu file JS (source text) untuk secret/credential hardcode.
 * sourceLabel dipakai sebagai identitas lokasi (path file atau "inline-script[n]").
 */
export function scanSecrets(source: string, sourceLabel: string): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>(); // dedupe per (rule, value redacted)

  for (const rule of RULES) {
    rule.pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    let hits = 0;
    while ((match = rule.pattern.exec(source)) && hits < 5) {
      hits++;
      const raw = match[1] ?? match[0];
      const entropy = shannonEntropy(raw);
      // Rule generik (password/secret literal pendek) butuh entropy minimal
      // supaya tidak flag string biasa seperti "your_password_here".
      if (rule.id === "generic-secret-assignment" && entropy < 3.0) continue;

      const line = lineOf(source, match.index);
      const redacted = redact(raw);
      const dedupeKey = `${rule.id}:${redacted}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      const snippetRaw = source.slice(Math.max(0, match.index - 20), match.index + raw.length + 20);
      const snippet = snippetRaw.replace(raw, redacted).replace(/\s+/g, " ").trim();

      findings.push({
        id: newId(),
        severity: rule.severity,
        title: `Hardcoded secret terdeteksi: ${rule.label}`,
        endpoint: `${sourceLabel}:${line}`,
        evidence: `Pattern: ${rule.label} | Entropy: ${entropy.toFixed(2)} | Snippet: ${snippet}`,
        impact: rule.impact,
        fix: rule.fix,
        cvss: rule.cvss,
        cwe: rule.cwe,
        poc: rule.pocTemplate ? rule.pocTemplate(raw) : undefined,
        category: "secret",
      });
    }
  }

  return findings;
}
