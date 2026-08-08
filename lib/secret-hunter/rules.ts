import type { SecretFinding } from "./types";
import type { Severity } from "@/lib/types";

interface SecretRule {
  id: string;
  type: string;
  severity: Severity;
  risk: string;
  pattern: RegExp;
  /** Berapa karakter di awal & akhir match yang tetap ditampilkan saat redaksi. */
  prefixKeep: number;
  suffixKeep: number;
  /** Kalau true, match ada di capture group 1 (bukan seluruh match). */
  useGroup1?: boolean;
  /** Kalau true, ini bukan secret literal (mis. URL) — tidak perlu diredaksi seagresif secret. */
  isDisclosureOnly?: boolean;
}

// Pola sesuai spesifikasi Header Armor / Secret Hunter — semua GET-only,
// tidak ada verifikasi/panggilan keluar terhadap value yang ditemukan.
const RULES: SecretRule[] = [
  {
    id: "aws-access-key",
    type: "AWS Access Key",
    severity: "HIGH",
    risk: "Access Key AWS yang bocor di bundle client bisa dipakai mengakses resource cloud (S3, EC2, dll) sesuai IAM policy yang melekat padanya.",
    pattern: /\bAKIA[0-9A-Z]{16}\b/g,
    prefixKeep: 4,
    suffixKeep: 4,
  },
  {
    id: "google-api-key",
    type: "Google/Firebase API Key",
    severity: "MEDIUM",
    risk: "API key Google/Firebase yang ter-hardcode berisiko disalahgunakan (abuse kuota, akses service lain) kalau tidak dibatasi HTTP referrer / API restriction.",
    pattern: /\bAIza[0-9A-Za-z\-_]{35}\b/g,
    prefixKeep: 4,
    suffixKeep: 4,
  },
  {
    id: "slack-token",
    type: "Slack Token",
    severity: "HIGH",
    risk: "Token Slack yang bocor bisa dipakai memposting pesan, membaca channel, atau mengakses workspace sesuai scope token.",
    // Mencakup prefix asli Slack (xoxb-/xoxp-/xoxa-/xoxr-/xoxs-) selain pola generik "xox-" di spesifikasi.
    pattern: /\bxox[baprs]?-[0-9A-Za-z-]{10,}\b/gi,
    prefixKeep: 5,
    suffixKeep: 4,
  },
  {
    id: "generic-secret-assignment",
    type: "Generic Credential Assignment",
    severity: "MEDIUM",
    risk: "Pattern generik (api_key/secret/password) — kemungkinan credential asli ter-hardcode di client bundle. Bisa juga false-positive, perlu verifikasi manual (tanpa mencoba value-nya).",
    pattern: /(api_key|apikey|secret|password)\s*[:=]\s*['"]([^'"]{8,})['"]/gi,
    prefixKeep: 0,
    suffixKeep: 4,
    useGroup1: false,
  },
  {
    id: "supabase-firebase-url",
    type: "Supabase/Firebase Project URL",
    severity: "LOW",
    risk: "URL project Supabase/Firebase ter-expose di bundle client (umumnya memang publik, tapi jadi titik awal recon backend — pastikan Row Level Security / rules sudah benar).",
    pattern: /\b[a-z0-9][a-z0-9-]*\.(?:supabase\.co|firebaseio\.com)\b/gi,
    prefixKeep: 999,
    suffixKeep: 0,
    isDisclosureOnly: true,
  },
  {
    id: "private-ip",
    type: "Private IP Address",
    severity: "LOW",
    risk: "Alamat IP privat/internal ter-expose di bundle client — bisa membocorkan topologi infrastruktur internal ke penyerang.",
    pattern: /\b(?:10\.(?:\d{1,3}\.){2}\d{1,3}|172\.(?:1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b/g,
    prefixKeep: 999,
    suffixKeep: 0,
    isDisclosureOnly: true,
  },
  {
    id: "public-env-secretish",
    type: "Public Env Var (VITE_/NEXT_PUBLIC_) Berisi Kata Kunci Rahasia",
    severity: "MEDIUM",
    risk: "Variable VITE_*/NEXT_PUBLIC_* SELALU ikut ter-bundle ke client by design — kalau namanya mengandung KEY/SECRET/TOKEN/PASSWORD, developer kemungkinan salah kira ini rahasia server-side.",
    pattern: /((?:VITE_|NEXT_PUBLIC_)[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD)[A-Z0-9_]*)\s*[:=]\s*['"]([^'"]{6,})['"]/g,
    prefixKeep: 0,
    suffixKeep: 4,
    useGroup1: false,
  },
];

function redact(value: string, prefixKeep: number, suffixKeep: number): string {
  if (prefixKeep >= 999) return value; // disclosure-only (URL/IP) — bukan secret literal, tidak diredaksi
  if (value.length <= prefixKeep + suffixKeep) return "*".repeat(Math.max(4, value.length));
  const middleLen = Math.min(4, Math.max(4, value.length - prefixKeep - suffixKeep));
  return value.slice(0, prefixKeep) + "*".repeat(middleLen) + value.slice(value.length - suffixKeep);
}

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

function lineOf(source: string, index: number): number {
  let line = 1;
  for (let i = 0; i < index && i < source.length; i++) {
    if (source[i] === "\n") line++;
  }
  return line;
}

function newId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

const MAX_HITS_PER_RULE = 8;

/**
 * Scan satu file (source text) untuk pola secret/credential/info-disclosure.
 * 100% pasif: hanya regex match pada teks yang sudah didapat lewat GET,
 * TIDAK PERNAH memverifikasi value (tidak ada request ke AWS/Slack/dst).
 * Value asli tidak pernah dikembalikan — hanya versi redacted.
 */
export function scanSourceForSecrets(source: string, fileLabel: string): SecretFinding[] {
  const findings: SecretFinding[] = [];
  const seen = new Set<string>();

  for (const rule of RULES) {
    rule.pattern.lastIndex = 0;
    let match: RegExpExecArray | null;
    let hits = 0;
    while ((match = rule.pattern.exec(source)) && hits < MAX_HITS_PER_RULE) {
      hits++;
      const full = match[0];
      const raw = rule.useGroup1 === false ? (match[2] ?? full) : match[1] ?? full;

      if (rule.id === "generic-secret-assignment" && shannonEntropy(raw) < 3.0) continue;

      const line = lineOf(source, match.index);
      const redactedValue = redact(raw, rule.prefixKeep, rule.suffixKeep);
      const dedupeKey = `${rule.id}:${fileLabel}:${redactedValue}`;
      if (seen.has(dedupeKey)) continue;
      seen.add(dedupeKey);

      const snippetPreview =
        rule.id === "public-env-secretish" ? `${match[1]} = "${redactedValue}"` : redactedValue;

      findings.push({
        id: newId(),
        ruleId: rule.id,
        type: rule.type,
        severity: rule.severity,
        file: `${fileLabel}:${line}`,
        line,
        redactedSnippet: snippetPreview,
        risk: rule.risk,
      });
    }
  }

  return findings;
}

export function riskLevelFromFindings(findings: SecretFinding[]): "HIGH" | "MEDIUM" | "LOW" | "CLEAN" {
  if (findings.some((f) => f.severity === "HIGH" || f.severity === "CRITICAL")) return "HIGH";
  if (findings.some((f) => f.severity === "MEDIUM")) return "MEDIUM";
  if (findings.length > 0) return "LOW";
  return "CLEAN";
}
