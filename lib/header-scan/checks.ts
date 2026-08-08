import type { Grade, HeaderCheckKey, HeaderCheckResult } from "./types";

interface CheckDef {
  key: HeaderCheckKey;
  headerName: string;
  weight: number;
  severity: HeaderCheckResult["severity"];
  risk: string;
  fixSnippetKey: string;
  fixSnippetValue: string;
  /** Cek apakah header (dan header terkait, kalau ada) sudah memenuhi syarat. */
  evaluate: (headers: Record<string, string>) => { pass: boolean; value: string | null };
}

// Bobot total = 100 (20 + 25 + 15 + 10 + 10 + 10 + 10)
const CHECK_DEFS: CheckDef[] = [
  {
    key: "hsts",
    headerName: "Strict-Transport-Security",
    weight: 20,
    severity: "HIGH",
    risk: "Tanpa HSTS, koneksi awal ke domain rentan SSL stripping / downgrade ke HTTP sebelum browser sempat memaksa HTTPS.",
    fixSnippetKey: "Strict-Transport-Security",
    fixSnippetValue: "max-age=63072000; includeSubDomains; preload",
    evaluate: (h) => {
      const v = h["strict-transport-security"] ?? null;
      return { pass: !!v, value: v };
    },
  },
  {
    key: "csp",
    headerName: "Content-Security-Policy",
    weight: 25,
    severity: "CRITICAL",
    risk: "Tanpa CSP, mitigasi XSS jauh lebih lemah — script asing yang berhasil disisipkan (lewat input, dependency, atau supply-chain) bisa jalan bebas di halaman.",
    fixSnippetKey: "Content-Security-Policy",
    fixSnippetValue: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
    evaluate: (h) => {
      const v = h["content-security-policy"] ?? null;
      return { pass: !!v, value: v };
    },
  },
  {
    key: "frame-protection",
    headerName: "X-Frame-Options / frame-ancestors",
    weight: 15,
    severity: "MEDIUM",
    risk: "Tanpa proteksi framing, halaman berpotensi di-embed di iframe domain lain — membuka celah clickjacking (UI redress attack).",
    fixSnippetKey: "X-Frame-Options",
    fixSnippetValue: "SAMEORIGIN",
    evaluate: (h) => {
      const xfo = h["x-frame-options"] ?? null;
      const csp = h["content-security-policy"] ?? "";
      const hasFrameAncestors = /frame-ancestors/i.test(csp);
      if (xfo) return { pass: true, value: xfo };
      if (hasFrameAncestors) return { pass: true, value: "via CSP frame-ancestors" };
      return { pass: false, value: null };
    },
  },
  {
    key: "x-content-type-options",
    headerName: "X-Content-Type-Options",
    weight: 10,
    severity: "MEDIUM",
    risk: "Tanpa header ini, browser bisa MIME-sniffing dan mengeksekusi file upload/asset sebagai tipe konten lain (mis. HTML/JS), berisiko stored XSS lewat file upload.",
    fixSnippetKey: "X-Content-Type-Options",
    fixSnippetValue: "nosniff",
    evaluate: (h) => {
      const v = h["x-content-type-options"] ?? null;
      return { pass: v?.toLowerCase() === "nosniff", value: v };
    },
  },
  {
    key: "referrer-policy",
    headerName: "Referrer-Policy",
    weight: 10,
    severity: "LOW",
    risk: "Tanpa Referrer-Policy, URL sensitif (token di query string, path internal) berpotensi bocor ke pihak ketiga lewat header Referer saat user klik keluar.",
    fixSnippetKey: "Referrer-Policy",
    fixSnippetValue: "strict-origin-when-cross-origin",
    evaluate: (h) => {
      const v = h["referrer-policy"] ?? null;
      return { pass: !!v, value: v };
    },
  },
  {
    key: "permissions-policy",
    headerName: "Permissions-Policy",
    weight: 10,
    severity: "LOW",
    risk: "Tanpa Permissions-Policy, tidak ada pembatasan eksplisit terhadap akses fitur browser (kamera, mikrofon, geolokasi) oleh script pihak ketiga yang tersisip.",
    fixSnippetKey: "Permissions-Policy",
    fixSnippetValue: "camera=(), microphone=(), geolocation=()",
    evaluate: (h) => {
      const v = h["permissions-policy"] ?? null;
      return { pass: !!v, value: v };
    },
  },
  {
    key: "coop",
    headerName: "Cross-Origin-Opener-Policy",
    weight: 10,
    severity: "MEDIUM",
    risk: "Tanpa COOP, tab/window lain (termasuk yang dibuka via window.open dari domain asing) masih bisa mereferensikan window ini — membuka celah cross-origin leak & beberapa varian spectre-class attack.",
    fixSnippetKey: "Cross-Origin-Opener-Policy",
    fixSnippetValue: "same-origin",
    evaluate: (h) => {
      const v = h["cross-origin-opener-policy"] ?? null;
      return { pass: !!v, value: v };
    },
  },
];

export function buildNextConfigSnippet(key: string, value: string): string {
  return `// next.config.js
module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
          { key: '${key}', value: '${value}' },
        ],
      },
    ];
  },
};`;
}

export function runHeaderChecks(rawHeaders: Record<string, string>): HeaderCheckResult[] {
  const lower: Record<string, string> = {};
  for (const [k, v] of Object.entries(rawHeaders)) lower[k.toLowerCase()] = v;

  return CHECK_DEFS.map((def) => {
    const { pass, value } = def.evaluate(lower);
    return {
      key: def.key,
      headerName: def.headerName,
      weight: def.weight,
      pass,
      value,
      severity: def.severity,
      risk: def.risk,
      fixSnippetKey: def.fixSnippetKey,
      fixSnippetValue: def.fixSnippetValue,
      fixNextConfig: buildNextConfigSnippet(def.fixSnippetKey, def.fixSnippetValue),
    };
  });
}

export function scoreFromChecks(checks: HeaderCheckResult[]): number {
  const total = checks.reduce((sum, c) => sum + c.weight, 0);
  const earned = checks.reduce((sum, c) => sum + (c.pass ? c.weight : 0), 0);
  return total === 0 ? 0 : Math.round((earned / total) * 100);
}

export function gradeFromScore(score: number): Grade {
  if (score >= 95) return "A+";
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

export function generateHardeningKit(checks: HeaderCheckResult[]): string {
  const missing = checks.filter((c) => !c.pass);
  const headerEntries = missing
    .map((c) => `          { key: '${c.fixSnippetKey}', value: '${c.fixSnippetValue}' },`)
    .join("\n");

  if (missing.length === 0) {
    return `// next.config.js
// Semua header keamanan yang dicek sudah terpasang. 🎉
// Tidak ada tambahan yang wajib — tetap lakukan review berkala.`;
  }

  return `// next.config.js
// Hardening kit dari Sentinel-ID Header Armor Checker
// Tambahkan blok headers() ini (atau merge ke konfigurasi existing kamu).

module.exports = {
  async headers() {
    return [
      {
        source: '/(.*)',
        headers: [
${headerEntries}
        ],
      },
    ];
  },
};
`;
}
