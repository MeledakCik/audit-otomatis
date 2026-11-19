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

const knownReferrerPolicies = new Set([
  "no-referrer", "no-referrer-when-downgrade", "same-origin", "origin",
  "strict-origin", "origin-when-cross-origin", "strict-origin-when-cross-origin", "unsafe-url",
]);
const strictReferrerPolicies = new Set(["no-referrer", "same-origin", "strict-origin", "strict-origin-when-cross-origin"]);

function policyDirectives(value: string, directive: string): string[][] {
  return value.split(",").flatMap((policy) => {
    const entry = policy.split(";")
      .map((part) => part.trim().split(/\s+/))
      .find(([name]) => name.toLowerCase() === directive);
    return entry ? [entry.slice(1)] : [];
  });
}

function hasScriptRestrictions(value: string): boolean {
  return value.split(",").some((policy) => {
    const defaults = policyDirectives(policy, "script-src")[0] ?? policyDirectives(policy, "default-src")[0];
    if (!defaults) return false;
    const elements = policyDirectives(policy, "script-src-elem")[0] ?? defaults;
    const attributes = policyDirectives(policy, "script-src-attr")[0] ?? defaults;
    return [elements, attributes].every((sources) => {
      const hasNonceOrHash = sources.some((source) => /^'(?:nonce-|sha(?:256|384|512)-)[A-Za-z0-9+/_=-]+'$/i.test(source));
      return !sources.includes("*") && (!sources.includes("'unsafe-inline'") || hasNonceOrHash);
    });
  });
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
      const ages = v?.split(";").map((part) => part.trim()).filter((part) => /^max-age(?:\s*=|\s*$)/i.test(part)) ?? [];
      const age = ages[0]?.match(/^max-age\s*=\s*(?:"(\d+)"|(\d+))$/i);
      return { pass: ages.length === 1 && !!age && Number(age[1] ?? age[2]) > 0, value: v };
    },
  },
  {
    key: "csp",
    headerName: "Content-Security-Policy",
    weight: 25,
    severity: "CRITICAL",
    risk: "Sumber skrip perlu dibatasi lewat script-src atau default-src pada kebijakan CSP yang diterapkan browser.",
    fixSnippetKey: "Content-Security-Policy",
    fixSnippetValue: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'self'",
    evaluate: (h) => {
      const v = h["content-security-policy"] ?? null;
      return { pass: !!v && hasScriptRestrictions(v), value: v };
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
      const ancestors = policyDirectives(h["content-security-policy"] ?? "", "frame-ancestors");
      if (ancestors.length > 0) {
        const pass = ancestors.some((sources) => sources.every((source) =>
          source === "'self'" || source === "'none'" || /^https?:\/\/(?:\*\.)?[^*\s/:]+(?::\d+)?$/i.test(source)
        ));
        return { pass, value: "via CSP frame-ancestors" };
      }
      return { pass: /^(deny|sameorigin)$/i.test(xfo?.trim() ?? ""), value: xfo };
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
      return { pass: v?.trim().toLowerCase() === "nosniff", value: v };
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
      const effective = v?.split(",").map((item) => item.trim().toLowerCase())
        .filter((item) => knownReferrerPolicies.has(item)).at(-1);
      return { pass: !!effective && strictReferrerPolicies.has(effective), value: v };
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
      const entries = v?.split(",").map((part) => part.trim()) ?? [];
      const pass = ["camera", "microphone", "geolocation"].every((feature) => {
        const rules = entries.filter((part) => new RegExp(`^${feature}\\s*=`, "i").test(part));
        return rules.length === 1 && /^\(\s*(?:self\s*)?\)$/i.test(rules[0].split("=")[1].trim());
      });
      return { pass, value: v };
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
      const policy = v?.split(";")[0]?.trim();
      return { pass: policy === "same-origin" || policy === "same-origin-allow-popups" || policy === "noopener-allow-popups", value: v };
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
          { key: ${JSON.stringify(key)}, value: ${JSON.stringify(value)} },
        ],
      },
    ];
  },
};`;
}

export function runHeaderChecks(rawHeaders: Record<string, string>): HeaderCheckResult[] {
  const lower: Record<string, string> = Object.create(null);
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
    .map((c) => `          { key: ${JSON.stringify(c.fixSnippetKey)}, value: ${JSON.stringify(c.fixSnippetValue)} },`)
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
