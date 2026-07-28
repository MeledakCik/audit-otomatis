import type { Finding, Severity } from "./types";

interface HeaderCheck {
  header: string;
  severity: Severity;
  title: string;
  impact: string;
  fix: string;
  validate?: (value: string) => boolean;
}

// Meniru daftar cek utama securityheaders.com
const CHECKS: HeaderCheck[] = [
  {
    header: "strict-transport-security",
    severity: "MEDIUM",
    title: "Tidak ada HTTP Strict Transport Security (HSTS)",
    impact:
      "Browser tidak dipaksa selalu pakai HTTPS, membuka celah downgrade/MITM lewat HTTP.",
    fix: "Tambahkan header `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`.",
  },
  {
    header: "content-security-policy",
    severity: "HIGH",
    title: "Tidak ada Content-Security-Policy (CSP)",
    impact:
      "Tanpa CSP, mitigasi XSS jauh lebih lemah — script asing yang berhasil disisipkan bisa jalan bebas.",
    fix: "Definisikan CSP minimal (`default-src 'self'`) lalu perketat bertahap sesuai kebutuhan aset.",
  },
  {
    header: "x-frame-options",
    severity: "MEDIUM",
    title: "Tidak ada X-Frame-Options",
    impact: "Halaman berpotensi di-embed di iframe domain lain (risiko clickjacking).",
    fix: "Tambahkan `X-Frame-Options: DENY` atau `SAMEORIGIN`, atau gunakan `frame-ancestors` di CSP.",
  },
  {
    header: "x-content-type-options",
    severity: "LOW",
    title: "Tidak ada X-Content-Type-Options",
    impact: "Browser bisa melakukan MIME-sniffing, berisiko file di-eksekusi sebagai tipe lain.",
    fix: "Tambahkan `X-Content-Type-Options: nosniff`.",
  },
  {
    header: "referrer-policy",
    severity: "LOW",
    title: "Tidak ada Referrer-Policy",
    impact: "URL sensitif berpotensi bocor ke pihak ketiga lewat header Referer.",
    fix: "Tambahkan `Referrer-Policy: strict-origin-when-cross-origin` (atau lebih ketat).",
  },
  {
    header: "permissions-policy",
    severity: "LOW",
    title: "Tidak ada Permissions-Policy",
    impact: "Tidak ada pembatasan eksplisit akses fitur browser (kamera, mic, geolokasi, dll).",
    fix: "Tambahkan `Permissions-Policy` sesuai fitur yang benar-benar dipakai saja.",
  },
];

export function analyzeSecurityHeaders(headers: Headers, endpointUrl: string): Finding[] {
  const findings: Finding[] = [];

  for (const check of CHECKS) {
    const value = headers.get(check.header);
    const ok = value !== null && (!check.validate || check.validate(value));
    if (!ok) {
      findings.push({
        id: cryptoRandomId(),
        severity: check.severity,
        title: check.title,
        endpoint: endpointUrl,
        evidence: `Header "${check.header}" tidak ditemukan pada response.`,
        impact: check.impact,
        fix: check.fix,
      });
    }
  }

  // Server header yang terlalu verbose (bocorin versi)
  const server = headers.get("server");
  if (server && /\d/.test(server)) {
    findings.push({
      id: cryptoRandomId(),
      severity: "LOW",
      title: "Header Server membocorkan versi software",
      endpoint: endpointUrl,
      evidence: `Server: ${server.slice(0, 100)}`,
      impact: "Memudahkan penyerang mencari exploit yang cocok dengan versi spesifik.",
      fix: "Sembunyikan/generic-kan header Server dan X-Powered-By di konfigurasi web server.",
    });
  }
  const poweredBy = headers.get("x-powered-by");
  if (poweredBy) {
    findings.push({
      id: cryptoRandomId(),
      severity: "LOW",
      title: "Header X-Powered-By membocorkan framework",
      endpoint: endpointUrl,
      evidence: `X-Powered-By: ${poweredBy.slice(0, 100)}`,
      impact: "Memudahkan fingerprinting stack teknologi oleh penyerang.",
      fix: "Nonaktifkan header X-Powered-By (mis. `poweredByHeader: false` di Next.js).",
    });
  }

  return findings;
}

function cryptoRandomId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}
