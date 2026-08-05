/**
 * lib/vuln/toFindings.ts
 *
 * Adapter: konversi output modul passive-audit (jsLibChecker, domSink,
 * redirectChecker, idorDetector, authChecker — semua pakai `AuditFinding`
 * standard JSON di ./types) ke `Finding` lama (lib/types.ts) supaya bisa
 * masuk ke pipeline addFinding() -> scan-store -> Finding UI -> export
 * markdown yang sudah ada, tanpa perlu ubah bentuk data di modul aslinya.
 *
 * Semua fungsi di sini pure (tidak ada network call) — cuma mapping data +
 * penulisan impact/fix dalam Bahasa Indonesia senada dengan module lain
 * (secret-scanner.ts, library-fingerprint.ts).
 */

import type { Finding } from "../types";
import { toLegacySeverity } from "./types";
import type { Vuln } from "./jsLibChecker";
import type { Sink } from "./domSink";
import type { TestCase } from "./redirectChecker";
import type { IdorCase } from "./idorDetector";
import type { AuthCheckResult } from "./authChecker";
import type { DiscoveredFileResult } from "../discovery/passiveDiscovery";

function newId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

/** jsLibChecker.checkVulnerableLibs() -> Finding[] ("Retire.js lite"). */
export function vulnLibsToFindings(vulns: Vuln[], sourceLabel: string): Finding[] {
  return vulns.map((v) => ({
    id: newId(),
    severity: toLegacySeverity(v.severity),
    title: `Library jadul terdeteksi (banner match): ${v.library} v${v.versionFound}`,
    endpoint: sourceLabel,
    evidence: v.evidence,
    impact: `${v.cve}. Terdeteksi dari string versi di source, bukan dari analisis dependency — false-negative wajar kalau bundle sudah di-minify agresif.`,
    fix: `Upgrade ${v.library} ke versi terbaru yang tidak lagi masuk rule "< ${v.versionFound}". Cek release notes/advisory resmi sebelum upgrade untuk breaking changes.`,
    category: "outdated-library",
  }));
}

/** domSink.findDomSinks() -> Finding[]. */
export function domSinksToFindings(sinks: Sink[], sourceLabel: string): Finding[] {
  return sinks.map((s) => ({
    id: newId(),
    severity: toLegacySeverity(s.severity),
    title: `Potensi DOM XSS sink: ${s.type}`,
    endpoint: sourceLabel,
    evidence: s.evidence,
    impact:
      "Sink DOM ini bisa jadi vektor XSS kalau data yang masuk berasal dari sumber yang bisa dikontrol pengguna (URL, postMessage, dsb) tanpa sanitasi. Deteksi ini regex pattern-matching di source, bukan bukti exploitability — wajib direview manual.",
    fix: "Review kode di sekitar sink ini. Ganti innerHTML/outerHTML/document.write dengan textContent atau sanitizer (mis. DOMPurify), hindari eval/setTimeout dengan argumen string, dan validasi/encode nilai dari location.hash atau location.search sebelum dipakai.",
    cwe: "CWE-79",
    category: "dom-xss-sink",
  }));
}

/** redirectChecker.detectRedirectParams() -> Finding[] (kandidat, belum di-fetch). */
export function redirectCasesToFindings(cases: TestCase[]): Finding[] {
  return cases.map((c) => ({
    id: newId(),
    severity: toLegacySeverity(c.severity),
    title:
      c.type === "SSRF"
        ? `Kandidat SSRF via query param "${c.param}"`
        : `Kandidat Open Redirect via query param "${c.param}"`,
    endpoint: c.originalUrl,
    evidence: c.evidence,
    impact:
      c.type === "SSRF"
        ? "Kalau server benar-benar melakukan fetch balik ke nilai param ini tanpa validasi, endpoint berpotensi disalahgunakan untuk SSRF ke resource internal / cloud metadata endpoint."
        : "Kalau server melakukan redirect ke nilai param ini tanpa whitelist, endpoint berpotensi disalahgunakan untuk phishing (redirect ke domain attacker yang terlihat berasal dari domain tepercaya).",
    fix:
      c.type === "SSRF"
        ? "Whitelist domain/IP tujuan yang boleh di-fetch server, blok range IP internal & metadata endpoint (169.254.169.254) di level aplikasi/network."
        : "Validasi nilai redirect terhadap whitelist domain internal, atau pakai mapping id -> URL alih-alih menerima URL bebas dari user.",
    poc: `Kandidat test case (belum dieksekusi — perlu izin eksplisit sebelum dijalankan): ganti param "${c.param}" jadi \`${c.payload}\` lalu cek header Location / perilaku response.`,
    cwe: c.type === "SSRF" ? "CWE-918" : "CWE-601",
    category: c.type === "SSRF" ? "ssrf" : "open-redirect",
  }));
}

/** idorDetector.generateIdorCases() -> Finding[], di-dedup 1 baris per originalUrl. */
export function idorCasesToFindings(cases: IdorCase[]): Finding[] {
  const seen = new Set<string>();
  const out: Finding[] = [];

  for (const c of cases) {
    if (seen.has(c.originalUrl)) continue;
    seen.add(c.originalUrl);

    const candidateUrls = cases.filter((x) => x.originalUrl === c.originalUrl).map((x) => x.testUrl);

    out.push({
      id: newId(),
      severity: toLegacySeverity(c.severity),
      title: `Kandidat IDOR: ID numerik "${c.originalId}" di path`,
      endpoint: c.originalUrl,
      evidence: c.evidence,
      impact:
        "Kalau endpoint ini tidak melakukan otorisasi per-object (verifikasi kepemilikan resource, bukan cuma cek autentikasi), mengganti ID di path bisa membocorkan atau memodifikasi data milik user lain.",
      fix: "Pastikan akses ke resource ini memverifikasi bahwa ID yang diminta memang milik user yang sedang login (object-level authorization), bukan cuma cek token/session valid.",
      poc: `Kandidat URL test (belum dieksekusi — perlu izin eksplisit sebelum dijalankan): ${candidateUrls
        .map((u) => `\`${u}\``)
        .join(", ")}`,
      cwe: "CWE-639",
      category: "idor-candidate",
    });
  }

  return out;
}

/** authChecker.checkAuthBypass()/checkAuthBypassBatch() -> Finding[]. */
export function authCheckToFindings(results: AuthCheckResult[]): Finding[] {
  const out: Finding[] = [];

  for (const r of results) {
    for (const f of r.findings) {
      const isBypass = f.type === "AUTH_BYPASS_POTENTIAL";
      out.push({
        id: newId(),
        severity: toLegacySeverity(f.severity),
        title: isBypass
          ? "Potensi endpoint sensitif bisa diakses tanpa autentikasi"
          : "Header rate-limit tidak ditemukan",
        endpoint: r.url,
        evidence: f.evidence,
        impact: isBypass
          ? "Endpoint yang path-nya terlihat butuh auth (admin/me/user) tapi mengembalikan HTTP 200 tanpa credentials berpotensi membocorkan data atau fungsi privileged ke pengguna anonim."
          : "Tanpa rate-limit header, tidak ada sinyal awal proteksi terhadap brute-force/abuse di endpoint ini — bukan bukti pasti tidak ada rate limit (bisa saja di-enforce di layer lain seperti WAF/CDN), tapi layak dicek manual.",
        fix: isBypass
          ? "Pastikan endpoint ini memvalidasi session/token di server sebelum mengembalikan data, dan kembalikan 401/403 kalau credentials tidak valid/tidak ada."
          : "Tambahkan rate limiting (mis. per-IP atau per-token) di endpoint ini kalau belum di-enforce di layer manapun.",
        cwe: isBypass ? "CWE-284" : "CWE-799",
        category: isBypass ? "auth-bypass" : "missing-rate-limit",
      });
    }
  }

  return out;
}

/** passiveDiscovery.discoverFilesDetailed() -> Finding[] (informational + swagger/openapi exposure). */
export function passiveDiscoveryToFindings(baseUrl: string, results: DiscoveredFileResult[]): Finding[] {
  const found = results.filter((r) => r.found);
  if (found.length === 0) return [];

  const out: Finding[] = [];
  const totalExtracted = found.reduce((sum, r) => sum + r.extractedPaths.length, 0);

  out.push({
    id: newId(),
    severity: "INFO",
    title: `Well-known file ditemukan: ${found.map((r) => r.path).join(", ")}`,
    endpoint: baseUrl,
    evidence: `${found.length} file well-known dapat diakses (${found
      .map((r) => `${r.path} [${r.status}]`)
      .join(", ")}). ${totalExtracted} path baru ditemukan dari isinya (sitemap/robots).`,
    impact:
      "File-file ini bukan kerentanan — sitemap.xml/robots.txt memang lazim publik. Tapi isinya bisa mempersempit permukaan endpoint yang perlu dicek lebih lanjut.",
    fix: "Tidak wajib diperbaiki. Kalau swagger.json/openapi.json ternyata tidak dimaksudkan untuk publik, lihat finding terpisah di bawah.",
    category: "passive-discovery",
  });

  for (const s of found.filter((r) => r.path.endsWith("swagger.json") || r.path.endsWith("openapi.json"))) {
    out.push({
      id: newId(),
      severity: "LOW",
      title: `API spec publik terekspos: ${s.path}`,
      endpoint: baseUrl + s.path,
      evidence: `${s.path} dapat diakses publik (HTTP ${s.status}) tanpa autentikasi.`,
      impact:
        "API spec publik memudahkan pemetaan seluruh permukaan API (endpoint, parameter, schema) tanpa perlu reverse-engineering manual.",
      fix: "Kalau API ini tidak dimaksudkan untuk konsumsi publik, batasi akses ke file spec ini (auth/IP allowlist) atau strip detail endpoint internal dari dokumen publik.",
      cwe: "CWE-200",
      category: "passive-discovery",
    });
  }

  return out;
}
