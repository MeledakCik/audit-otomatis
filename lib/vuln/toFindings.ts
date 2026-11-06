/**
 * lib/vuln/toFindings.ts
 *
 * Adapter: konversi output modul passive-audit (jsLibChecker, domSink,
 * redirectChecker, idorDetector, authChecker) ke `Finding` (lib/types.ts).
 * Mendukung klasifikasi mendalam: wp2shell, php2shell, node2shell, go2shell, py2shell, node-oob, webshell, filemanager-shell.
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
  return sinks.map((s) => {
    if (s.type === "node2shell_child_process") {
      return {
        id: newId(),
        severity: toLegacySeverity(s.severity),
        title: `[node2shell] Indikator eksekusi proses Node.js (${s.type})`,
        endpoint: sourceLabel,
        evidence: s.evidence,
        impact:
          "Pola pemanggilan child_process / exec / spawn ditemukan di kode JS. Apabila menerima input pengguna tanpa sanitasi di sisi server/SSR, berisiko memicu OS Command Injection (node2shell).",
        fix: "Hindari child_process.exec dengan string dinamis; gunakan execFile dengan argumen array yang divalidasi ketat dan jangan pernah menyertakan kode server di bundle client.",
        cwe: "CWE-78",
        rce: true,
        category: "node2shell",
      };
    }
    if (s.type === "node2shell_vm_eval") {
      return {
        id: newId(),
        severity: toLegacySeverity(s.severity),
        title: `[node2shell] Sink eksekusi VM / Function dinamis (${s.type})`,
        endpoint: sourceLabel,
        evidence: s.evidence,
        impact:
          "Penggunaan modul vm Node.js atau konstruktor new Function() bukan sandbox keamanan yang aman dan sering dapat di-bypass untuk mencapai RCE (node2shell).",
        fix: "Ganti vm.runInNewContext / new Function dengan parser deklaratif (JSON.parse) atau isolasi proses menggunakan worker/container terpisah.",
        cwe: "CWE-94",
        rce: true,
        category: "node2shell",
      };
    }
    if (s.type === "node2shell_deserialization") {
      return {
        id: newId(),
        severity: toLegacySeverity(s.severity),
        title: `[node2shell] Pola deserialisasi tidak aman (${s.type})`,
        endpoint: sourceLabel,
        evidence: s.evidence,
        impact:
          "Deserialisasi payload menggunakan node-serialize / unserialize dapat mengeksekusi IIFE (Immediately Invoked Function Expression) yang berujung pada Remote Code Execution (node2shell).",
        fix: "Gunakan JSON.parse murni dengan validasi skema (Zod/Joi) dan hapus pustaka node-serialize.",
        cwe: "CWE-502",
        rce: true,
        category: "node2shell",
      };
    }
    if (s.type === "node2shell_prototype_pollution") {
      return {
        id: newId(),
        severity: toLegacySeverity(s.severity),
        title: `[node2shell] Kandidat Prototype Pollution (__proto__ / prototype)`,
        endpoint: sourceLabel,
        evidence: s.evidence,
        impact:
          "Manipulasi properti __proto__ atau constructor.prototype tanpa filter dapat mencemari Object.prototype global, menyebabkan DOM XSS di browser atau RCE gadget chain di Node.js (node2shell).",
        fix: "Blokir kunci '__proto__', 'constructor', dan 'prototype' saat melakukan deep merge/clone objek, atau gunakan Map / Object.create(null).",
        cwe: "CWE-1321",
        category: "node2shell",
      };
    }
    if (s.type === "node_oob_buffer") {
      return {
        id: newId(),
        severity: toLegacySeverity(s.severity),
        title: `[Node Out-of-Bounds] Alokasi Buffer / TypedArray rawan OOB (${s.type})`,
        endpoint: sourceLabel,
        evidence: s.evidence,
        impact:
          "Penggunaan Buffer.allocUnsafe, konstruktor new Buffer(size) usang, atau pembacaan byteOffset DataView tanpa validasi batas dapat membocorkan memori internal (Out-of-Bounds Read CWE-125) atau korupsi memori (CWE-119/CWE-787).",
        fix: "Gunakan Buffer.alloc() (otomatis zero-filled) atau Buffer.from(), dan selalu validasi batas panjang & offset sebelum mengakses TypedArray/DataView.",
        cwe: "CWE-119, CWE-125",
        category: "node-oob",
      };
    }
    if (s.type === "wp2shell_admin_ajax") {
      return {
        id: newId(),
        severity: toLegacySeverity(s.severity),
        title: `[wp2shell] Endpoint WordPress admin-ajax / nopriv hook terdeteksi`,
        endpoint: sourceLabel,
        evidence: s.evidence,
        impact:
          "Rute /wp-admin/admin-ajax.php atau action wp_ajax_nopriv_ sering menjadi vektor utama kerentanan plugin WordPress (SQLi, Arbitrary File Upload, Privilege Escalation -> wp2shell).",
        fix: "Pastikan setiap handler AJAX WordPress memverifikasi nonce (check_ajax_referer) dan kapabilitas pengguna (current_user_can).",
        cwe: "CWE-284",
        category: "wp2shell",
      };
    }
    if (s.type === "webshell_filemanager_bridge") {
      return {
        id: newId(),
        severity: "HIGH",
        title: `[FileManager / WebShell Bridge] Referensi endpoint File Manager / WebShell di kode JS`,
        endpoint: sourceLabel,
        evidence: s.evidence,
        impact:
          "Ditemukan referensi langsung ke konektor Web File Manager (elFinder connector.minimal.php, TinyFileManager, Responsive FileManager, KCFinder, Roxy) atau penanda WebShell (FilesMan/Alfa) di kode client-side.",
        fix: "Pastikan endpoint konektor File Manager tidak dapat diakses tanpa autentikasi admin penuh, atau hapus plugin/file manager tersebut dari server produksi.",
        cwe: "CWE-434, CWE-306",
        rce: true,
        category: "filemanager-shell",
      };
    }

    return {
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
    };
  });
}

/** redirectChecker.detectRedirectParams() -> Finding[] (kandidat, belum di-fetch). */
export function redirectCasesToFindings(cases: TestCase[]): Finding[] {
  return cases.map((c) => {
    if (c.type === "NODE_OOB") {
      return {
        id: newId(),
        severity: toLegacySeverity(c.severity),
        title: `[Node Out-of-Band / OOB] Kandidat interaksi eksternal via param "${c.param}"`,
        endpoint: c.originalUrl,
        evidence: c.evidence,
        impact:
          "Parameter callback/webhook/pingback/xml/uri yang diproses server tanpa allowlist dapat memicu interaksi Out-of-Band (OOB SSRF, Blind XXE, atau kebocoran token ke host eksternal).",
        fix: "Terapkan allowlist domain tujuan secara ketat, matikan resolusi external entity pada parser XML, dan blokir akses ke IP privat/metadata cloud.",
        poc: `Analisis pasif (tidak dieksekusi otomatis): periksa apakah parameter "${c.param}" melakukan HTTP/DNS lookup ke host eksternal.`,
        cwe: "CWE-918, CWE-611",
        category: "node-oob",
      };
    }

    if (c.type === "SHELL_SURFACE") {
      return {
        id: newId(),
        severity: toLegacySeverity(c.severity),
        title: `[WebShell & RCE Surface] Kandidat parameter eksekusi "${c.param}"`,
        endpoint: c.originalUrl,
        evidence: c.evidence,
        impact:
          "Parameter dengan nama seperti cmd/exec/shell/passthru/system/code/eval/file/include sangat identik dengan backdoor WebShell atau berisiko tinggi terhadap Command Injection, Code Injection, maupun LFI/RFI.",
        fix: "Periksa file endpoint terkait untuk memastikan bukan backdoor WebShell, dan jangan pernah meneruskan nilai query parameter langsung ke fungsi eksekusi shell/eval/include.",
        poc: `Analisis pasif (tidak dieksekusi otomatis): audit handler backend untuk parameter "${c.param}" guna memastikan tidak ada pemanggilan shell/eval/file inclusion dinamis.`,
        cwe: "CWE-78, CWE-94, CWE-98",
        rce: true,
        category: "webshell",
      };
    }

    if (c.type === "FILEMANAGER_SURFACE") {
      return {
        id: newId(),
        severity: toLegacySeverity(c.severity),
        title: `[FileManager WebShell] Kandidat parameter operasi filesystem "${c.param}"`,
        endpoint: c.originalUrl,
        evidence: c.evidence,
        impact:
          "Parameter seperti dir/cwd/chmod/mkdir/unlink/rename/upfile merupakan tanda operasi manipulasi sistem file pada Web File Manager atau FileManager WebShell yang berpotensi memodifikasi file server.",
        fix: "Pastikan endpoint ini bukan FileManager WebShell liar, batasi path dengan realpath allowlist (cegah Path Traversal ../), dan wajibkan autentikasi ketat.",
        poc: `Analisis pasif (tidak dieksekusi otomatis): tinjau kontrol otorisasi dan sanitasi path pada endpoint yang menerima parameter "${c.param}".`,
        cwe: "CWE-22, CWE-434, CWE-306",
        rce: true,
        category: "filemanager-shell",
      };
    }

    return {
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
    };
  });
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
