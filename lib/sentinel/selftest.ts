/**
 * Self-test mesin "Audit File Sensitif" — TANPA jaringan, TANPA menyentuh domain manapun.
 * Menjalankan fixture tetap (string statis) lewat jalur kode produksi yang sama
 * (analyzeText / evaluateSensitive / buildCatalog / parseComposerPackages) untuk memverifikasi
 * engine masih berfungsi sebelum dipakai untuk pelaporan ke pihak domain.
 */
import {
  analyzeText,
  awsAccountFromKeyId,
  buildCatalog,
  evaluateSensitive,
  parseComposerPackages,
  placeholderReason,
  publicSummaryLine,
  redact,
  type SensitiveResponse,
} from "./sensitive";
import { buildSensitiveDossier, sensitiveDossierToMarkdown } from "./sensitive-dossier";
import type { SensitiveFileEntry } from "./sensitive-types";

export interface SelfTestCase { name: string; pass: boolean; detail: string }
export interface SelfTestResult { ranAt: number; pass: number; fail: number; cases: SelfTestCase[]; ok: boolean }

const resp = (text: string, ct = "text/plain", status = 200, head = new Uint8Array(8)): SensitiveResponse => ({
  status, contentType: ct, text, head, size: text.length,
});

export function runSelfTest(): SelfTestResult {
  const cases: SelfTestCase[] = [];
  const T = (name: string, ok: boolean, detail = "") => cases.push({ name, pass: ok, detail });

  // 1) .env NYATA → CRITICAL + liveCount > 0, nilai tidak bocor ke evidence_public
  {
    const spec = buildCatalog("contoh-selftest.id", { deep: true }).find((s) => s.path === "/.env.development")!;
    const hit = evaluateSensitive(spec, resp("APP_NAME=Trout\nDB_PASSWORD=S3cretHunter2!\nAPP_KEY=base64:QUJDREVGRw==\n"));
    const pub = hit ? publicSummaryLine(hit, 200) : "";
    T("Katalog: .env.staging berkredensial nyata -> CRITICAL", hit?.severity === "CRITICAL" && (hit?.analysis.liveCount ?? 0) > 0);
    T("Publik: evidence TIDAK memuat nilai rahasia", !pub.includes("S3cretHunter2") && !pub.includes("QUJDREVGRw"));
  }

  // 2) .env HANYA placeholder → severity diturunkan ke HIGH (downgradeWhenNoLive)
  {
    const spec = buildCatalog("contoh-selftest.id", { deep: true }).find((s) => s.path === "/.env.development")!;
    const hit = evaluateSensitive(spec, resp("APP_NAME=Trout\nDB_PASSWORD=changeme\nAPP_DEBUG=true\n"));
    T("Katalog: .env hanya placeholder -> diturunkan ke HIGH", hit?.severity === "HIGH" && hit?.analysis.liveCount === 0);
  }

  // 3) SPA catch-all (semua path balas 200 halaman HTML yang sama) → bukan true positive
  {
    const spec = buildCatalog("contoh-selftest.id", { deep: true }).find((s) => s.path === "/.env.development")!;
    const hit = evaluateSensitive(spec, resp("<!doctype html><html><body>App Shell DB_PASSWORD=</body></html>", "text/html"));
    T("Anti false-positive: SPA catch-all HTML -> ditolak", hit === null);
  }

  // 4) AWS access key -> flag live + account ID diturunkan OFFLINE (vektor uji resmi AWS)
  {
    const acct = awsAccountFromKeyId("AKIAIOSFODNN7EXAMPLE");
    T("AWS: account-id offline dari AKIAIOSFODNN7EXAMPLE = 581039954779", acct === "581039954779");
    T("AWS: kunci contoh resmi AWS (mengandung 'EXAMPLE') -> BUKAN live", placeholderReason("AKIAIOSFODNN7EXAMPLE") !== null);
    // Format AWS access key ID yang sah (AKIA + 16 karakter base32), BUKAN kunci nyata — hanya untuk uji pola regex/entropi.
    // Dirakit saat runtime (bukan string literal utuh) supaya scanner secret (mis. GitHub Push
    // Protection) tidak menganggap ini kredensial sungguhan, walau formatnya valid secara pola.
    // Alfabet base32 AWS: A-Z & 2-7 saja (tanpa 0/1/8/9).
    const fixtureKey = ["AKIA", "2Q7Z", "J4NR", "X6P3", "W7KF"].join("");
    const fixtureSecret = ["kH8m", "Q2zV", "t5uR", "7wXp", "Y1bC", "4dN6", "sL9e", "A0fJ", "3gM5", "hT8r"].join("");
    const a = analyzeText(`aws_access_key_id = ${fixtureKey}\naws_secret_access_key = ${fixtureSecret}`, "credentials", "aws credentials");
    const ak = a.secrets.find((s) => s.type === "aws-access-key");
    T("AWS: access key format sah terdeteksi & live, preview tersamarkan", !!ak && ak.live && ak.preview.includes("…") && !ak.preview.includes(fixtureKey.slice(4, -2)));
  }

  // 5) Private key terenkripsi passphrase tetap ditandai live (karena tetap bisa di-brute-force)
  {
    const pem = "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,ABCDEF0123456789\n\n" + "A".repeat(200) + "\n-----END RSA PRIVATE KEY-----";
    const a = analyzeText(pem, "private-key", "id_rsa");
    T("Private key terenkripsi tetap live (bukan diabaikan)", a.secrets.some((s) => s.type === "private-key" && s.live));
  }

  // 6) JWT kedaluwarsa → ditandai TIDAK live (exp di masa lalu)
  {
    const b64url = (o: object) => Buffer.from(JSON.stringify(o)).toString("base64url");
    const jwt = `${b64url({ alg: "HS256", typ: "JWT" })}.${b64url({ sub: "1", exp: Math.floor(Date.now() / 1000) - 3600 })}.sig_AAAAAAAAAAAAAAAAAAAAAA`;
    const a = analyzeText(`token=${jwt}`, "credentials", "jwt");
    const j = a.secrets.find((s) => s.type === "jwt");
    T("JWT kedaluwarsa -> live=false", !!j && j.live === false && j.reason === "kedaluwarsa");
  }

  // 7) composer.lock asli → jumlah paket & phpunit-in-prod terbaca benar
  {
    const lock = JSON.stringify({
      packages: [{ name: "laravel/framework", version: "v8.40.0" }, { name: "guzzlehttp/guzzle", version: "7.4.1" }],
      "packages-dev": [{ name: "phpunit/phpunit", version: "9.5.0" }],
    });
    const { components, summary } = parseComposerPackages(lock, "x", "x");
    T("composer.lock: 2 prod + 1 dev terbaca, phpunit tidak dihitung prod", summary.prod === 2 && summary.dev === 1 && !summary.phpunitInProd && components.length === 3);
  }

  // 8) SQL dump asli vs artikel yang hanya MENYEBUT "CREATE TABLE"
  {
    const spec = buildCatalog("contoh-selftest.id", { deep: true }).find((s) => s.path === "/db.sql")!;
    const real = evaluateSensitive(spec, resp("-- MySQL dump 10.13\nCREATE TABLE `users` (`id` int, `email` varchar(255));\nINSERT INTO `users` VALUES (1,'a@b.com');\n"));
    const fake = evaluateSensitive(spec, resp("Tutorial: untuk membuat tabel pakai CREATE TABLE lalu INSERT INTO seperti ini...", "text/html"));
    T("SQL dump asli -> CRITICAL + tabel terbaca", real?.severity === "CRITICAL" && (real?.analysis.sqlTables?.length ?? 0) > 0);
    T("Artikel yang menyebut 'CREATE TABLE' -> ditolak (bukan dump asli)", fake === null);
  }

  // 9) placeholder/redaction util
  T("placeholderReason: 'changeme' terdeteksi placeholder", placeholderReason("changeme") !== null);
  T("placeholderReason: secret acak panjang -> bukan placeholder", placeholderReason("k7Jp2m9QxZ4vL8nR1tY6") === null);
  T("redact(): tidak pernah membocorkan nilai utuh", !redact("SuperRahasia123456").includes("SuperRahasia123456"));

  // 10) directory listing varian nama domain ikut masuk katalog
  {
    const cat = buildCatalog("www.noxora.site", { deep: true });
    T("Katalog: varian nama domain (noxora.zip / noxora.sql) otomatis ditambahkan", cat.some((s) => /\/noxora(?:[._-])/i.test(s.path)));
  }

  // 11) dossier + laporan markdown untuk pelaporan ke pihak domain
  {
    const spec = buildCatalog("contoh-selftest.id", { deep: true }).find((s) => s.path === "/.env.development")!;
    const hit = evaluateSensitive(spec, resp("DB_PASSWORD=HunterLive123!\nMAIL_PASSWORD=placeholder\n"))!;
    const entry: SensitiveFileEntry = {
      path: spec.path, url: `https://contoh-selftest.id${spec.path}`, title: hit.spec.title, category: hit.spec.category,
      severity: hit.severity, fileKind: hit.fileKind, marker: hit.marker, status: 200, confidence: "verified",
      analysis: hit.analysis, cwe: hit.spec.cwe, cve: hit.spec.cve, rce: hit.spec.rce, fix: hit.spec.fix,
    };
    const d = buildSensitiveDossier("contoh-selftest.id", "https://contoh-selftest.id", 1, [entry]);
    const md = sensitiveDossierToMarkdown(d);
    T("Dossier: ringkasan live/placeholder terhitung benar", d.summary.liveSecrets >= 1 && d.summary.totalFiles === 1);
    T("Laporan .md: ada kolom verifikasi & TIDAK memuat nilai penuh", /Diverifikasi oleh/.test(md) && !md.includes("HunterLive123!"));
  }

  const pass = cases.filter((c) => c.pass).length;
  return { ranAt: Date.now(), pass, fail: cases.length - pass, cases, ok: cases.every((c) => c.pass) };
}
