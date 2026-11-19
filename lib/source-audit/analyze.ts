/**
 * Mesin audit kode sumber dari arsip ZIP.
 * Statis & read-only: tidak ada kode yang dieksekusi, tidak ada berkas yang ditulis,
 * dan isi kode tidak disimpan. Yang keluar dari server hanya nama+versi paket ke OSV.dev.
 */
import type { Severity } from "@/lib/types";
import { readZip, isProbablyText, DEFAULT_ZIP_LIMITS } from "./zip";
import {
  LINE_RULES, SECRET_RULES, PLACEHOLDER, detectLang, redact, shannonEntropy,
  type Lang, type LineRule,
} from "./rules";
import { maskCode, CODE_LANGS } from "./mask";
import { maxVersion } from "./semver";
import { parseLockfiles, auditDependencies, type Dep } from "./deps";
import type { SourceAuditReport, SourceFinding, SourceCategory, Confidence } from "./types";

const RANK: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
const MAX_FINDINGS = 500;
const MAX_PER_RULE_PER_FILE = 3;
const SAST_BYTES_BUDGET = 30_000_000;

const newId = () => Math.random().toString(36).slice(2, 10);
const TEST_PATH = /(^|\/)(__tests__|tests?|spec|fixtures?|mocks?|examples?|samples?|docs?|stories)(\/|$)|(self-?test|\.test|\.spec|\.stories)\.[a-z]+$|\.(example|sample|template|dist)$/i;
const LOCKFILE = /(^|\/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|poetry\.lock|pipfile\.lock|go\.sum|gemfile\.lock|cargo\.lock|requirements[-\w]*\.txt)$/i;

function isComment(line: string, lang: Lang | null): boolean {
  const t = line.trimStart();
  if (t.startsWith("//") || t.startsWith("/*") || t.startsWith("* ") || t === "*" || t.startsWith("<!--")) return true;
  if (t.startsWith("#") && lang !== "js" && lang !== "cs" && lang !== "java") return true;
  return false;
}

function isMinified(path: string, text: string): boolean {
  if (/\.min\.(js|css)$|[-.]bundle\.js$|\.chunk\.js$/.test(path)) return true;
  const lines = text.length / Math.max(1, (text.match(/\n/g)?.length ?? 0) + 1);
  return lines > 400;
}

function trimSnippet(line: string): string {
  const s = line.trim().replace(/\s+/g, " ");
  return s.length > 180 ? s.slice(0, 177) + "…" : s;
}

function b64urlJson(part: string): Record<string, unknown> | null {
  try {
    return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

export async function analyzeSourceZip(buf: Buffer, fileName: string): Promise<SourceAuditReport> {
  const started = Date.now();
  const zip = readZip(buf, DEFAULT_ZIP_LIMITS);
  const findings: SourceFinding[] = [];
  const languages: Record<string, number> = {};
  const seenSecrets = new Map<string, SourceFinding>();
  const notes: string[] = [];

  const push = (f: Omit<SourceFinding, "id">) => {
    if (findings.length < MAX_FINDINGS) findings.push({ id: newId(), ...f });
  };

  // ---------- teks yang bisa dianalisis ----------
  const texts: { path: string; text: string; lang: Lang | null }[] = [];
  for (const e of zip.entries) {
    if (!isProbablyText(e.data)) continue;
    const lang = detectLang(e.path);
    texts.push({ path: e.path, text: e.data.toString("utf8"), lang });
    const ext = lang ?? (e.path.split(".").pop() || "other").toLowerCase();
    languages[ext] = (languages[ext] ?? 0) + 1;
  }
  const byBase = (re: RegExp) => texts.filter((t) => re.test(t.path.split("/").pop() ?? ""));
  const anyText = (re: RegExp) => texts.some((t) => re.test(t.text));

  // ---------- 1. Secrets ----------
  for (const { path, text } of texts) {
    if (LOCKFILE.test(path)) continue;
    const testFile = TEST_PATH.test(path);
    const minified = isMinified(path, text);
    const lines = text.split(/\r?\n/);
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > 4000) continue;

      for (const rule of SECRET_RULES) {
        if (minified && rule.id === "generic-secret") continue;
        const m = rule.re.exec(line);
        if (!m) continue;
        const value = rule.group ? m[rule.group] : m[0];
        if (!value) continue;
        if ((rule.id === "generic-secret" || rule.id === "db-url") && (PLACEHOLDER.test(value) || shannonEntropy(value) < 3)) continue;
        // Contoh resmi dokumentasi (mis. AKIAIOSFODNN7EXAMPLE) & nilai placeholder bukan secret nyata.
        if (rule.id !== "private-key" && /EXAMPLE|PLACEHOLDER|XXXXXXXX|00000000|123456789/i.test(value)) continue;
        if (rule.id === "db-url" && /localhost|127\.0\.0\.1|@db:|@postgres:|@mysql:|@redis:/.test(line) && testFile) continue;

        const key = `${rule.id}:${value}`;
        const prev = seenSecrets.get(key);
        if (prev) continue;
        const sev: Severity = testFile ? (RANK[rule.severity] >= 3 ? "MEDIUM" : "LOW") : rule.severity;
        const f: SourceFinding = {
          id: newId(),
          ruleId: `secret-${rule.id}`,
          severity: sev,
          title: `${rule.title} ditulis di kode`,
          category: "secret",
          cwe: "CWE-798",
          owasp: "A07:2021 Identification & Authentication Failures",
          file: path,
          line: i + 1,
          snippet: trimSnippet(line.replace(value, redact(value))),
          impact: testFile
            ? "Berada di berkas uji/contoh. Pastikan ini bukan kredensial asli."
            : "Siapa pun yang punya akses ke kode atau riwayat git dapat memakai kredensial ini.",
          fix: "Cabut (revoke) dan rotasi kredensial ini SEKARANG, pindahkan ke environment variable/secret manager, lalu hapus dari riwayat git (git filter-repo / BFG).",
          confidence: rule.id === "generic-secret" ? "pattern-only" : "likely",
        };
        seenSecrets.set(key, f);
        if (findings.length < MAX_FINDINGS) findings.push(f);
      }

      // Supabase service_role JWT (kunci yang mem-bypass RLS)
      for (const m of line.matchAll(/\beyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,}\b/g)) {
        const payload = b64urlJson(m[1]);
        if (payload?.role === "service_role") {
          const key = `sb-service:${m[0]}`;
          if (seenSecrets.has(key)) continue;
          const f: SourceFinding = {
            id: newId(), ruleId: "secret-supabase-service-role", severity: "CRITICAL",
            title: "Supabase service_role key ditulis di kode", category: "secret", cwe: "CWE-798",
            owasp: "A01:2021 Broken Access Control", file: path, line: i + 1,
            snippet: trimSnippet(line.replace(m[0], redact(m[0]))),
            impact: "service_role mem-bypass seluruh Row Level Security: akses baca/tulis penuh ke database.",
            fix: "Rotasi JWT secret di dashboard Supabase, simpan key hanya di server (tanpa NEXT_PUBLIC_).",
            confidence: "verified",
          };
          seenSecrets.set(key, f);
          if (findings.length < MAX_FINDINGS) findings.push(f);
        }
      }
    }
  }

  // ---------- 2. Berkas sensitif (dari nama) ----------
  const textByPath = new Map(texts.map((t) => [t.path, t.text]));
  for (const p of zip.allPaths) {
    const base = (p.split("/").pop() ?? p).toLowerCase();
    const add = (severity: Severity, title: string, impact: string, fix: string, cwe = "CWE-538", confidence: Confidence = "verified") =>
      push({ ruleId: "sensitive-file", severity, title, category: "sensitive-file", cwe, owasp: "A05:2021 Security Misconfiguration", file: p, impact, fix, confidence });

    if (/^\.env(\.(local|production|prod|development|dev|staging|test))?$/.test(base)) {
      const t = textByPath.get(p) ?? "";
      const realValues = t.split(/\r?\n/).filter((l) => /^\s*[A-Z0-9_]+\s*=\s*\S{6,}/.test(l) && !PLACEHOLDER.test(l)).length;
      add(realValues > 0 ? "HIGH" : "LOW", `Berkas ${base} ikut dalam arsip${realValues ? ` (${realValues} nilai terisi)` : ""}`,
        "Berkas environment biasanya berisi kunci API, password database, dan secret sesi.",
        "Jangan commit/kirim .env. Tambahkan ke .gitignore, gunakan .env.example berisi placeholder, dan rotasi nilai yang pernah bocor.", "CWE-538");
    } else if (/^id_(rsa|dsa|ecdsa|ed25519)$/.test(base)) {
      add("CRITICAL", `Kunci SSH privat (${base})`, "Akses SSH ke server/repo yang memercayai kunci ini.", "Cabut kunci dari authorized_keys/GitHub, buat kunci baru, hapus dari repo & riwayat.", "CWE-321");
    } else if (/\.(p12|pfx|jks|keystore|key)$/.test(base) && !/\.pub$/.test(base)) {
      add("HIGH", `Berkas kunci/sertifikat privat (${base})`, "Kunci penandatanganan (mis. keystore Android rilis) bisa dipakai memalsukan aplikasi/sertifikat.", "Simpan di secret manager/CI secrets, bukan di repo.", "CWE-321");
    } else if (/(service[-_]?account|firebase-adminsdk|credentials|gcp[-_]?key)[^/]*\.json$/.test(base) && /"private_key"/.test(textByPath.get(p) ?? "")) {
      add("CRITICAL", `Kredensial service account (${base})`, "Akses admin ke proyek Google Cloud/Firebase.", "Hapus kunci di IAM console, buat yang baru, simpan sebagai secret.", "CWE-798");
    } else if (/^(\.npmrc|\.pypirc|\.git-credentials|\.netrc|\.htpasswd)$/.test(base) && /(_authToken|password|:\/\/[^:\s]+:[^@\s]+@|\$apr1|\$2y)/.test(textByPath.get(p) ?? "")) {
      add("HIGH", `Berkas kredensial (${base}) berisi token/password`, "Token registry/akun dapat dipakai untuk publish paket atau akses akun.", "Cabut token, hapus berkas dari repo.", "CWE-798");
    } else if (/^terraform\.tfstate(\.backup)?$/.test(base)) {
      add("HIGH", "terraform.tfstate ikut dalam arsip", "State Terraform menyimpan output & atribut sumber daya, sering termasuk password dan key dalam teks biasa.", "Gunakan remote backend terenkripsi (S3+KMS, Terraform Cloud) dan hapus state dari repo.", "CWE-312");
    } else if (/\.(sqlite3?|db)$/.test(base) || (/\.sql$/.test(base) && /(dump|backup|bak|export|prod)/.test(base))) {
      add("MEDIUM", `Berkas database/dump (${base})`, "Dump database dapat berisi data pribadi pengguna dan hash password.", "Hapus dari repo; simpan backup di storage privat terenkripsi.", "CWE-530", "likely");
    }
  }
  if (zip.hasGitDir) {
    notes.push("Folder .git ikut terarsip: riwayat commit bisa berisi secret lama walau sudah dihapus dari kode terbaru.");
    push({ ruleId: "git-dir", severity: "INFO", title: "Folder .git ikut dalam arsip", category: "sensitive-file", cwe: "CWE-527", owasp: "A05:2021 Security Misconfiguration", file: ".git/", impact: "Bila folder ini ikut ter-deploy ke server web, seluruh kode & riwayat bisa diunduh (/.git/config).", fix: "Pastikan .git tidak pernah ter-deploy; blokir akses /.git di server.", confidence: "verified" });
  }

  // .gitignore tidak mengecualikan .env
  const gitignore = texts.find((t) => t.path === ".gitignore" || /^[^/]+\/\.gitignore$/.test(t.path));
  const usesEnv = anyText(/process\.env\.|os\.environ|getenv\(|env\(['"]/);
  if (usesEnv && (!gitignore || !/^\s*\.env/m.test(gitignore.text))) {
    push({ ruleId: "gitignore-env", severity: "MEDIUM", title: gitignore ? ".gitignore tidak mengecualikan .env" : "Tidak ada .gitignore padahal proyek memakai environment variable", category: "config", cwe: "CWE-538", owasp: "A05:2021 Security Misconfiguration", file: gitignore?.path ?? ".gitignore", impact: "Berkas .env berisi secret mudah ikut ter-commit dan ter-push ke GitHub publik.", fix: "Tambahkan baris `.env*` dan `!.env.example` ke .gitignore.", confidence: "verified" });
  }

  // ---------- 3. SAST per baris ----------
  let sastBytes = 0;
  for (const { path, text, lang } of texts) {
    if (!lang || LOCKFILE.test(path) || isMinified(path, text)) continue;
    sastBytes += text.length;
    if (sastBytes > SAST_BYTES_BUDGET) {
      notes.push("Batas analisis SAST tercapai; sebagian berkas besar tidak dipindai pola kodenya.");
      break;
    }
    const rules = LINE_RULES.filter((r) => r.lang.includes(lang) || r.lang.includes("any"));
    if (!rules.length) continue;
    const lines = text.split(/\r?\n/);
    const masked = CODE_LANGS.has(lang) ? maskCode(lines, lang) : null;
    const perRule = new Map<string, number>();
    const testFile = TEST_PATH.test(path);

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.length > 2000 || isComment(line, lang)) continue;
      for (const rule of rules) {
        const m = rule.re.exec(line);
        if (!m) continue;
        // Pola harus berada di kode, bukan di dalam string/komentar (kecuali aturan inString).
        if (!rule.inString && masked && masked[i][m.index] !== line[m.index]) continue;
        const count = perRule.get(rule.id) ?? 0;
        if (count >= MAX_PER_RULE_PER_FILE) continue;
        const w = rule.ctxLines ?? 2;
        const ctx = lines.slice(Math.max(0, i - w), i + w + 1).join("\n");
        if (rule.unless && rule.unless.test(ctx)) continue;
        let severity = rule.severity;
        let confidence = rule.confidence;
        const nearCtx = rule.nearSameLine ? line : ctx;
        if (rule.near && rule.near.test(nearCtx)) {
          if (rule.escalateTo) severity = rule.escalateTo;
          confidence = confidence === "pattern-only" ? "likely" : confidence;
        } else if (rule.near && !rule.escalateTo) {
          continue; // aturan yang hanya relevan bila ada konteks (mis. Math.random untuk token)
        }
        if (testFile && RANK[severity] > RANK.LOW) severity = "LOW";
        perRule.set(rule.id, count + 1);
        pushRule(rule, path, i + 1, line, severity, confidence);
      }
    }
  }

  function pushRule(rule: LineRule, file: string, line: number, raw: string, severity: Severity, confidence: Confidence) {
    push({ ruleId: rule.id, severity, title: rule.title, category: rule.category, cwe: rule.cwe, owasp: rule.owasp, file, line, snippet: trimSnippet(raw), impact: rule.impact, fix: rule.fix, confidence });
  }

  // ---------- 4. Pemeriksaan tingkat proyek ----------
  const frameworks = new Set<string>();
  const pkgs = byBase(/^package\.json$/).filter((t) => !t.path.includes("node_modules/"));
  const allDeps: Record<string, string> = {};
  for (const pkg of pkgs) {
    try {
      const j = JSON.parse(pkg.text);
      Object.assign(allDeps, j.dependencies ?? {}, j.devDependencies ?? {});
      for (const [name, script] of Object.entries<string>(j.scripts ?? {})) {
        if (/^(pre|post)?install$|^prepare$/.test(name) && /(curl|wget|Invoke-WebRequest|node\s+-e|python\s+-c|base64\s+-d|\|\s*(ba)?sh)/i.test(script)) {
          push({ ruleId: "npm-install-script", severity: "MEDIUM", title: `Skrip ${name} mengunduh/menjalankan kode`, category: "supply-chain", cwe: "CWE-506", owasp: "A08:2021 Software & Data Integrity Failures", file: pkg.path, snippet: trimSnippet(`"${name}": "${script}"`), impact: "Skrip lifecycle berjalan otomatis saat `npm install` di mesin developer & CI (pola umum malware paket).", fix: "Hapus atau ganti dengan langkah build eksplisit yang bisa diaudit.", confidence: "likely" });
        }
      }
      for (const [name, ver] of Object.entries<string>({ ...(j.dependencies ?? {}), ...(j.devDependencies ?? {}) })) {
        if (/^(git\+|https?:|github:|git:)/.test(ver)) {
          push({ ruleId: "npm-remote-dep", severity: "LOW", title: `Dependensi ${name} diambil dari URL/git`, category: "supply-chain", cwe: "CWE-829", owasp: "A08:2021 Software & Data Integrity Failures", file: pkg.path, snippet: `"${name}": "${ver}"`, impact: "Tidak melewati registry & audit npm; isi bisa berubah tanpa versi.", fix: "Gunakan versi dari registry atau pin ke commit SHA.", confidence: "verified" });
        }
      }
    } catch { /* package.json rusak */ }
  }
  if (allDeps.next) frameworks.add(`Next.js ${allDeps.next}`);
  if (allDeps.react && !allDeps.next) frameworks.add("React");
  if (allDeps.express) frameworks.add("Express");
  if (allDeps.fastify) frameworks.add("Fastify");
  if (allDeps.nuxt) frameworks.add("Nuxt");
  if (allDeps["@supabase/supabase-js"]) frameworks.add("Supabase");
  if (allDeps.firebase || allDeps["firebase-admin"]) frameworks.add("Firebase");
  if (allDeps.expo || allDeps["react-native"]) frameworks.add("React Native");
  if (texts.some((t) => /composer\.json$/.test(t.path) && /laravel\/framework/.test(t.text))) frameworks.add("Laravel");
  const anyPy = (re: RegExp) => texts.some((t) => t.lang === "py" && re.test(t.text));
  if (anyPy(/^\s*(from|import) django/m)) frameworks.add("Django");
  if (anyPy(/^\s*from flask import|Flask\(__name__\)/m)) frameworks.add("Flask");
  if (zip.allPaths.some((p) => /AndroidManifest\.xml$/.test(p))) frameworks.add("Android");
  if (zip.allPaths.some((p) => /\.csproj$/.test(p))) frameworks.add(".NET");
  if (zip.allPaths.some((p) => /(^|\/)go\.mod$/.test(p))) frameworks.add("Go");

  const hasLock = zip.allPaths.some((p) => LOCKFILE.test(p) && !/requirements/.test(p));
  if (pkgs.length && Object.keys(allDeps).length && !zip.allPaths.some((p) => /(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?)$/.test(p))) {
    push({ ruleId: "no-lockfile", severity: "LOW", title: "Tidak ada lockfile npm", category: "supply-chain", cwe: "CWE-1357", owasp: "A08:2021 Software & Data Integrity Failures", file: pkgs[0].path, impact: "Versi dependensi tidak terkunci; build bisa menarik versi baru yang disusupi.", fix: "Commit package-lock.json / pnpm-lock.yaml dan gunakan `npm ci` di CI.", confidence: "verified" });
  }

  // Header keamanan (Next.js / Express)
  const isWeb = frameworks.has("Express") || [...frameworks].some((f) => f.startsWith("Next.js")) || frameworks.has("Nuxt");
  if (isWeb && !anyText(/Content-Security-Policy|contentSecurityPolicy|helmet\(/)) {
    push({ ruleId: "no-csp", severity: "MEDIUM", title: "Tidak ada Content-Security-Policy yang dikonfigurasi", category: "config", cwe: "CWE-1021", owasp: "A05:2021 Security Misconfiguration", file: zip.allPaths.find((p) => /next\.config\.(m?js|ts)$/.test(p)) ?? "(proyek)", impact: "Tanpa CSP, XSS apa pun bisa memuat skrip asing dan mencuri sesi.", fix: "Next.js: buat CSP berbasis nonce di proxy/middleware (lihat dokumentasi 'Content Security Policy'). Express: gunakan helmet.", confidence: "likely" });
  }
  if (isWeb && !anyText(/X-Frame-Options|frame-ancestors|frameguard|helmet\(/)) {
    push({ ruleId: "no-frame-protection", severity: "LOW", title: "Tidak ada proteksi clickjacking (X-Frame-Options / frame-ancestors)", category: "config", cwe: "CWE-1021", owasp: "A05:2021 Security Misconfiguration", file: "(proyek)", impact: "Halaman bisa di-embed situs lain untuk clickjacking.", fix: "Kirim `X-Frame-Options: DENY` atau CSP `frame-ancestors 'none'`.", confidence: "likely" });
  }
  const hasApi = zip.allPaths.some((p) => /(^|\/)app\/api\/.+\/route\.(t|j)s$|(^|\/)pages\/api\/|routes?\/[^/]*(auth|login)/.test(p));
  if (hasApi && !anyText(/rate.?limit|ratelimit|@upstash\/ratelimit|express-rate-limit|throttle/i)) {
    push({ ruleId: "no-rate-limit", severity: "LOW", title: "Tidak terlihat mekanisme rate limiting di API", category: "auth", cwe: "CWE-770", owasp: "A04:2021 Insecure Design", file: "(proyek)", impact: "Endpoint login/API rawan brute force, credential stuffing, dan penyalahgunaan biaya (mis. API AI).", fix: "Tambahkan rate limit per IP/akun (@upstash/ratelimit, express-rate-limit) atau aturan WAF.", confidence: "pattern-only" });
  }
  if (frameworks.has("Express") && !anyText(/disable\(\s*['"]x-powered-by['"]\s*\)|helmet\(/)) {
    push({ ruleId: "express-powered-by", severity: "LOW", title: "Express mengirim header X-Powered-By", category: "config", cwe: "CWE-200", owasp: "A05:2021 Security Misconfiguration", file: "(proyek)", impact: "Memudahkan fingerprinting framework.", fix: "app.disable('x-powered-by') atau pakai helmet.", confidence: "likely" });
  }

  // Dockerfile tanpa USER / tanpa .dockerignore
  for (const d of texts.filter((t) => t.lang === "docker")) {
    const lastFrom = d.text.split(/\r?\n/).filter((l) => /^\s*FROM\s/i.test(l)).pop() ?? "";
    if (!/^\s*USER\s+(?!root\b|0\b)\S+/im.test(d.text) && !/distroless|scratch|chainguard/i.test(lastFrom)) {
      push({ ruleId: "docker-root", severity: "MEDIUM", title: "Kontainer berjalan sebagai root (tidak ada USER)", category: "container", cwe: "CWE-250", owasp: "A05:2021 Security Misconfiguration", file: d.path, impact: "RCE di aplikasi langsung menjadi root di kontainer, memudahkan escape.", fix: "Tambahkan `USER node` (Node), `USER 10001`, atau gunakan image distroless nonroot.", confidence: "verified" });
    }
    const dir = d.path.includes("/") ? d.path.slice(0, d.path.lastIndexOf("/") + 1) : "";
    if (/^\s*COPY\s+\.\s/m.test(d.text) && !zip.allPaths.includes(`${dir}.dockerignore`)) {
      push({ ruleId: "no-dockerignore", severity: "LOW", title: "COPY . tanpa .dockerignore", category: "container", cwe: "CWE-538", owasp: "A05:2021 Security Misconfiguration", file: d.path, impact: ".env, .git, dan kunci lokal ikut masuk ke image.", fix: "Buat .dockerignore berisi .env*, .git, node_modules, *.pem.", confidence: "verified" });
    }
  }

  // GitHub Actions "pwn request"
  for (const w of texts.filter((t) => t.lang === "gha")) {
    if (/pull_request_target/.test(w.text) && /ref:\s*\$\{\{\s*github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref/.test(w.text)) {
      push({ ruleId: "gha-pwn-request", severity: "CRITICAL", title: "pull_request_target + checkout kode PR (pwn request)", category: "ci-cd", cwe: "CWE-829", owasp: "A08:2021 Software & Data Integrity Failures", file: w.path, impact: "Kode dari fork tak tepercaya dijalankan dengan akses secrets & token tulis repo.", fix: "Gunakan `pull_request` biasa, atau jangan checkout/jalankan kode PR di job pull_request_target.", confidence: "likely" });
    }
  }

  // Supabase: tabel tanpa RLS
  const sql = texts.filter((t) => t.lang === "sql").map((t) => t.text).join("\n");
  if (sql) {
    const tables = new Set([...sql.matchAll(/create\s+table\s+(if\s+not\s+exists\s+)?(public\.)?"?(\w+)"?/gi)].map((m) => m[3].toLowerCase()));
    const rls = new Set([...sql.matchAll(/alter\s+table\s+(public\.)?"?(\w+)"?\s+enable\s+row\s+level\s+security/gi)].map((m) => m[2].toLowerCase()));
    const missing = [...tables].filter((t) => !rls.has(t));
    if (frameworks.has("Supabase") && missing.length) {
      push({ ruleId: "supabase-no-rls", severity: "HIGH", title: `Tabel tanpa Row Level Security: ${missing.slice(0, 6).join(", ")}${missing.length > 6 ? "…" : ""}`, category: "access-control", cwe: "CWE-284", owasp: "A01:2021 Broken Access Control", file: "(migrasi SQL)", impact: "Dengan anon key publik, siapa pun bisa membaca/menulis tabel ini lewat REST API Supabase.", fix: "`alter table <t> enable row level security;` lalu buat policy berbasis auth.uid().", confidence: "likely" });
    }
  }

  // ---------- 5. Dependensi (OSV) ----------
  const lockTexts = texts.filter((t) => LOCKFILE.test(t.path)).map((t) => ({ path: t.path, text: t.text }));
  let deps: Dep[] = parseLockfiles(lockTexts);
  if (!deps.length && Object.keys(allDeps).length && !hasLock) {
    deps = Object.entries(allDeps)
      .filter(([, v]) => /^\d+\.\d+\.\d+$/.test(v))
      .map(([name, version]) => ({ name, version, ecosystem: "npm" as const, source: "package.json" }));
  }
  const ecosystems: Record<string, number> = {};
  for (const d of deps) ecosystems[d.ecosystem] = (ecosystems[d.ecosystem] ?? 0) + 1;
  const depResult = await auditDependencies(deps);
  for (const v of depResult.vulnerable) {
    const worst = v.vulns.reduce<Severity>((a, b) => (RANK[b.severity] > RANK[a] ? b.severity : a), "LOW");
    const fixed = maxVersion(v.vulns.map((x) => x.fixed));
    push({
      ruleId: "vulnerable-dependency", severity: worst, category: "dependency" as SourceCategory,
      title: `${v.name}@${v.version} punya ${v.vulns.length} kerentanan diketahui`,
      cwe: "CWE-1395", owasp: "A06:2021 Vulnerable & Outdated Components", file: v.source,
      snippet: v.vulns.slice(0, 3).map((x) => `${x.aliases.find((a) => a.startsWith("CVE-")) ?? x.id}: ${x.summary}`).join(" | ").slice(0, 300),
      impact: "Kerentanan publik pada dependensi bisa dieksploitasi tanpa mengubah kode Anda.",
      fix: fixed ? `Upgrade ${v.name} ke ≥ ${fixed} (npm i ${v.name}@^${fixed}) lalu jalankan ulang tes.` : `Cek advisory di OSV.dev dan upgrade ${v.name} ke versi yang sudah ditambal.`,
      confidence: "version-based" as Confidence,
    });
  }
  if (depResult.error) notes.push(depResult.error);

  // ---------- 6. Skor ----------
  findings.sort((a, b) => RANK[b.severity] - RANK[a.severity] || a.file.localeCompare(b.file) || (a.line ?? 0) - (b.line ?? 0));
  const counts: Record<Severity, number> = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
  for (const f of findings) counts[f.severity]++;
  const weight = (f: SourceFinding) =>
    ({ CRITICAL: 20, HIGH: 8, MEDIUM: 3, LOW: 1, INFO: 0 })[f.severity] * (f.confidence === "pattern-only" ? 0.5 : 1);
  const penalty = findings.reduce((s, f) => s + weight(f), 0);
  const score = Math.max(0, Math.round(100 - Math.min(100, penalty)));
  const grade = counts.CRITICAL > 0 ? (score >= 40 ? "D" : "F") : score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F";

  if (findings.length >= MAX_FINDINGS) notes.push(`Temuan dibatasi ${MAX_FINDINGS} teratas.`);
  notes.unshift("Analisis statis (pattern + konteks). Temuan berlabel 'pattern-only' wajib direview manual sebelum dianggap kerentanan.");

  return {
    id: `src_${Date.now().toString(36)}${newId()}`,
    createdAt: Date.now(),
    fileName: fileName.slice(0, 120),
    durationMs: Date.now() - started,
    score,
    grade,
    counts,
    stats: {
      filesScanned: texts.length,
      bytesScanned: zip.totalBytes,
      totalEntries: zip.totalEntries,
      languages,
      frameworks: [...frameworks],
    },
    findings,
    dependencies: { scanned: deps.length, ecosystems, vulnerable: depResult.vulnerable, error: depResult.error },
    skipped: zip.skipped.slice(0, 50),
    notes,
  };
}
