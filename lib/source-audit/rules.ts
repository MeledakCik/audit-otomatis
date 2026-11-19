/**
 * Aturan audit kode sumber (statis, tanpa eksekusi).
 * Prinsip: tiap aturan menyebut CWE + OWASP Top 10 (2021), punya tingkat keyakinan,
 * dan memakai konteks (`near`/`unless`) untuk menekan false positive.
 */
import type { Severity } from "@/lib/types";
import type { Confidence, SourceCategory } from "./types";

export type Lang =
  | "js" | "php" | "py" | "go" | "java" | "cs" | "rb"
  | "docker" | "gha" | "compose" | "k8s" | "tf" | "nginx" | "sql" | "rules" | "android" | "env" | "any";

export function detectLang(path: string): Lang | null {
  const p = path.toLowerCase();
  const base = p.split("/").pop() ?? p;
  if (/\.(m|c)?[jt]sx?$/.test(p) || p.endsWith(".vue") || p.endsWith(".svelte")) return "js";
  if (p.endsWith(".php") || p.endsWith(".phtml")) return "php";
  if (p.endsWith(".py")) return "py";
  if (p.endsWith(".go")) return "go";
  if (base === "androidmanifest.xml") return "android";
  if (p.endsWith(".java") || p.endsWith(".kt") || p.endsWith(".kts")) return "java";
  if (p.endsWith(".cs")) return "cs";
  if (p.endsWith(".rb")) return "rb";
  if (base === "dockerfile" || base.endsWith(".dockerfile") || base.startsWith("dockerfile.")) return "docker";
  if (/(^|\/)\.github\/workflows\/[^/]+\.ya?ml$/.test(p)) return "gha";
  if (/^(docker-)?compose(\.[\w-]+)?\.ya?ml$/.test(base)) return "compose";
  if (p.endsWith(".tf")) return "tf";
  if (base.endsWith(".conf") && /nginx|sites-(available|enabled)/.test(p)) return "nginx";
  if (base === "nginx.conf") return "nginx";
  if (p.endsWith(".sql")) return "sql";
  if (/(firestore|storage)\.rules$|database\.rules\.json$/.test(base)) return "rules";
  if (p.endsWith(".yaml") || p.endsWith(".yml")) return "k8s";
  if (/^\.env(\.|$)/.test(base)) return "env";
  return null;
}

export interface LineRule {
  id: string;
  lang: Lang[];
  re: RegExp;
  severity: Severity;
  title: string;
  category: SourceCategory;
  cwe: string;
  owasp: string;
  impact: string;
  fix: string;
  confidence: Confidence;
  /** Naikkan severity bila pola ini muncul di ±2 baris (mis. input user). */
  near?: RegExp;
  escalateTo?: Severity;
  /** Lewati bila pola ini ada di ±2 baris (sanitizer, nilai literal, dll). */
  unless?: RegExp;
  /** Jumlah baris konteks di atas/bawah untuk near/unless (default 2). */
  ctxLines?: number;
  /** `near` hanya dicek di baris yang sama (bukan ±2 baris). */
  nearSameLine?: boolean;
  /** Pola boleh berada di dalam string literal (mis. nama header). Default: hanya kode. */
  inString?: boolean;
}

// Sumber input yang dikontrol pengguna, per bahasa.
const JS_USER = /\breq\.(query|body|params|headers|cookies)|searchParams\.get\(|request\.(json|formData|nextUrl)|\bformData\.get\(|ctx\.(query|request)|event\.queryStringParameters|params\.[a-z]/i;
const PHP_USER = /\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\b/;
const PY_USER = /request\.(args|form|values|json|GET|POST|data|query_params)|sys\.argv|input\(/;

const A01 = "A01:2021 Broken Access Control";
const A02 = "A02:2021 Cryptographic Failures";
const A03 = "A03:2021 Injection";
const A04 = "A04:2021 Insecure Design";
const A05 = "A05:2021 Security Misconfiguration";
const A07 = "A07:2021 Identification & Authentication Failures";
const A08 = "A08:2021 Software & Data Integrity Failures";
const A09 = "A09:2021 Security Logging & Monitoring Failures";
const A10 = "A10:2021 Server-Side Request Forgery";

export const LINE_RULES: LineRule[] = [
  // ------------------------------ JavaScript / TypeScript ------------------------------
  {
    id: "js-eval", lang: ["js"], re: /(?<![\w.])eval\s*\(\s*(?!['"`][^'"`]*['"`]\s*\))/,
    severity: "HIGH", title: "eval() dengan argumen dinamis", category: "injection", cwe: "CWE-95", owasp: A03,
    impact: "Kode arbitrer bisa dieksekusi bila argumen dapat dipengaruhi penyerang.",
    fix: "Hapus eval(). Gunakan JSON.parse untuk data, atau peta fungsi yang diizinkan.", confidence: "likely",
    near: JS_USER, escalateTo: "CRITICAL",
  },
  {
    id: "js-new-function", lang: ["js"], re: /\bnew\s+Function\s*\(/,
    severity: "HIGH", title: "new Function() (eval terselubung)", category: "injection", cwe: "CWE-95", owasp: A03,
    impact: "Sama berbahayanya dengan eval: string dieksekusi sebagai kode.",
    fix: "Ganti dengan logika statis; jangan membangun kode dari string.", confidence: "likely",
    near: JS_USER, escalateTo: "CRITICAL",
  },
  {
    id: "js-child-process", lang: ["js"], re: /\b(exec|execSync)\s*\(\s*(`[^`]*\$\{|[^,)]*\+\s*\w)/,
    severity: "HIGH", title: "Perintah shell dibangun dari string dinamis", category: "injection", cwe: "CWE-78", owasp: A03,
    impact: "OS command injection: penyerang bisa menyisipkan `; rm -rf` atau membuka reverse shell.",
    fix: "Pakai execFile/spawn dengan argumen array dan TANPA shell; validasi input dengan allowlist.", confidence: "likely",
    near: JS_USER, escalateTo: "CRITICAL",
  },
  {
    id: "js-spawn-shell", lang: ["js"], re: /\bspawn(Sync)?\s*\([^)]*shell\s*:\s*true/,
    severity: "HIGH", title: "spawn() dengan shell: true", category: "injection", cwe: "CWE-78", owasp: A03,
    impact: "Argumen diinterpretasi shell sehingga rawan command injection.",
    fix: "Hapus `shell: true` dan kirim argumen sebagai array.", confidence: "likely",
  },
  {
    id: "js-dangerously-html", lang: ["js"], re: /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:/,
    severity: "MEDIUM", title: "dangerouslySetInnerHTML tanpa sanitasi terlihat", category: "xss", cwe: "CWE-79", owasp: A03,
    impact: "HTML dari data dinamis dirender apa adanya: XSS tersimpan/terpantul.",
    fix: "Sanitasi dengan DOMPurify (atau render teks biasa). Untuk JSON-LD, escape `<` menjadi \\u003c.", confidence: "pattern-only",
    unless: /DOMPurify|sanitize|JSON\.stringify|jsonLd|ld\+json/i, near: JS_USER, escalateTo: "HIGH",
  },
  {
    id: "js-inner-html", lang: ["js"], re: /\.(innerHTML|outerHTML)\s*=\s*(?!\s*['"`][^'"`$]*['"`]\s*;?\s*$)/,
    severity: "MEDIUM", title: "Penulisan innerHTML/outerHTML dari nilai dinamis", category: "xss", cwe: "CWE-79", owasp: A03,
    impact: "Nilai yang bisa dikontrol pengguna akan diparse sebagai HTML (DOM XSS).",
    fix: "Gunakan textContent, atau sanitasi dengan DOMPurify sebelum menyisipkan HTML.", confidence: "pattern-only",
    unless: /DOMPurify|sanitize|escapeHtml/i, near: /location\.(hash|search|href)|URLSearchParams|postMessage|\.data\b/, escalateTo: "HIGH",
  },
  {
    id: "js-document-write", lang: ["js"], re: /\bdocument\.write(ln)?\s*\(/,
    severity: "LOW", title: "document.write()", category: "xss", cwe: "CWE-79", owasp: A03,
    impact: "Sink XSS klasik dan memblokir rendering.",
    fix: "Bangun DOM dengan createElement/textContent.", confidence: "pattern-only",
    near: /location\.(hash|search|href)|URLSearchParams|postMessage|req\./, escalateTo: "MEDIUM",
  },
  {
    id: "js-sqli", lang: ["js"],
    re: /\.(query|execute|raw|\$queryRawUnsafe|\$executeRawUnsafe|unsafe)\s*\(\s*(`[^`]*\b(SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^`]*\$\{|['"][^'"]*\b(SELECT|INSERT|UPDATE|DELETE|WHERE)\b[^'"]*['"]\s*\+)/i,
    severity: "HIGH", title: "Query SQL dibangun dengan interpolasi string", category: "injection", cwe: "CWE-89", owasp: A03,
    impact: "SQL injection: baca/ubah/hapus seluruh database, bypass login.",
    fix: "Gunakan parameterized query (`$1`, `?`) atau tagged template aman (Prisma $queryRaw``, postgres.js sql``).", confidence: "likely",
    near: JS_USER, escalateTo: "CRITICAL",
  },
  {
    id: "js-prisma-unsafe", lang: ["js"], re: /\$(queryRawUnsafe|executeRawUnsafe)\s*\(/,
    severity: "MEDIUM", title: "Prisma $queryRawUnsafe/$executeRawUnsafe", category: "injection", cwe: "CWE-89", owasp: A03,
    impact: "API 'Unsafe' tidak meng-escape parameter yang digabung ke string.",
    fix: "Gunakan $queryRaw`...` (tagged template) atau Prisma.sql.", confidence: "pattern-only",
    near: JS_USER, escalateTo: "HIGH",
  },
  {
    id: "js-nosql-where", lang: ["js"], re: /\$where\s*:|\.find(One)?\(\s*req\.(body|query)\s*\)/,
    severity: "HIGH", title: "Potensi NoSQL injection", category: "injection", cwe: "CWE-943", owasp: A03,
    impact: "Objek query dari pengguna (mis. {\"$ne\": null}) bisa mem-bypass filter/login.",
    fix: "Validasi tipe (zod/joi), cast ke string, gunakan mongo-sanitize; hindari $where.", confidence: "likely",
  },
  {
    id: "js-open-redirect", lang: ["js"],
    re: /\b(res\.redirect|redirect|NextResponse\.redirect|router\.push|location\.(href|assign|replace))\s*\(?\s*[^)]*(req\.(query|body|params)|searchParams\.get\()/,
    severity: "MEDIUM", title: "Redirect ke URL dari input pengguna", category: "access-control", cwe: "CWE-601", owasp: A01,
    impact: "Open redirect: dipakai untuk phishing dan pencurian token OAuth.",
    fix: "Hanya izinkan path relatif (`/…` tanpa `//`) atau allowlist domain.", confidence: "likely",
    unless: /startsWith\(\s*['"]\/['"]|allowlist|allowedHosts|isSafeRedirect/i,
  },
  {
    id: "js-ssrf", lang: ["js"],
    re: /\b(fetch|axios(\.(get|post|request))?|got|request|needle|superagent\.get|http\.get|https\.get)\s*\(\s*(req\.(query|body|params)|searchParams\.get\(|body\.url|query\.url)/,
    severity: "HIGH", title: "Request keluar ke URL dari input pengguna (SSRF)", category: "ssrf", cwe: "CWE-918", owasp: A10,
    impact: "Penyerang bisa menyuruh server mengakses 169.254.169.254 (metadata cloud), Redis/DB internal, atau localhost.",
    fix: "Validasi URL: hanya http(s), resolusi DNS lalu tolak IP privat/loopback/link-local, allowlist host, matikan redirect.", confidence: "likely",
    unless: /isPrivateIp|validatePublicUrl|validateDomainInput|allowlist|ALLOWED_HOSTS|ssrf/i,
  },
  {
    id: "js-ssrf-var", lang: ["js"],
    re: /\b(fetch|axios(\.(get|post|request))?|got|needle|http\.get|https\.get)\s*\(\s*(url|target|link|endpoint|href)\b/,
    severity: "MEDIUM", title: "Request keluar ke variabel URL yang berasal dari input pengguna", category: "ssrf", cwe: "CWE-918", owasp: A10,
    impact: "Bila variabel URL berasal dari request tanpa validasi, server dapat dipakai menjangkau jaringan internal.",
    fix: "Validasi URL (skema, host allowlist, tolak IP privat setelah resolusi DNS) sebelum fetch.", confidence: "pattern-only",
    near: JS_USER, unless: /isPrivateIp|validatePublicUrl|validateDomainInput|allowlist|ALLOWED_HOSTS|ssrf/i,
  },
  {
    id: "js-path-traversal", lang: ["js"],
    re: /\b(readFile|readFileSync|createReadStream|writeFile|writeFileSync|unlink|sendFile|res\.download|path\.(join|resolve))\s*\([^)]*(req\.(query|params|body)|searchParams\.get\()/,
    severity: "HIGH", title: "Path berkas dari input pengguna (path traversal)", category: "path-traversal", cwe: "CWE-22", owasp: A01,
    impact: "`../../etc/passwd` atau `../.env` dapat dibaca/ditulis.",
    fix: "Normalisasi lalu pastikan path tetap di dalam folder dasar (path.resolve + startsWith), atau gunakan ID → peta berkas.", confidence: "likely",
    unless: /startsWith\(|basename\(/,
  },
  {
    id: "js-tls-off", lang: ["js"], re: /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0/,
    severity: "HIGH", title: "Verifikasi sertifikat TLS dimatikan", category: "crypto", cwe: "CWE-295", owasp: A02,
    impact: "Koneksi rentan man-in-the-middle; kredensial/data bisa disadap.",
    fix: "Hapus rejectUnauthorized:false; untuk CA internal pakai opsi `ca`.", confidence: "verified",
    unless: /getPeerCertificate|tls\.connect\(|checkServerIdentity/, ctxLines: 10,
  },
  {
    id: "js-weak-hash-password", lang: ["js"], re: /createHash\(\s*['"](md5|sha1)['"]\s*\)/i,
    severity: "LOW", title: "Hash lemah (MD5/SHA-1)", category: "crypto", cwe: "CWE-328", owasp: A02,
    impact: "Tidak aman untuk password/tanda tangan; rentan collision & brute force.",
    fix: "Password: bcrypt/argon2/scrypt. Integritas: SHA-256 ke atas.", confidence: "pattern-only",
    unless: /gravatar|etag|cache.?key|checksum/i,
    near: /password|passwd|pwd|secret|token/i, escalateTo: "HIGH",
  },
  {
    id: "js-insecure-random", lang: ["js"], re: /Math\.random\s*\(/,
    severity: "MEDIUM", title: "Math.random() untuk nilai keamanan", category: "crypto", cwe: "CWE-338", owasp: A02,
    impact: "Math.random dapat diprediksi; token/OTP/ID sesi bisa ditebak.",
    fix: "Gunakan crypto.randomUUID() / crypto.getRandomValues() / randomBytes().", confidence: "pattern-only",
    near: /\b\w*(token|secret|otp|password|passwd|sessionid|session_id|nonce|salt|apikey|api_key|resetcode|invitecode)\w*\s*[:=]/i, nearSameLine: true,
  },
  {
    id: "js-jwt-none", lang: ["js"], re: /algorithms?\s*:\s*\[?\s*['"]none['"]|ignoreExpiration\s*:\s*true/i,
    severity: "HIGH", title: "Verifikasi JWT dilemahkan (alg none / ignoreExpiration)", category: "auth", cwe: "CWE-347", owasp: A07,
    impact: "Token palsu atau kedaluwarsa tetap diterima: bypass autentikasi.",
    fix: "Tetapkan `algorithms: ['HS256']` (atau RS256) dan jangan abaikan exp.", confidence: "verified",
  },
  {
    id: "js-jwt-decode-auth", lang: ["js"], re: /\bjwt\.decode\s*\(/,
    severity: "MEDIUM", title: "jwt.decode() (tanpa verifikasi tanda tangan)", category: "auth", cwe: "CWE-345", owasp: A07,
    impact: "decode tidak memverifikasi tanda tangan; bila dipakai untuk otorisasi, token bisa dipalsukan.",
    fix: "Gunakan jwt.verify() / jose.jwtVerify() untuk keputusan otorisasi.", confidence: "pattern-only",
    near: /role|admin|user(Id)?|auth|permission/i, escalateTo: "HIGH",
  },
  {
    id: "js-jwt-hardcoded", lang: ["js"], re: /\bjwt\.sign\s*\([^)]*,\s*['"][^'"]{3,}['"]/,
    severity: "HIGH", title: "Secret JWT ditulis langsung di kode", category: "secret", cwe: "CWE-798", owasp: A07,
    impact: "Siapa pun yang membaca kode/riwayat git bisa membuat token admin.",
    fix: "Ambil dari environment variable dan rotasi secret yang sudah bocor.", confidence: "verified",
  },
  {
    id: "js-cors-wildcard-cred", lang: ["js"], re: /origin\s*:\s*(['"]\*['"]|true)[^}]*credentials\s*:\s*true|credentials\s*:\s*true[^}]*origin\s*:\s*(['"]\*['"]|true)/,
    severity: "MEDIUM", title: "CORS menerima semua origin dengan credentials", category: "config", cwe: "CWE-942", owasp: A05,
    impact: "Situs lain bisa membaca respons ber-cookie milik pengguna.",
    fix: "Gunakan allowlist origin eksplisit bila credentials: true.", confidence: "likely",
  },
  {
    id: "js-acao-wildcard", lang: ["js"], re: /Access-Control-Allow-Origin['"]?\s*[,:]\s*['"]\*['"]/,
    severity: "LOW", title: "Access-Control-Allow-Origin: *", category: "config", cwe: "CWE-942", owasp: A05,
    impact: "Respons API bisa dibaca dari origin mana pun (aman hanya untuk data publik).",
    fix: "Batasi origin bila API memuat data privat.", confidence: "pattern-only", inString: true,
  },
  {
    id: "js-cookie-flags", lang: ["js"], re: /httpOnly\s*:\s*false|secure\s*:\s*false\b/,
    severity: "LOW", title: "Cookie tanpa httpOnly/secure", category: "config", cwe: "CWE-1004", owasp: A05,
    impact: "Cookie bisa dicuri lewat XSS atau dikirim lewat HTTP biasa.",
    fix: "Set httpOnly: true, secure: true (produksi), sameSite: 'lax'/'strict'.", confidence: "pattern-only",
    unless: /NODE_ENV|isProd|isDev|development/,
  },
  {
    id: "js-deserialize", lang: ["js"], re: /require\(\s*['"]node-serialize['"]\s*\)|\bunserialize\s*\(/,
    severity: "CRITICAL", title: "node-serialize / unserialize (RCE)", category: "deserialization", cwe: "CWE-502", owasp: A08,
    impact: "Deserialisasi node-serialize bisa mengeksekusi fungsi yang disisipkan (RCE).",
    fix: "Hapus node-serialize; gunakan JSON.parse + validasi skema.", confidence: "likely",
  },
  {
    id: "js-vm", lang: ["js"], re: /\bvm\.runIn(New|This)?Context\s*\(|require\(\s*['"]vm2['"]\s*\)/,
    severity: "HIGH", title: "Eksekusi kode via vm / vm2", category: "injection", cwe: "CWE-94", owasp: A03,
    impact: "vm bukan sandbox keamanan; vm2 sudah EOL dengan banyak escape RCE.",
    fix: "Jangan jalankan kode pengguna di proses utama; gunakan isolasi proses/kontainer (isolated-vm, worker terpisah).", confidence: "likely",
  },
  {
    id: "js-regex-user", lang: ["js"], re: /new\s+RegExp\s*\(\s*(req\.|searchParams\.get|query\.|body\.)/,
    severity: "MEDIUM", title: "RegExp dari input pengguna (ReDoS)", category: "injection", cwe: "CWE-1333", owasp: A03,
    impact: "Pola jahat bisa membuat CPU 100% (denial of service).",
    fix: "Escape input (lodash.escapeRegExp) atau gunakan pencarian string biasa.", confidence: "likely",
  },
  {
    id: "js-merge-user", lang: ["js"], re: /\b(_\.merge|merge|defaultsDeep|Object\.assign)\s*\([^)]*req\.(body|query)/,
    severity: "MEDIUM", title: "Deep merge objek dari input pengguna", category: "injection", cwe: "CWE-1321", owasp: A03,
    impact: "Prototype pollution via `__proto__` dapat mengubah perilaku seluruh aplikasi.",
    fix: "Validasi skema dan buang key __proto__/constructor/prototype sebelum merge.", confidence: "pattern-only",
  },
  {
    id: "js-log-secret", lang: ["js"], re: /console\.(log|info|debug)\s*\([^)]*\b(password|passwd|secret|token|apiKey|api_key|authorization)\b/i,
    severity: "LOW", title: "Data sensitif ditulis ke log", category: "config", cwe: "CWE-532", owasp: A09,
    impact: "Password/token tersimpan di log platform dan bisa dibaca pihak yang tidak berhak.",
    fix: "Jangan log nilai sensitif; redaksi sebelum logging.", confidence: "pattern-only",
  },
  {
    id: "js-public-env-secret", lang: ["js", "env"], re: /\bNEXT_PUBLIC_[A-Z0-9_]*(SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|PASSWD|ADMIN_KEY|ENCRYPTION_KEY)[A-Z0-9_]*/,
    severity: "HIGH", title: "Rahasia diberi prefiks NEXT_PUBLIC_ (terkirim ke browser)", category: "secret", cwe: "CWE-200", owasp: A02,
    impact: "Semua variabel NEXT_PUBLIC_ di-inline ke bundle JavaScript dan bisa dibaca siapa pun.",
    fix: "Ganti nama tanpa NEXT_PUBLIC_ dan akses hanya dari kode server; rotasi nilainya.", confidence: "likely",
  },
  {
    id: "js-source-maps", lang: ["js"], re: /productionBrowserSourceMaps\s*:\s*true/,
    severity: "LOW", title: "Source map produksi diaktifkan", category: "config", cwe: "CWE-540", owasp: A05,
    impact: "Kode sumber asli (termasuk komentar & logika internal) bisa direkonstruksi pengunjung.",
    fix: "Set productionBrowserSourceMaps: false atau upload source map hanya ke Sentry.", confidence: "verified",
  },
  {
    id: "js-images-wildcard", lang: ["js"], re: /hostname\s*:\s*['"]\*\*['"]/,
    severity: "MEDIUM", title: "next/image remotePatterns hostname \"**\"", category: "ssrf", cwe: "CWE-918", owasp: A10,
    impact: "Optimizer gambar bisa dipakai sebagai proxy ke host mana pun (penyalahgunaan bandwidth/SSRF terbatas).",
    fix: "Daftarkan host gambar secara eksplisit.", confidence: "verified",
  },

  // ------------------------------------- PHP -------------------------------------
  {
    id: "php-exec", lang: ["php"], re: /\b(system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(\s*[^)]*\$/,
    severity: "HIGH", title: "Eksekusi perintah OS dengan variabel", category: "injection", cwe: "CWE-78", owasp: A03,
    impact: "Command injection → RCE (php2shell).",
    fix: "Hindari fungsi shell; bila wajib, escapeshellarg() setiap argumen + allowlist.", confidence: "likely",
    near: PHP_USER, escalateTo: "CRITICAL", unless: /escapeshellarg/,
  },
  {
    id: "php-eval", lang: ["php"], re: /\b(eval|assert|create_function)\s*\(|preg_replace\s*\(\s*['"][^'"]*\/e['"]/,
    severity: "HIGH", title: "eval/assert/create_function/preg_replace /e", category: "injection", cwe: "CWE-95", owasp: A03,
    impact: "Eksekusi kode PHP arbitrer (pola umum webshell).",
    fix: "Hapus eval; gunakan logika statis.", confidence: "likely", near: PHP_USER, escalateTo: "CRITICAL",
  },
  {
    id: "php-include", lang: ["php"], re: /\b(include|require)(_once)?\s*\(?\s*[^;]*\$_(GET|POST|REQUEST|COOKIE)/,
    severity: "CRITICAL", title: "include/require dari input pengguna (LFI/RFI)", category: "path-traversal", cwe: "CWE-98", owasp: A03,
    impact: "Penyerang bisa memuat berkas lokal (log, /etc/passwd) atau remote → RCE.",
    fix: "Gunakan peta nama halaman → berkas tetap (allowlist).", confidence: "verified",
  },
  {
    id: "php-sqli", lang: ["php"], re: /(mysqli?_query|->query|->exec|pg_query)\s*\([^;]*(\$_(GET|POST|REQUEST|COOKIE)|["'][^"']*\b(SELECT|INSERT|UPDATE|DELETE)\b[^"']*\$\w)/i,
    severity: "HIGH", title: "Query SQL dengan variabel langsung", category: "injection", cwe: "CWE-89", owasp: A03,
    impact: "SQL injection: dump database, bypass login.",
    fix: "Gunakan prepared statement (PDO::prepare / mysqli_prepare) dengan bind parameter.", confidence: "likely",
    near: PHP_USER, escalateTo: "CRITICAL",
  },
  {
    id: "php-unserialize", lang: ["php"], re: /\bunserialize\s*\(\s*[^)]*\$_(GET|POST|REQUEST|COOKIE)/,
    severity: "CRITICAL", title: "unserialize() dari input pengguna", category: "deserialization", cwe: "CWE-502", owasp: A08,
    impact: "PHP object injection → RCE lewat gadget chain.",
    fix: "Gunakan json_decode; bila terpaksa, unserialize($x, ['allowed_classes' => false]).", confidence: "verified",
  },
  {
    id: "php-echo-xss", lang: ["php"], re: /\b(echo|print)\s+[^;]*\$_(GET|POST|REQUEST|COOKIE)/,
    severity: "MEDIUM", title: "Output input pengguna tanpa escape (XSS)", category: "xss", cwe: "CWE-79", owasp: A03,
    impact: "Reflected XSS: pencurian sesi, defacement.",
    fix: "Bungkus dengan htmlspecialchars($v, ENT_QUOTES, 'UTF-8').", confidence: "likely", unless: /htmlspecialchars|htmlentities|esc_html|\be\(/,
  },
  {
    id: "php-extract", lang: ["php"], re: /\bextract\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/,
    severity: "HIGH", title: "extract() dari input pengguna", category: "injection", cwe: "CWE-621", owasp: A03,
    impact: "Penyerang bisa menimpa variabel apa pun (mis. $is_admin).",
    fix: "Ambil field yang dibutuhkan secara eksplisit.", confidence: "verified",
  },
  {
    id: "php-ssrf", lang: ["php"], re: /\b(file_get_contents|fopen|curl_init|readfile)\s*\(\s*[^)]*\$_(GET|POST|REQUEST)/,
    severity: "HIGH", title: "Akses URL/berkas dari input pengguna (SSRF/LFI)", category: "ssrf", cwe: "CWE-918", owasp: A10,
    impact: "Baca berkas lokal atau akses layanan internal.",
    fix: "Allowlist host/berkas; tolak skema file://, php://, gopher://.", confidence: "likely",
  },
  {
    id: "php-weak-pass", lang: ["php"], re: /\b(md5|sha1)\s*\(\s*\$\w*(pass|pwd)/i,
    severity: "HIGH", title: "Password di-hash dengan MD5/SHA-1", category: "crypto", cwe: "CWE-916", owasp: A02,
    impact: "Hash bisa dipecahkan dalam hitungan detik (rainbow table/GPU).",
    fix: "Gunakan password_hash() dan password_verify().", confidence: "verified",
  },
  {
    id: "php-upload", lang: ["php"], re: /\bmove_uploaded_file\s*\(/,
    severity: "MEDIUM", title: "Upload berkas: pastikan validasi ekstensi & lokasi", category: "access-control", cwe: "CWE-434", owasp: A04,
    impact: "Upload .php/.phtml ke folder publik = webshell.",
    fix: "Validasi MIME + ekstensi via allowlist, ganti nama acak, simpan di luar web root, matikan eksekusi PHP di folder upload.", confidence: "pattern-only",
    unless: /pathinfo\([^)]*PATHINFO_EXTENSION|in_array\([^)]*(jpg|png|pdf)/i,
  },

  // ------------------------------------ Python ------------------------------------
  {
    id: "py-eval", lang: ["py"], re: /(?<![\w.])(eval|exec)\s*\(\s*(?!['"])/,
    severity: "HIGH", title: "eval()/exec() dengan argumen dinamis", category: "injection", cwe: "CWE-95", owasp: A03,
    impact: "Eksekusi kode Python arbitrer.", fix: "Gunakan ast.literal_eval atau parser khusus.", confidence: "likely",
    near: PY_USER, escalateTo: "CRITICAL",
  },
  {
    id: "py-shell", lang: ["py"], re: /subprocess\.\w+\([^)]*shell\s*=\s*True|\bos\.(system|popen)\s*\(/,
    severity: "HIGH", title: "Perintah shell (shell=True / os.system)", category: "injection", cwe: "CWE-78", owasp: A03,
    impact: "Command injection bila string memuat input pengguna.",
    fix: "subprocess.run([...], shell=False) dengan argumen list.", confidence: "likely", near: PY_USER, escalateTo: "CRITICAL",
  },
  {
    id: "py-deserialize", lang: ["py"], re: /\b(pickle|cPickle|dill|marshal)\.loads?\s*\(|yaml\.load\s*\((?![^)]*Loader\s*=\s*(yaml\.)?(Safe|CSafe)Loader)/,
    severity: "HIGH", title: "Deserialisasi tidak aman (pickle / yaml.load)", category: "deserialization", cwe: "CWE-502", owasp: A08,
    impact: "Payload pickle/YAML jahat mengeksekusi kode saat dimuat.",
    fix: "Gunakan json atau yaml.safe_load; jangan unpickle data tak tepercaya.", confidence: "likely",
  },
  {
    id: "py-sqli", lang: ["py"], re: /\.(execute|executemany|raw)\s*\(\s*(f['"]|['"][^'"]*['"]\s*(%|\+|\.format))/,
    severity: "HIGH", title: "Query SQL dengan f-string/format", category: "injection", cwe: "CWE-89", owasp: A03,
    impact: "SQL injection.", fix: "cursor.execute(\"... WHERE id = %s\", (id,)) / ORM parameter.", confidence: "likely",
    near: PY_USER, escalateTo: "CRITICAL",
  },
  {
    id: "py-verify-false", lang: ["py"], re: /verify\s*=\s*False|ssl\._create_unverified_context|CERT_NONE/,
    severity: "MEDIUM", title: "Verifikasi TLS dimatikan", category: "crypto", cwe: "CWE-295", owasp: A02,
    impact: "Rentan man-in-the-middle.", fix: "Hapus verify=False; gunakan bundle CA yang benar.", confidence: "verified",
  },
  {
    id: "py-debug", lang: ["py"], re: /\.run\([^)]*debug\s*=\s*True|^\s*DEBUG\s*=\s*True/,
    severity: "MEDIUM", title: "Mode debug aktif", category: "config", cwe: "CWE-489", owasp: A05,
    impact: "Debugger Werkzeug memberi konsol Python (RCE); Django membocorkan setting & stack trace.",
    fix: "Ambil dari env dan pastikan False di produksi.", confidence: "likely", unless: /environ|getenv|config\(/,
  },
  {
    id: "py-jwt-noverify", lang: ["py"], re: /verify_signature['"]?\s*:\s*False|jwt\.decode\([^)]*verify\s*=\s*False/,
    severity: "HIGH", title: "JWT didekode tanpa verifikasi tanda tangan", category: "auth", cwe: "CWE-347", owasp: A07,
    impact: "Token palsu diterima.", fix: "Selalu verifikasi dengan algorithms=['HS256'] dan kunci yang benar.", confidence: "verified",
  },
  {
    id: "py-allowed-hosts", lang: ["py"], re: /ALLOWED_HOSTS\s*=\s*\[\s*['"]\*['"]\s*\]/,
    severity: "LOW", title: "Django ALLOWED_HOSTS = ['*']", category: "config", cwe: "CWE-16", owasp: A05,
    impact: "Rentan host header poisoning (reset password, cache).", fix: "Daftarkan domain produksi secara eksplisit.", confidence: "verified",
  },

  // -------------------------------------- Go --------------------------------------
  {
    id: "go-exec", lang: ["go"], re: /exec\.Command\(\s*"(sh|bash|cmd|powershell)"[^)]*(\+|Sprintf)/,
    severity: "HIGH", title: "exec.Command lewat shell dengan string dinamis", category: "injection", cwe: "CWE-78", owasp: A03,
    impact: "Command injection.", fix: "Panggil biner langsung dengan argumen terpisah, tanpa sh -c.", confidence: "likely",
  },
  {
    id: "go-sqli", lang: ["go"], re: /\.(Query|QueryRow|Exec)(Context)?\(\s*(ctx,\s*)?(fmt\.Sprintf|"[^"]*"\s*\+)/,
    severity: "HIGH", title: "Query SQL dengan Sprintf/konkatenasi", category: "injection", cwe: "CWE-89", owasp: A03,
    impact: "SQL injection.", fix: "Gunakan placeholder ($1 / ?) dan argumen terpisah.", confidence: "likely",
  },
  {
    id: "go-tls-skip", lang: ["go"], re: /InsecureSkipVerify\s*:\s*true/,
    severity: "HIGH", title: "InsecureSkipVerify: true", category: "crypto", cwe: "CWE-295", owasp: A02,
    impact: "Verifikasi sertifikat dimatikan (MITM).", fix: "Hapus; gunakan RootCAs untuk CA internal.", confidence: "verified",
  },

  // ---------------------------- Java / Kotlin / Android ----------------------------
  {
    id: "java-exec", lang: ["java"], re: /Runtime\.getRuntime\(\)\.exec\(|ProcessBuilder\([^)]*\+/,
    severity: "HIGH", title: "Eksekusi proses OS", category: "injection", cwe: "CWE-78", owasp: A03,
    impact: "Command injection bila argumen memuat input.", fix: "Argumen array + allowlist; hindari shell.", confidence: "pattern-only",
  },
  {
    id: "java-sqli", lang: ["java"], re: /(executeQuery|executeUpdate|execute|rawQuery|execSQL)\(\s*"[^"]*\b(SELECT|INSERT|UPDATE|DELETE)\b[^"]*"\s*\+/i,
    severity: "HIGH", title: "Query SQL dengan konkatenasi string", category: "injection", cwe: "CWE-89", owasp: A03,
    impact: "SQL injection (termasuk SQLite di Android).", fix: "PreparedStatement / selectionArgs.", confidence: "likely",
  },
  {
    id: "java-trust-all", lang: ["java"], re: /checkServerTrusted\([^)]*\)\s*(\{\s*\}|=\s*Unit|\{\s*\/\/)|HostnameVerifier\s*\{[^}]*true|ALLOW_ALL_HOSTNAME_VERIFIER|hostnameVerifier\s*\{\s*_,\s*_\s*->\s*true/,
    severity: "HIGH", title: "TrustManager/HostnameVerifier menerima semua sertifikat", category: "crypto", cwe: "CWE-295", owasp: A02,
    impact: "Lalu lintas HTTPS aplikasi bisa disadap (MITM).", fix: "Gunakan TrustManager default; certificate pinning bila perlu.", confidence: "likely",
  },
  {
    id: "java-ecb", lang: ["java", "cs"], re: /AES\/ECB|Cipher\.getInstance\(\s*"(AES|DES|DESede)"\s*\)|\bDES(ede)?\b.*(Cipher|Create)/,
    severity: "MEDIUM", title: "Mode/cipher enkripsi lemah (ECB/DES)", category: "crypto", cwe: "CWE-327", owasp: A02,
    impact: "Pola data bocor (ECB) atau kunci mudah dipecahkan (DES).", fix: "Gunakan AES-GCM dengan IV acak per pesan.", confidence: "likely",
  },
  {
    id: "java-webview-js", lang: ["java"], re: /addJavascriptInterface\s*\(/,
    severity: "MEDIUM", title: "WebView addJavascriptInterface", category: "injection", cwe: "CWE-749", owasp: A03,
    impact: "Halaman web yang dimuat bisa memanggil method native aplikasi.", fix: "Hanya muat konten tepercaya; anotasi @JavascriptInterface seminimal mungkin.", confidence: "pattern-only",
  },
  {
    id: "android-debuggable", lang: ["android"], re: /android:debuggable\s*=\s*"true"/,
    severity: "HIGH", title: "android:debuggable=\"true\"", category: "config", cwe: "CWE-489", owasp: A05,
    impact: "Siapa pun dengan ADB bisa men-debug dan membaca data aplikasi.", fix: "Hapus atribut (Gradle mengaturnya per build type).", confidence: "verified",
  },
  {
    id: "android-cleartext", lang: ["android"], re: /android:usesCleartextTraffic\s*=\s*"true"/,
    severity: "MEDIUM", title: "Cleartext HTTP diizinkan", category: "crypto", cwe: "CWE-319", owasp: A02,
    impact: "Data dikirim tanpa enkripsi.", fix: "Set false dan gunakan HTTPS; atur pengecualian lewat network_security_config.", confidence: "verified",
  },
  {
    id: "android-backup", lang: ["android"], re: /android:allowBackup\s*=\s*"true"/,
    severity: "LOW", title: "android:allowBackup=\"true\"", category: "config", cwe: "CWE-530", owasp: A05,
    impact: "Data aplikasi bisa diekstrak lewat adb backup.", fix: "Set false atau batasi dengan dataExtractionRules.", confidence: "verified",
  },

  // -------------------------------------- C# --------------------------------------
  {
    id: "cs-sqli", lang: ["cs"], re: /new\s+(Sql|SqlCe|Npgsql|MySql|Sqlite)Command\(\s*(\$"|"[^"]*"\s*\+)/,
    severity: "HIGH", title: "SqlCommand dengan string dinamis", category: "injection", cwe: "CWE-89", owasp: A03,
    impact: "SQL injection.", fix: "Gunakan Parameters.AddWithValue / Dapper parameter.", confidence: "likely",
  },
  {
    id: "cs-binaryformatter", lang: ["cs"], re: /\bBinaryFormatter\b|\bNetDataContractSerializer\b|TypeNameHandling\s*=\s*TypeNameHandling\.(All|Auto|Objects)/,
    severity: "HIGH", title: "Deserialisasi tidak aman (.NET)", category: "deserialization", cwe: "CWE-502", owasp: A08,
    impact: "RCE lewat gadget chain (ysoserial.net).", fix: "Gunakan System.Text.Json tanpa type name handling.", confidence: "likely",
  },
  {
    id: "cs-tls-off", lang: ["cs"], re: /ServerCertificate(CustomValidation|Validation)Callback\s*=\s*[^;]*=>\s*true/,
    severity: "HIGH", title: "Validasi sertifikat TLS dimatikan", category: "crypto", cwe: "CWE-295", owasp: A02,
    impact: "MITM.", fix: "Hapus callback yang selalu true.", confidence: "verified",
  },
  {
    id: "cs-process", lang: ["cs"], re: /Process\.Start\(\s*[^)]*(\+|\$")/,
    severity: "MEDIUM", title: "Process.Start dengan string dinamis", category: "injection", cwe: "CWE-78", owasp: A03,
    impact: "Command injection bila memuat input.", fix: "ProcessStartInfo.ArgumentList + UseShellExecute=false.", confidence: "pattern-only",
  },

  // ------------------------------------ Ruby ------------------------------------
  {
    id: "rb-exec", lang: ["rb"], re: /\b(system|exec|spawn|`[^`]*#\{|%x\()/,
    severity: "MEDIUM", title: "Eksekusi shell di Ruby", category: "injection", cwe: "CWE-78", owasp: A03,
    impact: "Command injection bila memuat params.", fix: "system('cmd', arg1, arg2) bentuk array.", confidence: "pattern-only",
    near: /params\[/, escalateTo: "HIGH",
  },

  // ----------------------------------- Dockerfile -----------------------------------
  {
    id: "docker-latest", lang: ["docker"], re: /^\s*FROM\s+(?!scratch)[^\s:@]+(:latest)?(\s+AS\s+\w+)?\s*$/i,
    severity: "LOW", title: "Base image tanpa tag versi / :latest", category: "container", cwe: "CWE-1357", owasp: A08,
    impact: "Build tidak reproducible; image bisa berubah diam-diam.", fix: "Pin versi (node:20.11-alpine) atau digest @sha256.", confidence: "verified",
  },
  {
    id: "docker-curl-sh", lang: ["docker", "gha", "any"], re: /(curl|wget)\s[^|]*\|\s*(sudo\s+)?(ba)?sh\b/,
    severity: "MEDIUM", title: "Mengunduh lalu langsung menjalankan skrip (curl | sh)", category: "supply-chain", cwe: "CWE-494", owasp: A08,
    impact: "Bila sumber disusupi, kode penyerang langsung dieksekusi di build.", fix: "Unduh, verifikasi checksum/tanda tangan, baru jalankan.", confidence: "verified",
  },
  {
    id: "docker-env-secret", lang: ["docker"], re: /^\s*(ENV|ARG)\s+\w*(PASSWORD|PASSWD|SECRET|TOKEN|API_KEY|PRIVATE_KEY)\w*\s*=?\s*\S{4,}/i,
    severity: "HIGH", title: "Rahasia ditanam di image (ENV/ARG)", category: "secret", cwe: "CWE-798", owasp: A05,
    impact: "Nilai ENV/ARG tersimpan di layer image dan terlihat lewat `docker history`.", fix: "Gunakan secret runtime atau BuildKit `--mount=type=secret`.", confidence: "likely",
    unless: /\$\{?\w+\}?\s*$/,
  },
  {
    id: "docker-add-url", lang: ["docker"], re: /^\s*ADD\s+https?:\/\//i,
    severity: "LOW", title: "ADD dari URL", category: "supply-chain", cwe: "CWE-494", owasp: A08,
    impact: "Berkas remote tanpa verifikasi integritas.", fix: "Gunakan RUN curl + verifikasi checksum, atau COPY berkas lokal.", confidence: "verified",
  },

  // --------------------------------- GitHub Actions ---------------------------------
  {
    id: "gha-script-injection", lang: ["gha"],
    re: /\$\{\{\s*github\.event\.(issue|pull_request|comment|review|review_comment|head_commit|commits|pages|discussion)[\w.\[\]*]*\.(title|body|message|name|label|ref|head_ref|email|login)\s*\}\}/,
    severity: "HIGH", title: "Script injection lewat ekspresi github.event", category: "ci-cd", cwe: "CWE-94", owasp: A08,
    impact: "Judul/isi PR atau issue buatan penyerang dieksekusi sebagai shell di runner (bisa mencuri secrets).",
    fix: "Pindahkan ke env: `env: TITLE: ${{ github.event.pull_request.title }}` lalu pakai \"$TITLE\".", confidence: "likely",
  },
  {
    id: "gha-unpinned", lang: ["gha"], re: /uses:\s*(?!actions\/|github\/|\.\/|docker:\/\/)[\w.-]+\/[\w./-]+@(main|master|dev|latest|v?\d+(\.\d+)?)\s*$/,
    severity: "LOW", title: "Action pihak ketiga tidak di-pin ke commit SHA", category: "supply-chain", cwe: "CWE-829", owasp: A08,
    impact: "Tag/branch bisa digeser ke kode berbahaya (kasus tj-actions/changed-files 2025).", fix: "Pin ke SHA lengkap: `uses: owner/action@<40-char-sha> # v1.2.3`.", confidence: "verified",
  },
  {
    id: "gha-write-all", lang: ["gha"], re: /permissions:\s*write-all/,
    severity: "MEDIUM", title: "permissions: write-all", category: "ci-cd", cwe: "CWE-250", owasp: A01,
    impact: "Token GITHUB_TOKEN bisa push kode, membuat release, dll bila job disusupi.", fix: "Berikan izin minimum per job (contents: read).", confidence: "verified",
  },
  {
    id: "gha-echo-secret", lang: ["gha"], re: /run:.*echo\s+[^\n]*\$\{\{\s*secrets\./,
    severity: "MEDIUM", title: "Secret di-echo di workflow", category: "ci-cd", cwe: "CWE-532", owasp: A09,
    impact: "Masking bisa gagal pada transformasi nilai sehingga secret muncul di log.", fix: "Jangan echo secrets; kirim lewat env ke tool yang membutuhkannya.", confidence: "likely",
  },

  // ----------------------------- Compose / K8s / Terraform / nginx -----------------------------
  {
    id: "compose-privileged", lang: ["compose", "k8s"], re: /privileged\s*:\s*true|hostNetwork\s*:\s*true|allowPrivilegeEscalation\s*:\s*true/,
    severity: "HIGH", title: "Kontainer privileged / hostNetwork", category: "container", cwe: "CWE-250", owasp: A05,
    impact: "Kompromi kontainer = kompromi host.", fix: "Hapus privileged/hostNetwork; tambahkan capability yang benar-benar perlu saja.", confidence: "verified",
  },
  {
    id: "compose-default-db-pass", lang: ["compose", "env"], re: /(POSTGRES_PASSWORD|MYSQL_ROOT_PASSWORD|MYSQL_PASSWORD|MONGO_INITDB_ROOT_PASSWORD|REDIS_PASSWORD)\s*[:=]\s*['"]?(postgres|root|password|admin|123456|secret|example|changeme)?['"]?\s*$/i,
    severity: "MEDIUM", title: "Password database default/kosong", category: "auth", cwe: "CWE-521", owasp: A07,
    impact: "Database mudah diambil alih bila port terekspos.", fix: "Gunakan password kuat dari secret manager.", confidence: "likely",
  },
  {
    id: "compose-exposed-db", lang: ["compose"], re: /["']?(0\.0\.0\.0:)?(5432|3306|6379|27017|9200|11211):(5432|3306|6379|27017|9200|11211)["']?/,
    severity: "MEDIUM", title: "Port database dipublikasikan ke host", category: "config", cwe: "CWE-668", owasp: A05,
    impact: "Database/Redis bisa diakses dari internet bila host publik (umum dibobol bot).", fix: "Hapus mapping port atau bind ke 127.0.0.1.", confidence: "pattern-only",
    unless: /127\.0\.0\.1:/,
  },
  {
    id: "k8s-root", lang: ["k8s"], re: /runAsUser\s*:\s*0\b|runAsNonRoot\s*:\s*false/,
    severity: "MEDIUM", title: "Pod berjalan sebagai root", category: "container", cwe: "CWE-250", owasp: A05,
    impact: "Memperbesar dampak kompromi kontainer.", fix: "runAsNonRoot: true, runAsUser: 10001.", confidence: "verified",
  },
  {
    id: "tf-open-ssh", lang: ["tf"], re: /cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0\/0"\s*\]/,
    severity: "MEDIUM", title: "Security group terbuka ke 0.0.0.0/0", category: "config", cwe: "CWE-284", owasp: A01,
    impact: "Port (SSH/RDP/DB) bisa diakses seluruh internet.", fix: "Batasi ke IP kantor/VPN atau gunakan SSM/bastion.", confidence: "pattern-only",
    near: /from_port\s*=\s*(22|3389|3306|5432|6379|27017)/, escalateTo: "HIGH",
  },
  {
    id: "tf-public-bucket", lang: ["tf"], re: /acl\s*=\s*"public-read(-write)?"|block_public_acls\s*=\s*false/,
    severity: "HIGH", title: "Bucket storage publik", category: "access-control", cwe: "CWE-284", owasp: A01,
    impact: "Isi bucket bisa dibaca/ditulis siapa pun.", fix: "acl private + S3 Block Public Access aktif.", confidence: "verified",
  },
  {
    id: "nginx-autoindex", lang: ["nginx"], re: /^\s*autoindex\s+on\s*;/,
    severity: "MEDIUM", title: "nginx autoindex on (directory listing)", category: "config", cwe: "CWE-548", owasp: A05,
    impact: "Isi folder (backup, .env, upload) bisa dijelajahi.", fix: "autoindex off;", confidence: "verified",
  },
  {
    id: "nginx-tokens", lang: ["nginx"], re: /^\s*server_tokens\s+on\s*;/,
    severity: "LOW", title: "server_tokens on", category: "config", cwe: "CWE-200", owasp: A05,
    impact: "Versi nginx diumumkan ke publik.", fix: "server_tokens off;", confidence: "verified",
  },

  // ------------------------------ Firebase / Supabase ------------------------------
  {
    id: "rules-open", lang: ["rules"], re: /allow\s+(read|write|read\s*,\s*write)\s*(:\s*if\s+true)?\s*;|["']\.(read|write)["']\s*:\s*(true|["']true["'])/,
    severity: "CRITICAL", title: "Security Rules Firebase terbuka untuk semua", category: "access-control", cwe: "CWE-284", owasp: A01,
    impact: "Seluruh database/storage bisa dibaca dan ditimpa siapa pun tanpa login.",
    fix: "Wajibkan auth dan cek kepemilikan: `allow read, write: if request.auth != null && request.auth.uid == userId;`", confidence: "likely",
    unless: /request\.auth|auth\s*!=\s*null|auth\.uid/,
  },
  {
    id: "sql-grant-anon", lang: ["sql"], re: /grant\s+(all|insert|update|delete)[^;]*\bto\s+(anon|public)\b/i,
    severity: "HIGH", title: "GRANT tulis ke role anon/public", category: "access-control", cwe: "CWE-284", owasp: A01,
    impact: "Pengguna tanpa login bisa mengubah data (Supabase/PostgREST).", fix: "Cabut grant dan andalkan RLS policy yang ketat.", confidence: "likely",
  },
  {
    id: "sql-policy-true", lang: ["sql"], re: /create\s+policy[^;]*using\s*\(\s*true\s*\)/i,
    severity: "MEDIUM", title: "RLS policy USING (true)", category: "access-control", cwe: "CWE-284", owasp: A01,
    impact: "Policy mengizinkan semua baris untuk role terkait.", fix: "Batasi dengan auth.uid() = user_id.", confidence: "likely",
  },
];

// ------------------------------------- Secrets -------------------------------------
export interface SecretRule {
  id: string;
  title: string;
  re: RegExp;
  severity: Severity;
  group?: number;
}

export const SECRET_RULES: SecretRule[] = [
  { id: "private-key", title: "Private key (PEM/OpenSSH)", re: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----/, severity: "CRITICAL" },
  { id: "aws-key", title: "AWS Access Key ID", re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/, severity: "HIGH" },
  { id: "aws-secret", title: "AWS Secret Access Key", re: /aws_?secret_?(access_?)?key['"]?\s*[:=]\s*['"]?([A-Za-z0-9/+=]{40})\b/i, severity: "CRITICAL", group: 2 },
  { id: "github-token", title: "GitHub token", re: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/, severity: "HIGH" },
  { id: "gitlab-token", title: "GitLab token", re: /\bglpat-[A-Za-z0-9_-]{20,}\b/, severity: "HIGH" },
  { id: "slack-token", title: "Slack token", re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, severity: "HIGH" },
  { id: "slack-webhook", title: "Slack webhook", re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]+/, severity: "MEDIUM" },
  { id: "discord-webhook", title: "Discord webhook", re: /https:\/\/(ptb\.|canary\.)?discord(app)?\.com\/api\/webhooks\/\d+\/[\w-]{20,}/, severity: "MEDIUM" },
  { id: "stripe-live", title: "Stripe live secret key", re: /\b(sk|rk)_live_[0-9a-zA-Z]{20,}\b/, severity: "CRITICAL" },
  { id: "openai-key", title: "OpenAI API key", re: /\bsk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}\b|\bsk-proj-[A-Za-z0-9_-]{40,}\b/, severity: "HIGH" },
  { id: "anthropic-key", title: "Anthropic API key", re: /\bsk-ant-(api|admin)\d{2}-[A-Za-z0-9_-]{40,}\b/, severity: "HIGH" },
  { id: "groq-key", title: "Groq API key", re: /\bgsk_[A-Za-z0-9]{40,}\b/, severity: "HIGH" },
  { id: "google-api-key", title: "Google API key", re: /\bAIza[0-9A-Za-z_-]{35}\b/, severity: "MEDIUM" },
  { id: "sendgrid", title: "SendGrid API key", re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/, severity: "HIGH" },
  { id: "twilio", title: "Twilio API key", re: /\bSK[0-9a-f]{32}\b/, severity: "MEDIUM" },
  { id: "telegram-bot", title: "Telegram bot token", re: /\b\d{8,10}:AA[0-9A-Za-z_-]{33}\b/, severity: "HIGH" },
  { id: "npm-token", title: "npm token", re: /\bnpm_[A-Za-z0-9]{36}\b|_authToken\s*=\s*(?!\$\{)[A-Za-z0-9-_.]{20,}/, severity: "HIGH" },
  { id: "db-url", title: "URL database dengan password", re: /\b(postgres(ql)?|mysql|mariadb|mongodb(\+srv)?|redis|rediss|amqps?):\/\/[^:\s'"@/]+:([^@\s'"]{4,})@[^\s'"]+/i, severity: "HIGH", group: 4 },
  { id: "generic-secret", title: "Nilai rahasia ditulis langsung", re: /\b(password|passwd|pwd|secret|secret_?key|app_?key|client_secret|api_?key|access_?token|auth_?token|private_?key|encryption_?key|jwt_?secret|cookie_?secret|session_?secret)\b['"]?\s*[:=]\s*['"]([^'"\s]{10,})['"]/i, severity: "MEDIUM", group: 2 },
];

/** Placeholder/contoh yang bukan secret nyata. */
export const PLACEHOLDER = /(example|sample|dummy|placeholder|changeme|change_me|your[_-]|xxx+|\*\*\*|<[^>]+>|\$\{|process\.env|os\.environ|getenv|env\(|import\.meta\.env|test|fake|lorem|password123|redacted|todo)/i;

export function redact(value: string): string {
  if (value.length <= 10) return value.slice(0, 2) + "…" + "*".repeat(4);
  return value.slice(0, 4) + "…" + "*".repeat(6) + value.slice(-4);
}

export function shannonEntropy(s: string): number {
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}
