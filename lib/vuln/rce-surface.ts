/**
 * Permukaan RCE, Shell-Escalation (wp2shell, php2shell, node2shell, go2shell, py2shell)
 * & Node Out-of-Bounds / Memory Surface PASIF:
 * Endpoint diagnostik/debug/runtime yang membuka jalur eksekusi kode atau kebocoran memori bila terekspos.
 * 100% GET-only, tanpa payload eksploitasi. Temuan hanya dibuat jika ISI respons cocok dengan penanda spesifik (true-positive validated).
 */
import type { Finding, FindingCategory, Severity } from "@/lib/types";
import { chromeHeaders, detectCloudflareChallenge } from "@/lib/crawler";
import type { RequestBudget } from "@/lib/rate-limit";
import type { RceSurfaceEvidence } from "@/lib/sentinel/dossier";

export type ShellVector =
  | "wp2shell"
  | "php2shell"
  | "node2shell"
  | "go2shell"
  | "py2shell"
  | "node-oob"
  | "rce-surface";

export interface Spec {
  path: string;
  vector: ShellVector;
  title: string;
  cwe: string[];
  cve?: string[];
  rce: boolean;
  /** return severity bila cocok, null jika bukan true positive */
  validate: (body: string, ct: string, status?: number) => Severity | null;
  marker: string;
  impact: string;
  fix: string;
}

const html = (ct: string) => ct.includes("html");
const json = (ct: string, b: string) => ct.includes("json") || /^\s*[{[]/.test(b);
const notHtml = (ct: string, b: string) =>
  !ct.includes("html") && !/<(!doctype|html|head|body)\b/i.test(b.slice(0, 600));

export const RCE_SPECS: Spec[] = [
  // ==================== 1. wp2shell (WordPress Shell-Escalation & Debug Surface) ====================
  {
    path: "/wp-content/debug.log",
    vector: "wp2shell",
    title: "[wp2shell] WordPress debug.log terbuka di publik",
    cwe: ["CWE-532", "CWE-209"],
    rce: false,
    marker: "PHP Notice/Warning/Fatal in /wp-",
    validate: (b, ct) =>
      notHtml(ct, b) &&
      /\[\d{2}-[A-Za-z]{3}-\d{4}\s+\d{2}:\d{2}:\d{2}\s+UTC\]\s+PHP\s+(?:Notice|Warning|Fatal error|Deprecated|Parse error)/i.test(b)
        ? "HIGH"
        : null,
    impact:
      "Log debug WordPress membocorkan path absolut server, query database, nonce/token, dan celah plugin/theme yang dapat dirangkai menjadi eskalasi wp2shell.",
    fix: "Nonaktifkan WP_DEBUG_LOG di production, hapus /wp-content/debug.log, dan blokir akses *.log di konfigurasi web server.",
  },
  {
    path: "/wp-json/wp/v2/users",
    vector: "wp2shell",
    title: "[wp2shell] WordPress REST API User Enumeration terbuka",
    cwe: ["CWE-200", "CWE-284"],
    rce: false,
    marker: "wp/v2/users slug & id",
    validate: (b, ct) =>
      json(ct, b) && /"slug"\s*:\s*"[^"]+"/.test(b) && /"avatar_urls"\s*:/.test(b) ? "MEDIUM" : null,
    impact:
      "Daftar akun administrator/author WordPress terekspos tanpa autentikasi, memudahkan credential stuffing menuju pengambilalihan wp-admin & injeksi plugin/theme (wp2shell).",
    fix: "Batasi endpoint /wp-json/wp/v2/users hanya untuk pengguna terautentikasi dan aktifkan 2FA pada seluruh akun administrator.",
  },
  {
    path: "/xmlrpc.php",
    vector: "wp2shell",
    title: "[wp2shell] WordPress XML-RPC interface aktif",
    cwe: ["CWE-307", "CWE-918"],
    rce: false,
    marker: "XML-RPC server accepts POST requests only",
    validate: (b, _ct, st) =>
      (st === 200 || st === 405) && /XML-RPC server accepts POST requests only/i.test(b) ? "MEDIUM" : null,
    impact:
      "Antarmuka xmlrpc.php aktif dapat disalahgunakan untuk brute-force terdistribusi (system.multicall) dan pingback SSRF sebagai batu loncatan kompromi wp2shell.",
    fix: "Blokir akses ke /xmlrpc.php di level WAF/Nginx atau matikan melalui filter xmlrpc_enabled jika tidak diperlukan.",
  },
  {
    path: "/wp-admin/install.php",
    vector: "wp2shell",
    title: "[wp2shell] WordPress Installer / Setup terbuka",
    cwe: ["CWE-306", "CWE-434"],
    rce: true,
    marker: "WordPress installation form",
    validate: (b, ct) =>
      html(ct) &&
      /<title>[^<]*WordPress\s*&rsaquo;\s*Installation/i.test(b) &&
      /weblog_title|admin_password/i.test(b)
        ? "CRITICAL"
        : null,
    impact:
      "Halaman instalasi WordPress yang belum terkunci memungkinkan pihak luar mengambil alih akun admin utama dan mengunggah plugin/theme untuk mengeksekusi kode (wp2shell).",
    fix: "Selesaikan instalasi segera atau blokir akses publik ke /wp-admin/install.php dan /wp-admin/setup-config.php.",
  },
  {
    path: "/wp-content/uploads/",
    vector: "wp2shell",
    title: "[wp2shell] Directory listing terbuka pada /wp-content/uploads/",
    cwe: ["CWE-548", "CWE-434"],
    rce: false,
    marker: "Index of /wp-content/uploads",
    validate: (b, ct) =>
      html(ct) && /<(?:title|h1)>\s*Index of \/wp-content\/uploads/i.test(b) ? "HIGH" : null,
    impact:
      "Indeks direktori uploads terbuka memudahkan penyerang memetakan file sensitif, backup plugin, atau memicu webshell yang terunggah.",
    fix: "Matikan autoindex (Options -Indexes) dan larang eksekusi script PHP di dalam direktori /wp-content/uploads/.",
  },

  // ==================== 2. php2shell (PHP Eval, Ignition, Profiler & Runtime Surface) ====================
  {
    path: "/_ignition/health-check",
    vector: "php2shell",
    title: "[php2shell] Laravel Ignition debug endpoint terbuka",
    cwe: ["CWE-94", "CWE-489"],
    cve: ["CVE-2021-3129"],
    rce: true,
    marker: "can_execute_commands",
    validate: (b, ct) => (json(ct, b) && /"can_execute_commands"\s*:\s*true/.test(b) ? "HIGH" : json(ct, b) && /"can_execute_commands"\s*:\s*false/.test(b) ? "MEDIUM" : null),
    impact: "Ignition aktif di mode debug. Versi Ignition ≤ 2.5.1 dapat dieksploitasi untuk eksekusi kode jarak jauh (CVE-2021-3129).",
    fix: "Set APP_DEBUG=false di production, upgrade facade/ignition ≥ 2.5.2, dan blokir /_ignition/*.",
  },
  {
    path: "/console",
    vector: "py2shell",
    title: "[py2shell] Werkzeug / Flask Interactive Debug Console terbuka",
    cwe: ["CWE-94", "CWE-489"],
    rce: true,
    marker: "Werkzeug interactive console",
    validate: (b, ct) => (html(ct) && /<title>[^<]*Werkzeug[^<]*<\/title>/i.test(b) && /(Interactive Console|console locked|__debugger__)/i.test(b) ? "HIGH" : null),
    impact: "Console debugger interaktif dapat mengeksekusi kode Python di server bila PIN bocor atau debug aktif.",
    fix: "Jalankan aplikasi dengan debug=False di production dan jangan expose Werkzeug debugger.",
  },

  // ==================== 7. Enterprise & Server Diagnostics (Actuator, Jolokia, ELMAH, Server-Status) ====================
  {
    path: "/actuator/env",
    vector: "rce-surface",
    title: "Spring Boot Actuator /env terbuka",
    cwe: ["CWE-200", "CWE-215"],
    rce: true,
    marker: "propertySources",
    validate: (b, ct) => (json(ct, b) && /"propertySources"\s*:/.test(b) && /"activeProfiles"\s*:/.test(b) ? "HIGH" : null),
    impact:
      "Konfigurasi dan environment aplikasi terbaca publik; sering menjadi batu loncatan menuju Remote Code Execution via Spring Cloud / SnakeYAML.",
    fix: "Batasi endpoint actuator (management.endpoints.web.exposure.include) dan lindungi dengan autentikasi.",
  },
  {
    path: "/actuator/gateway/routes",
    vector: "rce-surface",
    title: "Spring Cloud Gateway Actuator routes terbuka",
    cwe: ["CWE-917", "CWE-94"],
    cve: ["CVE-2022-22947"],
    rce: true,
    marker: "route_id & predicates",
    validate: (b, ct) =>
      json(ct, b) && /"route_id"\s*:/.test(b) && /"predicates"\s*:/.test(b) ? "CRITICAL" : null,
    impact:
      "Endpoint Actuator Spring Cloud Gateway terbuka tanpa autentikasi; rentan terhadap SpEL Code Injection / RCE (CVE-2022-22947).",
    fix: "Upgrade Spring Cloud Gateway ke versi ter-patch dan nonaktifkan eksposur endpoint gateway di Actuator.",
  },
  {
    path: "/actuator",
    vector: "rce-surface",
    title: "Spring Boot Actuator index terbuka",
    cwe: ["CWE-200"],
    rce: false,
    marker: "_links",
    validate: (b, ct) =>
      json(ct, b) && /"_links"\s*:/.test(b) && /"(env|heapdump|beans|mappings|gateway)"\s*:/.test(b)
        ? "MEDIUM"
        : null,
    impact: "Daftar endpoint manajemen terbuka, memudahkan reconnaissance permukaan serangan server.",
    fix: "Batasi eksposur actuator ke jaringan internal atau tambahkan autentikasi.",
  },
  {
    path: "/elmah.axd",
    vector: "rce-surface",
    title: "ELMAH .NET error log terbuka",
    cwe: ["CWE-209", "CWE-532"],
    rce: false,
    marker: "ELMAH",
    validate: (b, ct) => (html(ct) && /<title>\s*Error Log for/i.test(b) && /ELMAH/i.test(b) ? "HIGH" : null),
    impact: "Log error berisi stack trace, parameter request, dan session/cookie autentikasi pengguna.",
    fix: "Batasi elmah.axd dengan autentikasi atau nonaktifkan remote access (`allowRemoteAccess=false`).",
  },
  {
    path: "/jolokia/version",
    vector: "rce-surface",
    title: "Jolokia JMX-over-HTTP terbuka",
    cwe: ["CWE-306", "CWE-94"],
    rce: true,
    marker: "jolokia agent",
    validate: (b, ct) =>
      json(ct, b) && /jolokia/i.test(b) && /"agent"\s*:/.test(b) && /"protocol"\s*:/.test(b) ? "CRITICAL" : null,
    impact:
      "Akses JMX tanpa autentikasi dapat dipakai memanggil MBean berbahaya (Logback/DiagnosticCommand) sehingga berpotensi RCE.",
    fix: "Matikan Jolokia di production atau lindungi dengan autentikasi dan pembatasan jaringan.",
  },
  {
    path: "/server-status",
    vector: "rce-surface",
    title: "Apache mod_status terbuka",
    cwe: ["CWE-200"],
    rce: false,
    marker: "Apache Server Status",
    validate: (b, ct) =>
      html(ct) && /<(?:h1|title)>\s*Apache (?:Server )?Status(?: for)?/i.test(b) ? "MEDIUM" : null,
    impact: "Menampilkan request HTTP aktif, IP klien, dan URL endpoint internal secara real-time.",
    fix: "Batasi /server-status hanya ke localhost atau jaringan administrator.",
  },
];

export const RCE_SURFACE_PATH_COUNT = RCE_SPECS.length;

export interface RceSurfaceResult {
  findings: Finding[];
  evidence: RceSurfaceEvidence[];
}

const newId = () => Math.random().toString(36).slice(2) + Date.now().toString(36);

export function evaluateRceSpec(spec: Spec, status: number, ct: string, body: string): Severity | null {
  if (status !== 200 && !(spec.path === "/xmlrpc.php" && status === 405)) return null;
  return spec.validate(body, ct.toLowerCase(), status);
}

export async function checkRceSurface(
  origin: string,
  budget: RequestBudget,
  cfClearance?: string
): Promise<RceSurfaceResult> {
  const out: RceSurfaceResult = { findings: [], evidence: [] };
  for (const spec of RCE_SPECS) {
    const url = new URL(spec.path, origin).toString();
    const r = await budget.spend(async () => {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), 8000);
      try {
        const res = await fetch(url, { method: "GET", headers: chromeHeaders(), redirect: "manual", signal: ctl.signal });
        const text = (await res.text()).slice(0, 64 * 1024);
        return {
          status: res.status,
          headers: res.headers,
          text,
          ct: res.headers.get("content-type") ?? "",
        };
      } catch {
        return null;
      } finally {
        clearTimeout(t);
      }
    });
    if (!r) continue;
    if (detectCloudflareChallenge(r.status, r.headers, r.text.slice(0, 2000))) continue;

    const sev = evaluateRceSpec(spec, r.status, r.ct, r.text);
    if (!sev) continue;

    const category: FindingCategory = spec.vector;

    out.findings.push({
      id: newId(),
      severity: sev,
      title: `${spec.title}${spec.rce ? " — potensi RCE" : ""}`,
      endpoint: url,
      evidence: `HTTP ${r.status} — isi respons cocok penanda "${spec.marker}" (detail diamankan di Sentinel Vault)`,
      impact: spec.impact,
      fix: spec.fix,
      cwe: spec.cwe.join(", "),
      cve: spec.cve,
      rce: spec.rce || undefined,
      confidence: "verified",
      category,
    });
    out.evidence.push({
      path: spec.path,
      title: spec.title,
      severity: sev,
      cwe: spec.cwe,
      cve: spec.cve ?? [],
      status: r.status,
      marker: spec.marker,
      snippet: r.text.replace(/\s+/g, " ").slice(0, 300),
    });
  }
  return out;
}
