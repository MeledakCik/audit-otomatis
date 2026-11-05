/**
 * Permukaan RCE PASIF: endpoint diagnostik/debug yang membuka jalur eksekusi kode bila terekspos.
 * Hanya GET, tanpa payload. Temuan hanya dibuat jika ISI respons cocok (bukan sekadar status 200).
 */
import type { Finding, Severity } from "@/lib/types";
import { chromeHeaders, detectCloudflareChallenge } from "@/lib/crawler";
import type { RequestBudget } from "@/lib/rate-limit";
import type { RceSurfaceEvidence } from "@/lib/sentinel/dossier";

interface Spec {
  path: string;
  title: string;
  cwe: string[];
  cve?: string[];
  rce: boolean;
  /** return severity bila cocok, null jika bukan true positive */
  validate: (body: string, ct: string) => Severity | null;
  marker: string;
  impact: string;
  fix: string;
}

const html = (ct: string) => ct.includes("html");
const json = (ct: string, b: string) => ct.includes("json") || /^\s*[{[]/.test(b);

export const RCE_SPECS: Spec[] = [
  {
    path: "/_ignition/health-check",
    title: "Laravel Ignition debug endpoint terbuka",
    cwe: ["CWE-94", "CWE-489"], cve: ["CVE-2021-3129"], rce: true,
    marker: "can_execute_commands",
    validate: (b, ct) => (json(ct, b) && /"can_execute_commands"\s*:\s*true/.test(b) ? "HIGH" : json(ct, b) && /"can_execute_commands"\s*:\s*false/.test(b) ? "MEDIUM" : null),
    impact: "Ignition aktif di mode debug. Versi Ignition ≤ 2.5.1 dapat dieksploitasi untuk eksekusi kode jarak jauh (CVE-2021-3129).",
    fix: "Set APP_DEBUG=false di production, upgrade facade/ignition ≥ 2.5.2, dan blokir /_ignition/*.",
  },
  {
    path: "/console",
    title: "Werkzeug/Flask debug console terbuka",
    cwe: ["CWE-94", "CWE-489"], rce: true,
    marker: "Werkzeug interactive console",
    validate: (b, ct) => (html(ct) && /<title>[^<]*Werkzeug[^<]*<\/title>/i.test(b) && /(Interactive Console|console locked|__debugger__)/i.test(b) ? "HIGH" : null),
    impact: "Console debugger interaktif dapat mengeksekusi kode Python di server bila PIN bocor atau debug aktif.",
    fix: "Jalankan aplikasi dengan debug=False di production dan jangan expose Werkzeug debugger.",
  },
  {
    path: "/actuator/env",
    title: "Spring Boot Actuator /env terbuka",
    cwe: ["CWE-200", "CWE-215"], rce: false,
    marker: "propertySources",
    validate: (b, ct) => (json(ct, b) && /"propertySources"\s*:/.test(b) && /"activeProfiles"\s*:/.test(b) ? "HIGH" : null),
    impact: "Konfigurasi dan environment aplikasi terbaca publik; sering menjadi batu loncatan menuju kompromi penuh.",
    fix: "Batasi endpoint actuator (management.endpoints.web.exposure.include) dan lindungi dengan autentikasi.",
  },
  {
    path: "/actuator",
    title: "Spring Boot Actuator index terbuka",
    cwe: ["CWE-200"], rce: false,
    marker: "_links",
    validate: (b, ct) => (json(ct, b) && /"_links"\s*:/.test(b) && /"(env|heapdump|beans|mappings)"\s*:/.test(b) ? "MEDIUM" : null),
    impact: "Daftar endpoint manajemen terbuka, memudahkan reconnaissance.",
    fix: "Batasi eksposur actuator ke jaringan internal atau tambahkan autentikasi.",
  },
  {
    path: "/_profiler/",
    title: "Symfony Profiler terbuka",
    cwe: ["CWE-489", "CWE-200"], rce: false,
    marker: "Symfony Profiler",
    validate: (b, ct) => (html(ct) && /<title>[^<]*Symfony Profiler[^<]*<\/title>/i.test(b) ? "HIGH" : null),
    impact: "Profiler menampilkan request, konfigurasi, dan kredensial yang bisa dimanfaatkan penyerang.",
    fix: "Nonaktifkan profiler dan APP_ENV=prod di production.",
  },
  {
    path: "/elmah.axd",
    title: "ELMAH error log terbuka",
    cwe: ["CWE-209", "CWE-532"], rce: false,
    marker: "ELMAH",
    validate: (b, ct) => (html(ct) && /<title>\s*Error Log for/i.test(b) && /ELMAH/i.test(b) ? "HIGH" : null),
    impact: "Log error berisi stack trace, parameter, dan kadang session/token pengguna.",
    fix: "Batasi elmah.axd dengan autentikasi atau nonaktifkan remote access.",
  },
  {
    path: "/jolokia/version",
    title: "Jolokia JMX-over-HTTP terbuka",
    cwe: ["CWE-306"], rce: true,
    marker: "jolokia agent",
    validate: (b, ct) => (json(ct, b) && /jolokia/i.test(b) && /"agent"\s*:/.test(b) && /"protocol"\s*:/.test(b) ? "HIGH" : null),
    impact: "Akses JMX tanpa autentikasi dapat dipakai memanggil MBean berbahaya sehingga berpotensi eksekusi kode.",
    fix: "Matikan Jolokia di production atau lindungi dengan autentikasi dan pembatasan jaringan.",
  },
  {
    path: "/server-status",
    title: "Apache mod_status terbuka",
    cwe: ["CWE-200"], rce: false,
    marker: "Apache Server Status",
    validate: (b, ct) => (html(ct) && /<(?:h1|title)>\s*Apache (?:Server )?Status(?: for)?/i.test(b) ? "MEDIUM" : null),
    impact: "Menampilkan request aktif, IP klien, dan URL internal.",
    fix: "Batasi /server-status ke localhost atau jaringan admin.",
  },
];

export const RCE_SURFACE_PATH_COUNT = RCE_SPECS.length;

export interface RceSurfaceResult { findings: Finding[]; evidence: RceSurfaceEvidence[] }

const newId = () => Math.random().toString(36).slice(2) + Date.now().toString(36);

export function evaluateRceSpec(spec: Spec, status: number, ct: string, body: string): Severity | null {
  if (status !== 200) return null;
  return spec.validate(body, ct.toLowerCase());
}

export async function checkRceSurface(origin: string, budget: RequestBudget): Promise<RceSurfaceResult> {
  const out: RceSurfaceResult = { findings: [], evidence: [] };
  for (const spec of RCE_SPECS) {
    const url = new URL(spec.path, origin).toString();
    const r = await budget.spend(async () => {
      const ctl = new AbortController();
      const t = setTimeout(() => ctl.abort(), 8000);
      try {
        const res = await fetch(url, { method: "GET", headers: chromeHeaders(), redirect: "manual", signal: ctl.signal });
        const text = (await res.text()).slice(0, 64 * 1024);
        return { status: res.status, headers: res.headers, text, ct: res.headers.get("content-type") ?? "" };
      } catch { return null; } finally { clearTimeout(t); }
    });
    if (!r) continue;
    if (detectCloudflareChallenge(r.status, r.headers, r.text.slice(0, 2000))) continue;

    const sev = evaluateRceSpec(spec, r.status, r.ct, r.text);
    if (!sev) continue;

    out.findings.push({
      id: newId(),
      severity: sev,
      title: `${spec.title}${spec.rce ? " — potensi RCE" : ""}`,
      endpoint: url,
      evidence: `HTTP 200 — isi respons cocok penanda "${spec.marker}" (isi tidak ditampilkan)`,
      impact: spec.impact,
      fix: spec.fix,
      cwe: spec.cwe.join(", "),
      cve: spec.cve,
      rce: spec.rce || undefined,
      confidence: "verified",
      category: "rce-surface",
    });
    out.evidence.push({ path: spec.path, title: spec.title, severity: sev, cwe: spec.cwe, cve: spec.cve ?? [], status: r.status, marker: spec.marker, snippet: r.text.replace(/\s+/g, " ").slice(0, 300) });
  }
  return out;
}
