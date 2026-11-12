"use client";

import React, { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  Search, ArrowRight, ChevronDown, Copy, Check, Loader2, AlertCircle,
  ShieldCheck, Lock, TrendingUp, Radar,
} from "lucide-react";
import { SENTINEL_NAV_ITEMS } from "@/lib/nav-items";
import { ModuleIcon } from "@/components/app-sidebar";

// ============================================================================
// DATA LANDING (modul & navigasi ada di lib/nav-items.ts — satu sumber)
// ============================================================================
const SHELL_SURFACES = [
  { id: "wp2shell", label: "wp2shell", cwe: "CWE-434 · CWE-538 · CWE-284", title: "WordPress RCE & Config Surface", desc: "Deteksi pasif wp-config.php.bak/~/.save, debug.log terbuka, xmlrpc.php aktif, enumerasi user REST API (/wp-json/wp/v2/users), dan indeks /wp-content/uploads/.", paths: ["/wp-config.php.bak", "/wp-content/debug.log", "/xmlrpc.php", "/wp-json/wp/v2/users"] },
  { id: "php2shell", label: "php2shell", cwe: "CWE-94 · CWE-95 · CWE-489", title: "PHP Eval, Ignition & Profiler", desc: "Audit pasif Laravel Ignition debug RCE (CVE-2021-3129), PHPUnit eval-stdin.php (CVE-2017-9841), Symfony Profiler, phpinfo(), dan PHP-FPM status.", paths: ["/_ignition/health-check", "/vendor/phpunit/.../eval-stdin.php", "/phpinfo.php", "/fpm-status"] },
  { id: "node2shell", label: "node2shell", cwe: "CWE-94 · CWE-502 · CWE-1321", title: "Node.js V8 Inspector & SSR Sinks", desc: "Deteksi port debug V8 Inspector (/json/version), PM2 ecosystem.config.js, serta sink AST child_process, vm.runInNewContext & prototype pollution.", paths: ["/json/version", "/ecosystem.config.js", "child_process / vm", "__proto__ pollution"] },
  { id: "go2shell", label: "go2shell", cwe: "CWE-215 · CWE-200 · CWE-489", title: "Go Runtime pprof & Expvar", desc: "Inspeksi pasif profil runtime Go (/debug/pprof/), kebocoran argumen binary (/debug/pprof/cmdline), goroutine/heap dump, serta expvar (/debug/vars).", paths: ["/debug/pprof/", "/debug/pprof/cmdline", "/debug/vars", "Go panic trace"] },
  { id: "py2shell", label: "py2shell", cwe: "CWE-94 · CWE-306 · CWE-489", title: "Python Werkzeug, Jupyter & Celery", desc: "Deteksi Werkzeug/Flask interactive debugger (/console), Jupyter Notebook kernel API (/api/kernels), Celery Flower (/api/workers), dan Django Debug Toolbar.", paths: ["/console", "/api/kernels", "/api/workers", "/__debug__/"] },
  { id: "node-oob", label: "node OOB", cwe: "CWE-119 · CWE-125 · CWE-787 · CWE-918", title: "Node Out-of-Bounds (OOB) & Memory", desc: "Deteksi snapshot memori V8 (/heapdump), alokasi Buffer.allocUnsafe & pembacaan TypedArray/DataView out-of-bounds, serta kandidat OOB SSRF/Webhook.", paths: ["/heapdump", "Buffer.allocUnsafe", "TypedArray OOB", "OOB Callback/SSRF"] },
  { id: "webshell", label: "webshell", cwe: "CWE-434 · CWE-94 · CWE-506", title: "Active WebShell & Stealth Backdoor", desc: "Deteksi artefak WebShell aktif (WSO, FilesMan, b374k, ALFA Team, MariJUANA, Gel4y, IndoXploit, Mini Shell) serta source PHP ter-obfuscate.", paths: ["/shell.php", "/wso.php", "/alfa.php", "/b374k.php"] },
  { id: "filemanager", label: "filemanager", cwe: "CWE-434 · CWE-306 · CWE-284", title: "FileManager WebShell & Connector Audit", desc: "Inspeksi pasif panel Web File Manager terekspos: TinyFileManager (CVE-2021-45010), elFinder & WP File Manager (CVE-2020-25213), KCFinder.", paths: ["/tinyfilemanager.php", "/fm.php", "/elfinder/...", "/filemanager/dialog.php"] }
];

const VAULT_STEPS = [
  { step: "STEP 01", title: "Crawl & Recon Pasif", badge: "GET-Only · Max 50 URL", summary: "Menelusuri tautan internal, robots.txt, sitemap.xml, dan header HTTP tanpa mengirim payload eksploitasi." },
  { step: "STEP 02", title: "Deep Shell & AST Audit", badge: "8 Runtime Engines", summary: "Membongkar bundle JS dan memeriksa permukaan wp2shell, php2shell, node2shell, go2shell, py2shell & OOB." },
  { step: "STEP 03", title: "Brankas AES-256-GCM", badge: "Auto-Redacted", summary: "Temuan kritis (.env, .git/HEAD, wp-config.php.bak, AWS keys) langsung disensor dari publik & dienkripsi." },
  { step: "STEP 04", title: "Klaim Pemilik Domain", badge: "DNS TXT / HTTP", summary: "Pemilik sah domain memverifikasi kepemilikan untuk membuka bukti 1x lihat dan mengunduh laporan." }
];

const INITIAL_FINDINGS = [
  { id: "F-01", sev: "MEDIUM", module: "lib/vuln (DOM Sink)", path: "/_next/static/chunks/main-app.js", detail: "Pola innerHTML pada chunk internal Next.js (status: POTENTIAL — false-positive wajar dari renderer React)." },
  { id: "F-02", sev: "MEDIUM", module: "Header Armor", path: "Content-Security-Policy", detail: "Direktif script-src memuat unsafe-inline untuk hidrasi skrip Next.js." },
  { id: "F-03", sev: "LOW", module: "Header Armor", path: "Permissions-Policy", detail: "Disarankan membatasi akses geolocation, camera, dan microphone secara eksplisit." },
  { id: "F-04", sev: "LOW", module: "SEO Master", path: "Hreflang International", detail: "Tag hreflang id-ID, en-US, dan x-default aktif; siap diperluas ke 13 locale penuh." },
  { id: "F-05", sev: "INFO", module: "lib/discovery", path: "/robots.txt & /sitemap.xml", detail: "File well-known ditemukan (200 OK) dan seluruh modul utama terindeks." }
];

const FAQ_DATA = [
  {
    q_id: "Apakah Sentinel-ID 100% aman dan tidak merusak server produksi?",
    a_id: "Ya. Sentinel-ID beroperasi secara 100% pasif menggunakan metode HTTP GET/HEAD-only tanpa injeksi payload, tanpa brute-force, dilengkapi SSRF Guard serta pembatas RequestBudget maksimal 100 request.",
    q_en: "Is Sentinel-ID 100% safe for production servers (zero-exploit)?",
    a_en: "Yes. Sentinel-ID is a strictly passive, non-intrusive website security auditor using read-only HTTP GET/HEAD requests with zero exploit payloads and a 100-request budget."
  },
  {
    q_id: "Bagaimana cara kerja Brankas Bukti Terenkripsi AES-256-GCM (Sentinel Vault)?",
    a_id: "Ketika pemindai mendeteksi file sensitif seperti .env, .git/HEAD, wp-config.php.bak, atau kunci AWS, isi rahasia langsung di-redact dari publik dan dienkripsi menggunakan AES-256-GCM. Hanya pemilik sah domain yang dapat mengklaim bukti tersebut melalui verifikasi DNS TXT atau file HTTP.",
    q_en: "How does the AES-256-GCM Encrypted Evidence Vault protect leaked secrets?",
    a_en: "When Sentinel-ID detects exposed .env files, .git repositories, or API keys, raw values are never shown publicly. Evidence is encrypted with AES-256-GCM and unlocked only once by the verified domain owner."
  },
  {
    q_id: "Bagaimana fitur SEO Master membantu website naik ke Rank #1 Google Internasional?",
    a_id: "Modul SEO Master memeriksa 35+ sinyal teknis Google: 13 tag Hreflang internasional (id-ID, en-US, en-GB, x-default, dll.), struktur JSON-LD Schema.org, Open Graph, Core Web Vitals, serta sinyal HTTPS/HSTS/CSP.",
    q_en: "How does the SEO Master module help websites rank #1 on Google internationally?",
    a_en: "SEO Master audits 35+ Google ranking factors including 13 international hreflang tags, Schema.org JSON-LD graphs, Core Web Vitals, Open Graph, and HTTPS/HSTS trust signals."
  }
];

const BADGE_TONE: Record<string, string> = {
  pink: "bg-accent/10 text-accent",
  emerald: "bg-ok/10 text-ok",
  purple: "bg-accent-2/10 text-accent-2",
  cyan: "bg-sev-low/10 text-sev-low",
  amber: "bg-warn/10 text-warn",
  rose: "bg-danger/10 text-danger",
};

const SEV_STYLE: Record<string, string> = {
  CRITICAL: "bg-sev-critical/10 text-sev-critical",
  HIGH: "bg-sev-high/10 text-sev-high",
  MEDIUM: "bg-sev-medium/10 text-sev-medium",
  LOW: "bg-sev-low/10 text-sev-low",
  INFO: "bg-sev-info/10 text-sev-info",
};

const STATS = [
  { label: "Deep Crawl", val: "50 URL", sub: "Depth 3 · 100 req" },
  { label: "Shell Surface", val: "8 engine", sub: "wp/php/node/go/py" },
  { label: "Sentinel Vault", val: "AES-256", sub: "Redaksi publik" },
  { label: "SEO Master", val: "13 locale", sub: "Hreflang · JSON-LD" },
];

const PIPELINE = [
  "Multi-page & edge crawler",
  "AST JS & secret scan",
  "wp/php/node/go/py shell",
  "WebShell & FileManager",
  "Node out-of-bounds (OOB)",
  "Brankas AES-256-GCM",
  "Cloudflare/WAF & DoH intel",
  "Header & OSV/NVD CVE intel",
];

function Chip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`shrink-0 snap-start px-3.5 py-2 rounded-xl text-sm font-medium transition-colors ${
        active ? "bg-gradient-accent text-white shadow-sm" : "text-muted hover:text-foreground hover:bg-foreground/5"
      }`}
    >
      {children}
    </button>
  );
}

function SectionHead({ eyebrow, title, tone = "text-accent" }: { eyebrow: string; title: string; tone?: string }) {
  return (
    <div>
      <span className={`text-xs font-mono uppercase tracking-widest font-semibold ${tone}`}>{eyebrow}</span>
      <h2 className="text-xl sm:text-2xl font-bold mt-1 text-balance">{title}</h2>
    </div>
  );
}

export function HomePage() {
  const router = useRouter();
  const [domain, setDomain] = useState("");
  const [consent, setConsent] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [activeShellId, setActiveShellId] = useState(SHELL_SURFACES[0].id);
  const [moduleCategory, setModuleCategory] = useState("Semua");
  const [severity, setSeverity] = useState<"ALL" | "MEDIUM" | "LOW" | "INFO">("ALL");
  const [faqLang, setFaqLang] = useState<"id" | "en">("id");
  const [openFaq, setOpenFaq] = useState<number | null>(0);
  const [copied, setCopied] = useState(false);

  const activeShell = SHELL_SURFACES.find((s) => s.id === activeShellId) ?? SHELL_SURFACES[0];
  const categories = useMemo(() => ["Semua", ...Array.from(new Set(SENTINEL_NAV_ITEMS.map((m) => m.category)))], []);
  const modules = useMemo(
    () => (moduleCategory === "Semua" ? SENTINEL_NAV_ITEMS : SENTINEL_NAV_ITEMS.filter((m) => m.category === moduleCategory)),
    [moduleCategory]
  );
  const findings = useMemo(
    () => (severity === "ALL" ? INITIAL_FINDINGS : INITIAL_FINDINGS.filter((f) => f.sev === severity)),
    [severity]
  );

  async function handleRunScan(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!domain.trim()) return setError("Masukkan domain atau URL target terlebih dahulu.");
    if (!consent) return setError("Centang konfirmasi kepemilikan/izin sebelum scan dimulai.");
    setPending(true);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: domain.trim(), permission: true }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.ok || !data.scanId) {
        setError(data.error ?? "Gagal memulai pemindaian. Silakan coba lagi.");
        setPending(false);
        return;
      }
      const host = data.domain || domain.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
      router.push(`/scan/${data.scanId}?domain=${encodeURIComponent(host)}`);
    } catch {
      setError("Gagal terhubung ke server. Periksa koneksi internet Anda lalu coba lagi.");
      setPending(false);
    }
  }

  function handleCopy() {
    const txt = `# Contoh Laporan Sentinel-ID\n${INITIAL_FINDINGS.map((f) => `- [${f.sev}] ${f.module} — ${f.path}`).join("\n")}`;
    try { navigator.clipboard?.writeText(txt); } catch {}
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const card = "glass-panel rounded-3xl p-5 sm:p-6";
  const inset = "rounded-2xl bg-sunken/60 border border-border";

  return (
    <div className="space-y-6 sm:space-y-8">
      {/* ============================ HERO ============================ */}
      <section className="grid grid-cols-1 lg:grid-cols-12 gap-5 items-stretch">
        <div className={`lg:col-span-7 ${card} space-y-5`}>
          <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs glass-pill">
            <span className="w-2 h-2 rounded-full bg-ok animate-pulse" aria-hidden />
            <span className="font-mono font-semibold text-ok">GET-ONLY · ZERO-EXPLOIT</span>
          </span>

          <div className="space-y-3">
            <h1 className="text-3xl sm:text-4xl xl:text-5xl font-extrabold tracking-tight leading-[1.1] text-balance">
              Audit keamanan web pasif.{" "}
              <span className="text-gradient-accent">Jernih, ringan, tanpa risiko.</span>
            </h1>
            <p className="text-base leading-relaxed text-soft max-w-2xl">
              Periksa postur keamanan dan kesiapan SEO domain Anda tanpa mengirim payload apa pun ke server.
              Crawler multi-halaman, 8 engine permukaan runtime, dan brankas bukti AES-256-GCM.
            </p>
          </div>

          <form onSubmit={handleRunScan} className={`${inset} p-4 space-y-3`} noValidate>
            <label htmlFor="landing-domain" className="text-sm font-semibold">Domain target</label>
            <div className="flex flex-col sm:flex-row gap-2.5">
              <div className="flex-1 flex items-center gap-2.5 px-3.5 rounded-xl bg-panel border border-border focus-within:border-accent">
                <Search className="w-4 h-4 text-accent shrink-0" aria-hidden />
                <input
                  id="landing-domain"
                  type="text"
                  inputMode="url"
                  autoCapitalize="none"
                  autoCorrect="off"
                  spellCheck={false}
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="contoh: sentinel-id.net"
                  className="w-full bg-transparent py-3 text-base font-mono focus:outline-none placeholder:text-muted-dim"
                />
              </div>
              <button
                type="submit"
                disabled={pending}
                className="px-6 py-3 rounded-xl font-semibold text-sm text-white bg-gradient-accent hover:brightness-110 disabled:opacity-60 transition flex items-center justify-center gap-2"
              >
                {pending ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
                <span>{pending ? "Memulai…" : "Mulai audit"}</span>
                {!pending && <ArrowRight className="w-4 h-4" />}
              </button>
            </div>

            <label className="flex items-start gap-2.5 text-sm text-soft cursor-pointer">
              <input
                type="checkbox"
                checked={consent}
                onChange={(e) => setConsent(e.target.checked)}
                className="mt-0.5 w-4 h-4 shrink-0 accent-[var(--accent)]"
              />
              <span>Saya pemilik sah atau memiliki izin tertulis untuk mengaudit domain ini secara pasif.</span>
            </label>

            {error && (
              <p role="alert" className="flex items-start gap-2 text-sm text-danger">
                <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" /> {error}
              </p>
            )}

            <div className="flex flex-wrap gap-x-5 gap-y-1 text-sm">
              <Link href="/scan/sentinel" className="inline-flex items-center gap-1.5 text-accent hover:underline">
                <Lock className="w-4 h-4" /> Brankas AES-256 &amp; klaim
              </Link>
              <Link href="/scan/seo-master" className="inline-flex items-center gap-1.5 text-accent hover:underline">
                <TrendingUp className="w-4 h-4" /> SEO Master
              </Link>
              <Link href="/qc" className="inline-flex items-center gap-1.5 text-accent hover:underline">
                <Radar className="w-4 h-4" /> QC Otomatis
              </Link>
            </div>
          </form>

          <dl className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
            {STATS.map((st) => (
              <div key={st.label} className={`${inset} p-3`}>
                <dt className="text-xs font-mono uppercase text-muted-dim">{st.label}</dt>
                <dd className="text-lg font-bold mt-0.5">{st.val}</dd>
                <dd className="text-xs text-muted truncate">{st.sub}</dd>
              </div>
            ))}
          </dl>
        </div>

        <aside className={`lg:col-span-5 ${card} space-y-4`}>
          <div className="flex items-center gap-3.5">
            <span className="w-12 h-12 rounded-2xl bg-gradient-accent flex items-center justify-center text-white shrink-0">
              <ShieldCheck className="w-6 h-6" />
            </span>
            <div className="min-w-0">
              <span className="text-xs font-mono uppercase tracking-widest text-ok font-semibold">Passive architecture</span>
              <h2 className="text-lg font-bold leading-snug">Unified Deep Security &amp; Vault Engine</h2>
            </div>
          </div>
          <p className="text-xs font-mono text-muted break-words">discovery → parsers → fingerprint → vuln → fuzzer</p>
          <ol className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-1 xl:grid-cols-2 gap-2">
            {PIPELINE.map((eng, i) => (
              <li key={eng} className={`${inset} px-3 py-2.5 text-sm flex items-center gap-2.5`}>
                <span className="font-mono text-xs text-accent font-semibold">{String(i + 1).padStart(2, "0")}</span>
                <span className="truncate">{eng}</span>
              </li>
            ))}
          </ol>
        </aside>
      </section>

      {/* ========================= CARA KERJA ========================= */}
      <section aria-labelledby="how" className="space-y-4">
        <h2 id="how" className="sr-only">Cara kerja</h2>
        <ol className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
          {VAULT_STEPS.map((st) => (
            <li key={st.step} className={`glass-panel rounded-2xl p-4`}>
              <div className="flex items-center justify-between gap-2">
                <span className="text-xs font-mono font-bold text-accent">{st.step}</span>
                <span className="text-xs font-mono text-ok text-right">{st.badge}</span>
              </div>
              <h3 className="text-base font-bold mt-2">{st.title}</h3>
              <p className="text-sm mt-1 leading-relaxed text-muted">{st.summary}</p>
            </li>
          ))}
        </ol>
      </section>

      {/* ======================= SHELL SURFACES ======================= */}
      <section className={`${card} space-y-5`}>
        <SectionHead eyebrow="Deep passive runtime" title="Inspeksi 8 permukaan runtime secara pasif" />
        <div role="tablist" aria-label="Permukaan runtime" className="flex gap-1.5 overflow-x-auto thin-scroll snap-x pb-1 -mx-1 px-1">
          {SHELL_SURFACES.map((s) => (
            <Chip key={s.id} active={activeShellId === s.id} onClick={() => setActiveShellId(s.id)}>
              <span className="font-mono">{s.label}</span>
            </Chip>
          ))}
        </div>
        <div className={`${inset} p-4 sm:p-5 grid grid-cols-1 lg:grid-cols-12 gap-5 items-center`}>
          <div className="lg:col-span-7 space-y-1.5">
            <div className="text-xs font-mono text-accent font-semibold break-words">{activeShell.label} · {activeShell.cwe}</div>
            <h3 className="text-lg font-bold">{activeShell.title}</h3>
            <p className="text-sm leading-relaxed text-muted">{activeShell.desc}</p>
          </div>
          <div className="lg:col-span-5 grid grid-cols-1 sm:grid-cols-2 gap-2">
            {activeShell.paths.map((p) => (
              <code key={p} className="px-3 py-2 rounded-xl bg-panel border border-border font-mono text-xs text-sev-low truncate">{p}</code>
            ))}
          </div>
        </div>
      </section>

      {/* ======================== CONTOH LAPORAN ======================== */}
      <section className={`${card} space-y-4`}>
        <div className="flex flex-wrap items-end justify-between gap-3">
          <SectionHead eyebrow="Contoh laporan" title="Seperti apa hasil audit" tone="text-ok" />
          <button
            type="button"
            onClick={handleCopy}
            className="px-4 py-2 rounded-xl text-sm font-semibold text-white bg-gradient-accent flex items-center gap-2"
          >
            {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
            {copied ? "Tersalin" : "Salin contoh"}
          </button>
        </div>
        <p className="text-sm text-muted">Data di bawah hanyalah contoh ilustrasi, bukan hasil scan domain Anda.</p>
        <div className="flex gap-1.5 overflow-x-auto thin-scroll snap-x pb-1">
          {(["ALL", "MEDIUM", "LOW", "INFO"] as const).map((s) => (
            <Chip key={s} active={severity === s} onClick={() => setSeverity(s)}>{s === "ALL" ? "Semua" : s}</Chip>
          ))}
        </div>
        <ul className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {findings.map((f) => (
            <li key={f.id} className={`${inset} p-4 space-y-1.5`}>
              <div className="flex items-center justify-between gap-2">
                <span className={`text-xs font-mono font-bold px-2 py-0.5 rounded ${SEV_STYLE[f.sev]}`}>{f.sev}</span>
                <span className="text-xs font-mono text-muted truncate">{f.path}</span>
              </div>
              <div className="text-sm font-bold">{f.module}</div>
              <p className="text-sm leading-relaxed text-muted">{f.detail}</p>
            </li>
          ))}
        </ul>
      </section>

      {/* ========================= KATALOG MODUL ========================= */}
      <section className={`${card} space-y-5`}>
        <SectionHead eyebrow="Katalog" title={`${SENTINEL_NAV_ITEMS.length} modul keamanan & SEO`} tone="text-sev-low" />
        <div className="flex gap-1.5 overflow-x-auto thin-scroll snap-x pb-1">
          {categories.map((c) => (
            <Chip key={c} active={moduleCategory === c} onClick={() => setModuleCategory(c)}>{c}</Chip>
          ))}
        </div>
        <ul className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3.5">
          {modules.map((m) => (
            <li key={m.id}>
              <Link
                href={m.route}
                className={`${inset} h-full p-4 flex flex-col gap-2.5 transition hover:border-accent/50 hover:-translate-y-0.5`}
              >
                <span className="flex items-center justify-between gap-2">
                  <span className="flex items-center gap-2.5 min-w-0">
                    <ModuleIcon name={m.iconName} className="w-5 h-5 text-accent shrink-0" />
                    <span className="text-sm font-bold truncate">{m.title}</span>
                  </span>
                  {m.badge && (
                    <span className={`text-xs font-mono font-semibold px-1.5 py-0.5 rounded shrink-0 ${BADGE_TONE[m.badgeTone ?? "pink"]}`}>
                      {m.badge}
                    </span>
                  )}
                </span>
                <span className="text-sm leading-relaxed text-muted">{m.description}</span>
              </Link>
            </li>
          ))}
        </ul>
      </section>

      {/* ============================== FAQ ============================== */}
      <section className={`${card} space-y-4`}>
        <div className="flex flex-wrap items-end justify-between gap-3">
          <SectionHead eyebrow="FAQ" title="Pertanyaan umum" tone="text-sev-low" />
          <div className="inline-flex p-1 rounded-xl glass-pill">
            {(["id", "en"] as const).map((l) => (
              <button
                key={l}
                type="button"
                onClick={() => setFaqLang(l)}
                aria-pressed={faqLang === l}
                className={`px-3.5 py-1.5 rounded-lg text-sm font-semibold ${faqLang === l ? "bg-gradient-accent text-white" : "text-muted"}`}
              >
                {l.toUpperCase()}
              </button>
            ))}
          </div>
        </div>
        <div className="space-y-2.5">
          {FAQ_DATA.map((item, idx) => {
            const open = openFaq === idx;
            return (
              <div key={item.q_id} className={`${inset} p-4`}>
                <button
                  type="button"
                  onClick={() => setOpenFaq(open ? null : idx)}
                  aria-expanded={open}
                  className="w-full flex items-center justify-between gap-3 text-left"
                >
                  <span className="text-sm sm:text-base font-semibold">{faqLang === "id" ? item.q_id : item.q_en}</span>
                  <ChevronDown className={`w-5 h-5 shrink-0 transition ${open ? "rotate-180 text-accent" : "text-muted"}`} />
                </button>
                {open && (
                  <p className="mt-3 pt-3 border-t border-border text-sm leading-relaxed text-muted">
                    {faqLang === "id" ? item.a_id : item.a_en}
                  </p>
                )}
              </div>
            );
          })}
        </div>
      </section>
    </div>
  );
}

export default HomePage;
