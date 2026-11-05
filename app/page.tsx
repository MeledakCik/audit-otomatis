import { Suspense } from "react";
import Link from "next/link";
import { ScanForm } from "@/components/scan-form";
import { VerifiedBadge } from "@/components/verified-badge";
import {
  Search,
  Code2,
  ShieldCheck,
  FileText,
  Lock,
  KeyRound,
  Map,
  Radar,
  Globe2,
  Fingerprint,
  UserSearch,
  TrafficConeIcon,
  ExternalLink,
  FileJson,
  ShellIcon,
  ClipboardCheck,
  ArrowUpRight,
  Sparkles,
  Activity,
  Terminal,
  Cpu,
  ShieldAlert,
} from "lucide-react";

export const maxDuration = 300;

const DEEP_SHELL_ENGINES = [
  {
    code: "wp2shell",
    title: "WordPress RCE & Config Surface",
    cwe: "CWE-434 · CWE-538 · CWE-284",
    desc: "Deteksi pasif wp-config.php.bak/~/.save, debug.log, xmlrpc.php aktif, enumerasi user REST API (/wp-json/wp/v2/users), installer terbuka, dan indeks /wp-content/uploads/.",
    targets: ["/wp-config.php.bak", "/wp-content/debug.log", "/xmlrpc.php", "/wp-json/wp/v2/users"],
  },
  {
    code: "php2shell",
    title: "PHP Eval, Ignition & Profiler",
    cwe: "CWE-94 · CWE-95 · CWE-489",
    desc: "Audit pasif Laravel Ignition debug RCE (CVE-2021-3129), PHPUnit eval-stdin.php (CVE-2017-9841), Symfony Profiler, phpinfo(), PHP-FPM status, dan eksposur composer.json.",
    targets: ["/_ignition/health-check", "/vendor/phpunit/.../eval-stdin.php", "/phpinfo.php", "/fpm-status"],
  },
  {
    code: "node2shell",
    title: "Node.js V8 Inspector & SSR Sinks",
    cwe: "CWE-94 · CWE-502 · CWE-1321",
    desc: "Deteksi port debug V8 Inspector (/json/version), PM2 ecosystem.config.js, Next.js dev stack-frame, serta sink AST child_process, vm.runInNewContext, deserialization & prototype pollution.",
    targets: ["/json/version", "/ecosystem.config.js", "child_process / vm", "__proto__ pollution"],
  },
  {
    code: "go2shell",
    title: "Go Runtime pprof & Expvar",
    cwe: "CWE-215 · CWE-200 · CWE-489",
    desc: "Inspeksi pasif profil runtime Go (/debug/pprof/), kebocoran argumen binary (/debug/pprof/cmdline), goroutine/heap dump, serta variabel runtime expvar (/debug/vars).",
    targets: ["/debug/pprof/", "/debug/pprof/cmdline", "/debug/vars", "Go panic trace"],
  },
  {
    code: "py2shell",
    title: "Python Werkzeug, Jupyter & Celery",
    cwe: "CWE-94 · CWE-306 · CWE-489",
    desc: "Deteksi Werkzeug/Flask interactive debugger (/console), Jupyter Notebook kernel API tanpa autentikasi (/api/kernels), Celery Flower monitor (/api/workers), dan Django Debug Toolbar.",
    targets: ["/console", "/api/kernels", "/api/workers", "/__debug__/"],
  },
  {
    code: "node out of bound",
    title: "Node Out-of-Bounds (OOB) & Memory",
    cwe: "CWE-119 · CWE-125 · CWE-787 · CWE-918",
    desc: "Deteksi snapshot memori V8 (/heapdump), alokasi Buffer.allocUnsafe & pembacaan TypedArray/DataView out-of-bounds, RangeError buffer leak, serta kandidat parameter Out-of-Band (OOB SSRF/Webhook).",
    targets: ["/heapdump", "Buffer.allocUnsafe", "TypedArray OOB", "OOB Callback/SSRF"],
  },
];

const QUICK_MODULES = [
  {
    title: "Sentinel Vault & Klaim",
    desc: "Audit File Sensitif (.env, .git/HEAD, backup.zip, wp-config.php.bak, AWS keys) & Brankas AES-256-GCM",
    href: "/scan/sentinel",
    icon: Lock,
    badge: "AES-256-GCM",
  },
  {
    title: "Header Armor",
    desc: "Skor & analisis HTTP security headers (CSP, HSTS, XFO)",
    href: "/scan/headers",
    icon: ShieldCheck,
    badge: "HTTP",
  },
  {
    title: "Secret Hunter",
    desc: "Deteksi API key, token & kredensial bocor di bundle JS",
    href: "/scan/secrets",
    icon: KeyRound,
    badge: "AST / Regex",
  },
  {
    title: "Attack Surface Map",
    desc: "Visualisasi graf interaktif relasi halaman, JS & endpoint",
    href: "/scan/map",
    icon: Map,
    badge: "Graph",
  },
  {
    title: "Subdomain Watch",
    desc: "Enumerasi CT logs crt.sh & deteksi risiko subdomain takeover",
    href: "/scan/subdomain",
    icon: Globe2,
    badge: "CT Logs",
  },
  {
    title: "DNS Intelligence",
    desc: "Audit record A/MX/TXT, proteksi anti-spoofing SPF & DMARC",
    href: "/scan/dns",
    icon: TrafficConeIcon,
    badge: "DoH",
  },
  {
    title: "SSL/TLS Inspector",
    desc: "Inspeksi rantai sertifikat, masa aktif, cipher & protokol TLS",
    href: "/scan/ssl",
    icon: ShellIcon,
    badge: "TLS",
  },
  {
    title: "JS Supply Chain",
    desc: "Deteksi library pihak ketiga usang, CVE & tracker skrip",
    href: "/scan/js",
    icon: FileJson,
    badge: "CVE DB",
  },
  {
    title: "Breach Peek & OSINT",
    desc: "Cek eksposur email/domain pada insiden kebocoran data publik",
    href: "/scan/breach",
    icon: Radar,
    badge: "OSINT",
  },
  {
    title: "Tech Stack Fingerprint",
    desc: "Identifikasi framework, CMS, CDN, WAF & server secara pasif",
    href: "/scan/stack",
    icon: Fingerprint,
    badge: "Stack",
  },
  {
    title: "Exposure Check",
    desc: "Verifikasi kebocoran file konfigurasi, shell surface & informasi sensitif",
    href: "/scan/exposure",
    icon: ExternalLink,
    badge: "Passive",
  },
  {
    title: "OSINT Lookup",
    desc: "Reconnaissance multi-sumber untuk domain, email & username",
    href: "/scan/osint",
    icon: UserSearch,
    badge: "Recon",
  },
  {
    title: "QC Otomatis",
    desc: "Audit kualitas SEO on-page, performa PageSpeed & broken link",
    href: "/qc",
    icon: ClipboardCheck,
    badge: "SEO + Perf",
  },
];

export default function Home() {
  return (
    <div className="w-full min-h-full">
      <div className="mx-auto max-w-6xl px-5 sm:px-6 lg:px-8 py-8 lg:py-12 space-y-12">
        {/* Hero & Integrated Scan Launchpad */}
        <div className="grid grid-cols-1 lg:grid-cols-[1.08fr_0.92fr] gap-8 lg:gap-10 items-start">
          {/* Left Hero Column */}
          <div className="space-y-6 pt-1">
            <div className="flex flex-wrap items-center gap-2.5">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-purple-500/15 border border-purple-500/30 text-xs font-mono tracking-wider uppercase text-purple-300">
                <span className="h-2 w-2 rounded-full bg-purple-400 animate-pulse" />
                SENTINEL-ID PASSIVE AUDITOR v3.5
              </div>
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-white/[0.04] border border-white/10 text-xs font-mono text-slate-300">
                <Lock className="h-3 w-3 text-pink-400" />
                AES-256-GCM Vault Integrated
              </span>
            </div>

            <div className="space-y-4">
              <h1 className="text-3xl sm:text-4xl lg:text-5xl font-extrabold leading-[1.12] tracking-tight text-white">
                Platform Audit Keamanan Web{" "}
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-fuchsia-400 to-pink-400">
                  Pasif, Mendalam &amp; Terpadu
                </span>
              </h1>
              <p className="text-sm sm:text-base leading-relaxed text-slate-300/90 max-w-xl">
                Analisis postur keamanan domain secara mendalam tanpa risiko merusak server. Menggabungkan{" "}
                <strong className="text-white">Multi-Page Crawler</strong>,{" "}
                <strong className="text-white">Deep Shell &amp; OOB Engine</strong> (
                <code className="text-purple-300">wp2shell</code>, <code className="text-purple-300">php2shell</code>,{" "}
                <code className="text-purple-300">node2shell</code>, <code className="text-purple-300">go2shell</code>,{" "}
                <code className="text-purple-300">py2shell</code>, <code className="text-purple-300">node out of bound</code>
                ), dan <strong className="text-white">Brankas Bukti Terenkripsi (AES-256-GCM)</strong>.
              </p>
            </div>

            {/* Official Google Developer Bandung Verification Card */}
            <div className="pt-1">
              <VerifiedBadge variant="hero" />
            </div>

            {/* Highlighted Box: Audit File Sensitif & Brankas Bukti Terenkripsi (AES-256-GCM) */}
            <div className="rounded-2xl border border-purple-500/35 bg-gradient-to-r from-purple-950/40 via-[#150f24] to-pink-950/30 p-4 sm:p-5 space-y-2.5 shadow-lg">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="inline-flex items-center gap-2 text-xs font-mono font-bold text-purple-300">
                  <Lock className="h-4 w-4 text-pink-400" />
                  <span>PROTEKSI BUKTI KRITIS &amp; KLAIM DOMAIN SAH</span>
                </div>
                <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 border border-emerald-500/35 px-2.5 py-0.5 text-[10px] font-mono font-bold text-emerald-300">
                  ✓ Sudah Terverifikasi oleh Google Developer Bandung
                </span>
              </div>
              <h2 className="text-base sm:text-lg font-extrabold text-white">
                Audit File Sensitif &amp; Brankas Bukti Terenkripsi (AES-256-GCM)
              </h2>
              <p className="text-xs sm:text-sm text-slate-200/90 leading-relaxed">
                Mendeteksi kebocoran kritis (<code className="text-purple-300 font-semibold">.env</code>,{" "}
                <code className="text-purple-300 font-semibold">.git/HEAD</code>,{" "}
                <code className="text-purple-300 font-semibold">backup.zip</code>,{" "}
                <code className="text-purple-300 font-semibold">wp-config.php.bak</code>,{" "}
                <code className="text-purple-300 font-semibold">AWS keys</code>) secara pasif. Nilai rahasia tidak pernah bocor ke publik dan disimpan terenkripsi di Vault Admin untuk diklaim pemilik sah domain.
              </p>
              <div className="flex flex-wrap items-center gap-2 pt-1">
                <Link
                  href="/scan/sentinel"
                  className="inline-flex items-center gap-1.5 rounded-xl bg-purple-600/30 hover:bg-purple-600/45 border border-purple-400/40 px-3.5 py-1.5 text-xs font-mono font-bold text-purple-100 transition-colors"
                >
                  <span>Buka Brankas Bukti &amp; Klaim Domain</span>
                  <ArrowUpRight className="h-3.5 w-3.5" />
                </Link>
              </div>
            </div>

            {/* Key Capabilities Pills */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-1">
              {[
                { label: "Deep Crawl", sub: "Max 50 URL · Depth 3", icon: Search },
                { label: "Shell & OOB Check", sub: "wp/php/node/go/py", icon: Terminal },
                { label: "Sentinel Vault", sub: "AES-256-GCM + Klaim", icon: Lock },
                { label: "Laporan & Export", sub: "Markdown & Graph", icon: FileText },
              ].map((item) => (
                <div
                  key={item.label}
                  className="rounded-xl border border-white/[0.08] bg-[#120d1d]/90 p-3 hover:border-purple-500/35 transition-all"
                >
                  <item.icon className="h-4 w-4 text-purple-400 mb-1.5" />
                  <div className="text-xs font-bold text-white">{item.label}</div>
                  <div className="text-[11px] font-mono text-slate-400 mt-0.5">{item.sub}</div>
                </div>
              ))}
            </div>

            {/* Security Guarantees Bar */}
            <div className="flex flex-wrap items-center gap-3 text-xs font-mono text-slate-300 bg-white/[0.02] border border-white/[0.07] px-4 py-3 rounded-xl">
              <span className="inline-flex items-center gap-1.5 text-emerald-400 font-semibold">
                <Activity className="h-3.5 w-3.5" />
                100% Non-Intrusif
              </span>
              <span className="text-white/20">•</span>
              <span>GET-Only</span>
              <span className="text-white/20">•</span>
              <span>SSRF Guard</span>
              <span className="text-white/20">•</span>
              <span>Terverifikasi Google Developer Bandung</span>
            </div>
          </div>

          {/* Right Column: Unified Scan & Sentinel Vault Card */}
          <div className="relative rounded-2xl border border-purple-500/25 bg-gradient-to-b from-[#171126] via-[#120d1e] to-[#0e0a18] p-5 sm:p-6 shadow-2xl shadow-purple-950/30">
            <div className="mb-4 flex items-center justify-between gap-2">
              <div>
                <div className="text-xs font-mono tracking-widest uppercase text-purple-300 font-bold flex items-center gap-1.5">
                  <Sparkles className="h-3.5 w-3.5 text-purple-400" />
                  Unified Deep Security Scanner
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Pilih Full Scan komprehensif atau Audit File Sensitif &amp; Brankas Bukti Terenkripsi (AES-256-GCM)
                </p>
              </div>
            </div>

            <Suspense fallback={<div className="h-64 animate-pulse rounded-xl bg-white/5" />}>
              <ScanForm />
            </Suspense>
          </div>
        </div>

        {/* Deep Shell-Surface & Node Out-of-Bounds Security Matrix */}
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <div className="inline-flex items-center gap-1.5 text-xs font-mono uppercase tracking-wider text-pink-400 font-bold mb-1">
                <Cpu className="h-3.5 w-3.5" />
                DEEP PASSIVE RUNTIME &amp; SHELL-SURFACE ENGINE
              </div>
              <h2 className="text-lg sm:text-xl font-extrabold text-white tracking-tight">
                Deteksi Mendalam: wp2shell, php2shell, node2shell, go2shell, py2shell &amp; Node Out-of-Bounds
              </h2>
              <p className="text-xs text-slate-400 mt-0.5">
                Memeriksa titik masuk eksekusi kode, debugger terbuka, dan kebocoran memori secara 100% pasif (GET-only, validasi isi respons)
              </p>
            </div>
            <VerifiedBadge variant="vault" />
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {DEEP_SHELL_ENGINES.map((eng) => (
              <div
                key={eng.code}
                className="flex flex-col justify-between rounded-2xl border border-white/[0.08] bg-gradient-to-b from-[#161024] to-[#0f0b19] p-5 hover:border-purple-500/40 transition-all"
              >
                <div className="space-y-2.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="inline-flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-purple-500/20 to-pink-500/20 border border-purple-400/35 px-2.5 py-1 text-xs font-mono font-extrabold uppercase text-pink-200">
                      <ShieldAlert className="h-3.5 w-3.5 text-pink-400" />
                      {eng.code}
                    </span>
                    <span className="text-[10px] font-mono text-slate-400">{eng.cwe}</span>
                  </div>
                  <h3 className="text-sm font-bold text-white">{eng.title}</h3>
                  <p className="text-xs text-slate-400 leading-relaxed">{eng.desc}</p>
                </div>

                <div className="mt-4 pt-3 border-t border-white/[0.06] flex flex-wrap gap-1.5">
                  {eng.targets.map((t) => (
                    <code
                      key={t}
                      className="rounded-md bg-black/40 border border-white/[0.07] px-2 py-0.5 text-[10px] font-mono text-purple-300"
                    >
                      {t}
                    </code>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* 4-Step Workflow Pipeline */}
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-lg font-extrabold text-white tracking-tight">
                Alur Kerja Audit File Sensitif &amp; Brankas Bukti Terenkripsi (AES-256-GCM)
              </h2>
              <p className="text-xs text-slate-400">
                Dirancang untuk menjaga kerahasiaan temuan kritis hingga pemilik sah domain terverifikasi — Sudah Terverifikasi oleh Google Developer Bandung
              </p>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              {
                n: "01",
                t: "Crawl & Recon Pasif",
                d: "Menelusuri tautan internal, form, well-known files, dan header HTTP dengan metode GET-only.",
                icon: Search,
              },
              {
                n: "02",
                t: "Deep Shell & OOB Audit",
                d: "Mendeteksi permukaan wp2shell, php2shell, node2shell, go2shell, py2shell, dan Node Out-of-Bounds secara pasif.",
                icon: Code2,
              },
              {
                n: "03",
                t: "Brankas Bukti AES-256-GCM",
                d: "Kebocoran kritis (.env, .git/HEAD, backup.zip, wp-config.php.bak, AWS keys) dienkripsi ke Vault Admin tanpa bocor ke publik.",
                icon: Lock,
              },
              {
                n: "04",
                t: "Klaim Pemilik Sah Domain",
                d: "Pemilik sah domain memverifikasi DNS TXT / file HTTP untuk membuka bukti 1x lihat & mengunduh laporan.",
                icon: FileText,
              },
            ].map((c) => (
              <div
                key={c.n}
                className="flex flex-col justify-between rounded-2xl border border-white/[0.08] bg-gradient-to-b from-[#151022] to-[#100c1a] p-5 hover:border-purple-500/40 transition-all group"
              >
                <div className="flex items-start justify-between">
                  <span className="inline-flex items-center justify-center rounded-lg bg-purple-500/15 border border-purple-500/30 px-2.5 py-1 text-xs font-mono font-bold text-purple-300">
                    STEP {c.n}
                  </span>
                  <c.icon className="h-4 w-4 text-slate-400 group-hover:text-purple-300 transition-colors" />
                </div>
                <div className="mt-4">
                  <div className="text-sm font-bold text-white">{c.t}</div>
                  <div className="text-xs text-slate-400 mt-1.5 leading-relaxed">{c.d}</div>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Complete Suite of Specialized Security Scanners */}
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-lg font-extrabold text-white tracking-tight">
                Modul Spesialis Keamanan &amp; Intelijen Siber
              </h2>
              <p className="text-xs text-slate-400">
                Seluruh modul terintegrasi langsung dengan pusat monitoring aktivitas Admin &amp; Brankas AES-256-GCM
              </p>
            </div>
            <Link
              href="/history"
              className="inline-flex items-center gap-1.5 text-xs font-mono text-purple-300 hover:text-purple-200"
            >
              <span>Lihat Riwayat Scan</span>
              <ArrowUpRight className="h-3.5 w-3.5" />
            </Link>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
            {QUICK_MODULES.map((m) => {
              const Icon = m.icon;
              return (
                <Link
                  key={m.href}
                  href={m.href}
                  className="group flex flex-col justify-between rounded-2xl border border-white/[0.07] bg-[#120d1d]/90 p-4 hover:bg-[#171126] hover:border-purple-500/35 transition-all"
                >
                  <div>
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2.5">
                        <div className="h-9 w-9 rounded-xl bg-purple-500/10 border border-purple-500/20 grid place-items-center text-purple-300 group-hover:bg-purple-500/20 group-hover:text-white transition-colors">
                          <Icon className="h-4 w-4" />
                        </div>
                        <span className="text-sm font-bold text-white group-hover:text-purple-200 transition-colors">
                          {m.title}
                        </span>
                      </div>
                      <span className="rounded-full bg-white/[0.04] border border-white/10 px-2.5 py-0.5 text-[10px] font-mono text-slate-300">
                        {m.badge}
                      </span>
                    </div>
                    <p className="mt-2.5 text-xs text-slate-400 leading-relaxed">{m.desc}</p>
                  </div>
                  <div className="mt-3 pt-2.5 border-t border-white/[0.05] flex items-center justify-between text-[11px] font-mono text-purple-300/80 group-hover:text-purple-300">
                    <span>Buka Modul</span>
                    <ArrowUpRight className="h-3.5 w-3.5 transition-transform group-hover:translate-x-0.5 group-hover:-translate-y-0.5" />
                  </div>
                </Link>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
