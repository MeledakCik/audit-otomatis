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
} from "lucide-react";

export const maxDuration = 300;

const QUICK_MODULES = [
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
    desc: "Verifikasi kebocoran file konfigurasi & informasi sensitif",
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
                SENTINEL-ID PASSIVE AUDITOR v3.2
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
                  Pasif &amp; Terpadu
                </span>
              </h1>
              <p className="text-sm sm:text-base leading-relaxed text-slate-300/90 max-w-xl">
                Analisis postur keamanan domain Anda secara instan tanpa risiko merusak server. Menggabungkan{" "}
                <strong className="text-white">Multi-Page Crawler</strong>,{" "}
                <strong className="text-white">AST JS Analyzer</strong>, dan{" "}
                <strong className="text-white">Sentinel Encrypted Vault</strong> dalam satu pusat komando.
              </p>
            </div>

            {/* Official Google Developer Bandung Verification Card */}
            <div className="pt-1">
              <VerifiedBadge variant="hero" />
            </div>

            {/* Key Capabilities Pills */}
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 pt-2">
              {[
                { label: "Deep Crawl", sub: "Max 50 URL · Depth 3", icon: Search },
                { label: "AST JS Engine", sub: "Endpoint & Secret", icon: Code2 },
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
              <span>Semua aktivitas tercatat di Admin Telemetry</span>
            </div>
          </div>

          {/* Right Column: Unified Scan & Sentinel Vault Card */}
          <div className="relative rounded-2xl border border-purple-500/25 bg-gradient-to-b from-[#171126] via-[#120d1e] to-[#0e0a18] p-5 sm:p-6 shadow-2xl shadow-purple-950/30">
            <div className="mb-4 flex items-center justify-between">
              <div>
                <div className="text-xs font-mono tracking-widest uppercase text-purple-300 font-bold flex items-center gap-1.5">
                  <Sparkles className="h-3.5 w-3.5 text-purple-400" />
                  Unified Security Scanner
                </div>
                <p className="text-xs text-slate-400 mt-0.5">
                  Pilih Full Scan komprehensif atau audit cepat Sentinel Vault &amp; Klaim Domain
                </p>
              </div>
            </div>

            <Suspense fallback={<div className="h-64 animate-pulse rounded-xl bg-white/5" />}>
              <ScanForm />
            </Suspense>
          </div>
        </div>

        {/* 4-Step Workflow Pipeline */}
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-lg font-extrabold text-white tracking-tight">
                Alur Kerja Audit Pasif &amp; Proteksi Bukti (Sentinel Vault)
              </h2>
              <p className="text-xs text-slate-400">
                Dirancang untuk menjaga kerahasiaan temuan kritis hingga pemilik domain terverifikasi
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
                t: "AST JS & Secret Scan",
                d: "Membedah bundle JavaScript menggunakan Acorn AST untuk memetakan API endpoint & mendeteksi secret.",
                icon: Code2,
              },
              {
                n: "03",
                t: "Sentinel Encrypted Vault",
                d: "Temuan CRITICAL (.env, .git, backup) dienkripsi AES-256-GCM ke Vault Admin tanpa membocorkan isi ke publik.",
                icon: Lock,
              },
              {
                n: "04",
                t: "Klaim Domain & Laporan",
                d: "Pemilik domain memverifikasi DNS TXT / file HTTP untuk membuka bukti 1x lihat & mengunduh laporan.",
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

        {/* Complete Suite of 12 Specialized Security Scanners */}
        <div className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-lg font-extrabold text-white tracking-tight">
                Modul Spesialis Keamanan &amp; Intelijen Siber
              </h2>
              <p className="text-xs text-slate-400">
                Seluruh modul terintegrasi langsung dengan pusat monitoring aktivitas Admin
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
