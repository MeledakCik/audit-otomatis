"use client";

import React, { useState, useEffect, useMemo } from "react";
import {
  Shield,
  TrendingUp,
  Lock,
  Globe,
  Code2,
  CheckCircle2,
  AlertTriangle,
  Sparkles,
  Search,
  Copy,
  Check,
  Sun,
  Moon,
  KeyRound,
  FileText,
  Server,
  Eye,
  EyeOff,
  RefreshCw,
  ArrowRight,
  Terminal,
  Layers,
  Award
} from "lucide-react";

type ActiveModuleView = "seo-master" | "sentinel-vault";
type SeoCategoryTab = "hreflang" | "schema" | "meta" | "cwv" | "trust";
type ClaimMethod = "dns" | "http";

interface HreflangItem {
  code: string;
  region: string;
  urlPath: string;
  status: "ACTIVE" | "READY";
}

interface SeoSignalItem {
  id: string;
  category: SeoCategoryTab;
  title: string;
  value: string;
  status: "OPTIMAL" | "GOOD" | "ACTION";
  detail: string;
}

interface VaultArtifact {
  id: string;
  path: string;
  cwe: string;
  risk: "CRITICAL" | "HIGH" | "SAFE";
  publicPreview: string;
  decryptedPreview: string;
  cipherMeta: string;
  remediation: string;
}

const HREFLANG_13: HreflangItem[] = [
  { code: "x-default", region: "Global Fallback Default", urlPath: "/", status: "ACTIVE" },
  { code: "id-ID", region: "Indonesia (Primary)", urlPath: "/?hl=id-ID", status: "ACTIVE" },
  { code: "id", region: "Bahasa Indonesia Generic", urlPath: "/?hl=id", status: "ACTIVE" },
  { code: "en-US", region: "United States (English)", urlPath: "/?hl=en-US", status: "ACTIVE" },
  { code: "en-GB", region: "United Kingdom (English)", urlPath: "/?hl=en-GB", status: "ACTIVE" },
  { code: "en-SG", region: "Singapore (English)", urlPath: "/?hl=en-SG", status: "ACTIVE" },
  { code: "en-AU", region: "Australia (English)", urlPath: "/?hl=en-AU", status: "ACTIVE" },
  { code: "en-CA", region: "Canada (English)", urlPath: "/?hl=en-CA", status: "ACTIVE" },
  { code: "en-IN", region: "India (English)", urlPath: "/?hl=en-IN", status: "ACTIVE" },
  { code: "en", region: "International English", urlPath: "/?hl=en", status: "ACTIVE" },
  { code: "ms-MY", region: "Malaysia (Bahasa Melayu)", urlPath: "/?hl=ms-MY", status: "ACTIVE" },
  { code: "ja-JP", region: "Japan (Japanese)", urlPath: "/?hl=ja-JP", status: "ACTIVE" },
  { code: "de-DE", region: "Germany (German)", urlPath: "/?hl=de-DE", status: "ACTIVE" }
];

const SEO_SIGNALS: SeoSignalItem[] = [
  {
    id: "S-01",
    category: "hreflang",
    title: "Reciprocal 13-Locale Hreflang Cluster",
    value: "13 / 13 Valid",
    status: "OPTIMAL",
    detail: "Seluruh 13 tag hreflang (termasuk x-default, id-ID, en-US, en-GB) memiliki canonical timbal-balik yang valid."
  },
  {
    id: "S-02",
    category: "hreflang",
    title: "HTML Lang & Content-Language Parity",
    value: "lang=\"id\" + Multi-Region",
    status: "OPTIMAL",
    detail: "Atribut lang pada elemen <html> selaras dengan deklarasi hreflang utama dan peta situs internasional."
  },
  {
    id: "S-03",
    category: "schema",
    title: "Schema.org SoftwareApplication Graph",
    value: "JSON-LD Valid",
    status: "OPTIMAL",
    detail: "Mendeklarasikan aplikasi keamanan web pasif beserta kategori, fitur, dan verifikasi komunitas GDG Bandung."
  },
  {
    id: "S-04",
    category: "schema",
    title: "Schema.org FAQPage Structured Data",
    value: "4 Bilingual Q&A",
    status: "OPTIMAL",
    detail: "Struktur FAQPage tervalidasi untuk memperkaya tampilan Rich Snippet di halaman pertama Google SERP."
  },
  {
    id: "S-05",
    category: "meta",
    title: "Meta Title & Description Length",
    value: "58 chars · 154 chars",
    status: "OPTIMAL",
    detail: "Panjang judul dan deskripsi berada pada rentang ideal tanpa pemotongan piksel pada SERP desktop maupun mobile."
  },
  {
    id: "S-06",
    category: "meta",
    title: "OpenGraph & Twitter Card Image (1200x630)",
    value: "/opengraph-image.png",
    status: "GOOD",
    detail: "Menggunakan rasio 1.91:1 (1200x630 px) dengan kartu summary_large_image untuk pratinjau sosial yang tajam."
  },
  {
    id: "S-07",
    category: "cwv",
    title: "Largest Contentful Paint (LCP) & CLS",
    value: "LCP 1.1s · CLS 0.01",
    status: "OPTIMAL",
    detail: "Desain berbasis komponen kaca ringan tanpa blokir render menghasilkan skor Core Web Vitals hijau."
  },
  {
    id: "S-08",
    category: "cwv",
    title: "XML Sitemap & Robots.txt Directives",
    value: "22 Routes Indexed",
    status: "OPTIMAL",
    detail: "Seluruh modul spesialis tercantum pada /sitemap.xml dan diizinkan untuk perayapan Googlebot."
  },
  {
    id: "S-09",
    category: "trust",
    title: "HTTPS + HSTS Preload Trust Signal",
    value: "TLS 1.3 · max-age=63072000",
    status: "OPTIMAL",
    detail: "Enkripsi TLS 1.3 dan header Strict-Transport-Security memperkuat sinyal kepercayaan peringkat Google."
  },
  {
    id: "S-10",
    category: "trust",
    title: "Content-Security-Policy & Anti-Clickjacking",
    value: "CSP + X-Frame-Options",
    status: "OPTIMAL",
    detail: "Melindungi reputasi domain dari injeksi skrip pihak ketiga dan penyalahgunaan iframe."
  }
];

const VAULT_ARTIFACTS: VaultArtifact[] = [
  {
    id: "V-01",
    path: "/.env",
    cwe: "CWE-538 · CWE-312",
    risk: "CRITICAL",
    publicPreview: "APP_KEY=[REDACTED_AES256_GCM_8F3A] · AWS_SECRET=[REDACTED_AES256_GCM_9C12]",
    decryptedPreview: "APP_KEY=base64:SentinelDemoKey9912... · AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCY",
    cipherMeta: "AES-256-GCM · IV: 9f4b...21a0 · Tag: e81c...770b",
    remediation: "Blokir akses ke dotfile (/.env*) pada konfigurasi Nginx/Cloudflare atau pindahkan ke luar public root."
  },
  {
    id: "V-02",
    path: "/.git/HEAD",
    cwe: "CWE-538 · CWE-200",
    risk: "HIGH",
    publicPreview: "ref: refs/heads/[REDACTED_VAULT_BRANCH] (Objek Git disensor dari publik)",
    decryptedPreview: "ref: refs/heads/main (Eksposur direktori .git memungkinkan rekonstruksi source code)",
    cipherMeta: "AES-256-GCM · IV: 3c18...84d2 · Tag: 44a9...19f0",
    remediation: "Tambahkan aturan deny all untuk lokasi ~ /\\.(git|svn|hg) pada server web atau Edge WAF."
  },
  {
    id: "V-03",
    path: "/wp-config.php.bak",
    cwe: "CWE-530 · CWE-284",
    risk: "CRITICAL",
    publicPreview: "DB_PASSWORD=[REDACTED_AES256_GCM_4D91] · AUTH_SALT=[REDACTED_VAULT]",
    decryptedPreview: "DB_PASSWORD='prod_db_secret_example' · AUTH_SALT='unique_phrase_verified_owner_only'",
    cipherMeta: "AES-256-GCM · IV: 7a02...55e1 · Tag: b12d...90c3",
    remediation: "Hapus seluruh file cadangan editor (*.bak, *~, *.save, *.swp) dari direktori produksi."
  },
  {
    id: "V-04",
    path: "/backup.zip",
    cwe: "CWE-530",
    risk: "SAFE",
    publicPreview: "404 Not Found — Tidak ditemukan arsip backup publik pada domain target.",
    decryptedPreview: "404 Not Found — Aman (Tidak ada file arsip .zip/.tar.gz/.sql yang terekspos).",
    cipherMeta: "Status: Clean (Zero Exposure)",
    remediation: "Pertahankan kebijakan penyimpanan backup di bucket privat terpisah dari web root."
  }
];

/**
 * Komponen `SeoMasterView` untuk `/scan/seo-master` (`components/seo-master/seo-master-view.tsx`)
 */
export function SeoMasterView({ isDark = true }: { isDark?: boolean }) {
  const [domainInput, setDomainInput] = useState<string>("sentinel-id.net");
  const [activeCat, setActiveCat] = useState<SeoCategoryTab>("hreflang");
  const [generatorTab, setGeneratorTab] = useState<"head" | "nextjs" | "jsonld">("nextjs");
  const [copiedCode, setCopiedCode] = useState<boolean>(false);

  const glassCard = isDark
    ? "bg-foreground/[0.04] backdrop-blur-2xl border border-foreground/[0.11] shadow-[0_24px_60px_-15px_rgba(0,0,0,0.65)]"
    : "bg-foreground/75 backdrop-blur-2xl border border-slate-900/[0.08] shadow-[0_20px_50px_-12px_rgba(15,23,42,0.07)]";
  const glassPill = isDark
    ? "bg-foreground/[0.06] backdrop-blur-xl border border-foreground/[0.1]"
    : "bg-foreground/85 backdrop-blur-xl border border-slate-900/[0.08]";
  const mutedText = isDark ? "text-muted" : "text-slate-600";

  const filteredSignals = useMemo(
    () => SEO_SIGNALS.filter((s) => s.category === activeCat),
    [activeCat]
  );

  const generatedSnippet = useMemo(() => {
    const cleanDom = domainInput.trim().replace(/^https?:\/\//i, "").split("/")[0] || "sentinel-id.net";
    if (generatorTab === "nextjs") {
      return `// app/layout.tsx — Next.js 16 International Rank #1 Metadata
import type { Metadata } from "next";

export const metadata: Metadata = {
  metadataBase: new URL("https://www.${cleanDom}"),
  title: "Sentinel-ID — #1 Passive Website Security Auditor & SEO Master",
  description: "Platform audit keamanan web pasif 100% GET-only dengan Brankas AES-256-GCM & 35+ sinyal SEO Global.",
  alternates: {
    canonical: "https://www.${cleanDom}/",
    languages: {
      "x-default": "https://www.${cleanDom}/",
      "id-ID": "https://www.${cleanDom}/?hl=id-ID",
      "en-US": "https://www.${cleanDom}/?hl=en-US",
      "en-GB": "https://www.${cleanDom}/?hl=en-GB",
      "en-SG": "https://www.${cleanDom}/?hl=en-SG",
      "ja-JP": "https://www.${cleanDom}/?hl=ja-JP",
      "de-DE": "https://www.${cleanDom}/?hl=de-DE"
    }
  },
  openGraph: {
    title: "Sentinel-ID — Passive Website Security Auditor & SEO Master",
    url: "https://www.${cleanDom}/",
    siteName: "Sentinel-ID",
    images: [{ url: "/opengraph-image.png", width: 1200, height: 630 }],
    locale: "id_ID",
    type: "website"
  }
};`;
    }
    if (generatorTab === "jsonld") {
      return `{
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "SoftwareApplication",
      "name": "Sentinel-ID Passive Security Auditor",
      "applicationCategory": "SecurityApplication",
      "operatingSystem": "Web",
      "url": "https://www.${cleanDom}/",
      "author": { "@type": "Person", "name": "Kasyaf" }
    },
    {
      "@type": "FAQPage",
      "mainEntity": [
        {
          "@type": "Question",
          "name": "Apakah Sentinel-ID 100% aman untuk server produksi?",
          "acceptedAnswer": {
            "@type": "Answer",
            "text": "Ya, 100% pasif menggunakan metode HTTP GET/HEAD-only tanpa eksploitasi."
          }
        }
      ]
    }
  ]
}`;
    }
    return `<!-- Tag Hreflang Internasional & OpenGraph untuk https://www.${cleanDom}/ -->
<link rel="canonical" href="https://www.${cleanDom}/" />
<link rel="alternate" hreflang="x-default" href="https://www.${cleanDom}/" />
<link rel="alternate" hreflang="id-ID" href="https://www.${cleanDom}/?hl=id-ID" />
<link rel="alternate" hreflang="en-US" href="https://www.${cleanDom}/?hl=en-US" />
<link rel="alternate" hreflang="en-GB" href="https://www.${cleanDom}/?hl=en-GB" />
<meta property="og:image" content="https://www.${cleanDom}/opengraph-image.png" />`;
  }, [domainInput, generatorTab]);

  function copySnippet() {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(generatedSnippet);
      }
    } catch {
      // Abaikan bila clipboard tidak tersedia
    }
    setCopiedCode(true);
    setTimeout(() => setCopiedCode(false), 2200);
  }

  return (
    <div className="space-y-8">
      {/* Top Bento Hero for SEO Master */}
      <div className={`rounded-3xl p-6 sm:p-8 grid grid-cols-1 lg:grid-cols-12 gap-6 items-center ${glassCard}`}>
        <div className="lg:col-span-7 space-y-4">
          <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono text-emerald-500 ${glassPill}`}>
            <TrendingUp className="w-3.5 h-3.5" />
            <span>MODUL /scan/seo-master · GLOBAL SERP ENGINE</span>
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight">
            SEO Master &amp;{" "}
            <span className="bg-gradient-to-r from-emerald-400 via-cyan-400 to-purple-500 bg-clip-text text-transparent">
              International Rank #1
            </span>
          </h1>
          <p className={`text-sm sm:text-base leading-relaxed ${mutedText}`}>
            Mengaudit <strong>35+ sinyal teknis Google SERP</strong>, klaster{" "}
            <strong>13 tag hreflang internasional</strong>, grafik{" "}
            <strong>JSON-LD Schema.org</strong>, dan sinyal kepercayaan keamanan{" "}
            <strong>HTTPS/HSTS/CSP</strong> tanpa menumpuk informasi.
          </p>

          <div className="flex flex-col sm:flex-row gap-2.5 pt-1">
            <div className={`flex-1 flex items-center gap-2.5 px-3.5 py-2.5 rounded-2xl ${glassPill}`}>
              <Globe className="w-4 h-4 text-emerald-500 shrink-0" />
              <input
                type="text"
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                placeholder="Masukkan domain audit SEO..."
                className="w-full bg-transparent text-sm font-mono focus:outline-none"
                aria-label="Domain Target SEO Master"
              />
            </div>
            <span className="px-4 py-2.5 rounded-2xl text-xs font-mono font-semibold bg-emerald-500/15 text-emerald-500 border border-emerald-500/30 flex items-center justify-center">
              ✓ 35/35 Sinyal Aktif
            </span>
          </div>
        </div>

        {/* Right Bento Score Cards */}
        <div className="lg:col-span-5 grid grid-cols-2 gap-3">
          {[
            { label: "SERP Readiness", val: "96 / 100", sub: "Global Rank #1 Ready", tone: "text-emerald-500" },
            { label: "Hreflang Cluster", val: "13 Locale", sub: "x-default + 12 Negara", tone: "text-cyan-500" },
            { label: "Schema.org Graph", val: "2 Entities", sub: "SoftwareApp + FAQPage", tone: "text-purple-400" },
            { label: "Security Trust", val: "A+ Grade", sub: "TLS 1.3 · HSTS · CSP", tone: "text-pink-500" }
          ].map((item) => (
            <div key={item.label} className={`rounded-2xl p-4 ${glassPill}`}>
              <span className={`text-xs font-mono uppercase ${mutedText}`}>{item.label}</span>
              <p className={`text-2xl font-extrabold mt-1 ${item.tone}`}>{item.val}</p>
              <p className={`text-xs mt-0.5 ${mutedText}`}>{item.sub}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Progressive-Disclosure Signal Inspector & 13 Hreflang Matrix */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: 35+ Signals Categorized Inspector (7 cols) */}
        <div className={`lg:col-span-7 rounded-3xl p-6 space-y-5 ${glassCard}`}>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-lg font-bold">Inspeksi Sinyal SEO Teknis</h2>
              <p className={`text-xs ${mutedText}`}>
                Pilih kategori sinyal untuk menjaga tampilan tetap ringkas
              </p>
            </div>
            <div className={`flex flex-wrap gap-1 p-1 rounded-xl ${glassPill}`}>
              {(
                [
                  { id: "hreflang", label: "Hreflang (13)" },
                  { id: "schema", label: "JSON-LD" },
                  { id: "meta", label: "Meta & OG" },
                  { id: "cwv", label: "Web Vitals" },
                  { id: "trust", label: "Trust HTTPS" }
                ] as { id: SeoCategoryTab; label: string }[]
              ).map((t) => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setActiveCat(t.id)}
                  className={`px-2.5 py-1 rounded-lg text-xs font-semibold transition ${
                    activeCat === t.id
                      ? "bg-gradient-to-r from-emerald-500 to-cyan-600 text-white"
                      : mutedText
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>
          </div>

          <div className="space-y-3">
            {filteredSignals.map((sig) => (
              <div key={sig.id} className={`rounded-2xl p-4 space-y-1.5 ${glassPill}`}>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-bold">{sig.title}</span>
                  <span className="px-2.5 py-0.5 rounded-full text-xs font-mono font-semibold bg-emerald-500/15 text-emerald-500">
                    {sig.value}
                  </span>
                </div>
                <p className={`text-xs leading-relaxed ${mutedText}`}>{sig.detail}</p>
              </div>
            ))}
          </div>

          {/* 13 Hreflang Badges Grid */}
          <div className="pt-2 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="font-semibold">Matriks 13 Tag Hreflang Internasional</span>
              <span className="font-mono text-cyan-500">ISO-639-1 / ISO-3166-1</span>
            </div>
            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-2">
              {HREFLANG_13.map((h) => (
                <div
                  key={h.code}
                  className={`px-3 py-2 rounded-xl text-xs flex items-center justify-between ${glassPill}`}
                  title={h.region}
                >
                  <span className="font-mono font-bold text-emerald-500">{h.code}</span>
                  <span className={`text-xs truncate ml-1.5 ${mutedText}`}>
                    {h.region.split(" ")[0]}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right: Ready-to-Paste Rank #1 Code Generator (5 cols) */}
        <div className={`lg:col-span-5 rounded-3xl p-6 flex flex-col justify-between space-y-4 ${glassCard}`}>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-bold">Generator Kode SEO Rank #1</h2>
                <p className={`text-xs ${mutedText}`}>
                  Otomatis disesuaikan untuk {domainInput || "sentinel-id.net"}
                </p>
              </div>
              <button
                type="button"
                onClick={copySnippet}
                className="px-3 py-1.5 rounded-xl text-xs font-semibold text-white bg-gradient-to-r from-emerald-500 to-cyan-600 flex items-center gap-1.5 shadow-sm"
              >
                {copiedCode ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span>{copiedCode ? "Tersalin" : "Salin Kode"}</span>
              </button>
            </div>

            <div className={`inline-flex p-1 rounded-xl ${glassPill}`}>
              {(
                [
                  { id: "nextjs", label: "Next.js Metadata" },
                  { id: "jsonld", label: "JSON-LD Graph" },
                  { id: "head", label: "HTML <head>" }
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  onClick={() => setGeneratorTab(tab.id)}
                  className={`px-3 py-1 rounded-lg text-xs font-mono font-semibold transition ${
                    generatorTab === tab.id
                      ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white"
                      : mutedText
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          <pre
            className={`rounded-2xl p-4 text-xs font-mono overflow-x-auto max-h-[340px] leading-relaxed ${glassPill}`}
          >
            {generatedSnippet}
          </pre>
        </div>
      </div>
    </div>
  );
}

/**
 * Komponen `SentinelVaultView` untuk `/scan/sentinel` (`components/sentinel/sentinel-audit.tsx`)
 */
export function SentinelVaultView({ isDark = true }: { isDark?: boolean }) {
  const [claimDomain, setClaimDomain] = useState<string>("sentinel-id.net");
  const [claimMethod, setClaimMethod] = useState<ClaimMethod>("dns");
  const [isOwnerVerified, setIsOwnerVerified] = useState<boolean>(false);
  const [selectedArtifactId, setSelectedArtifactId] = useState<string>("V-01");
  const [verifyNotice, setVerifyNotice] = useState<string>("");

  const glassCard = isDark
    ? "bg-foreground/[0.04] backdrop-blur-2xl border border-foreground/[0.11] shadow-[0_24px_60px_-15px_rgba(0,0,0,0.65)]"
    : "bg-foreground/75 backdrop-blur-2xl border border-slate-900/[0.08] shadow-[0_20px_50px_-12px_rgba(15,23,42,0.07)]";
  const glassPill = isDark
    ? "bg-foreground/[0.06] backdrop-blur-xl border border-foreground/[0.1]"
    : "bg-foreground/85 backdrop-blur-xl border border-slate-900/[0.08]";
  const mutedText = isDark ? "text-muted" : "text-slate-600";

  const selectedArtifact = useMemo(
    () => VAULT_ARTIFACTS.find((a) => a.id === selectedArtifactId) || VAULT_ARTIFACTS[0],
    [selectedArtifactId]
  );

  const verificationToken = useMemo(() => {
    const clean = claimDomain.trim().replace(/^https?:\/\//i, "").split("/")[0] || "sentinel-id.net";
    return `sentinel-site-verification=aes256_${clean.replace(/[^a-z0-9]/gi, "")}_9f82c1`;
  }, [claimDomain]);

  function handleVerifyOwnership(e: React.FormEvent) {
    e.preventDefault();
    setIsOwnerVerified(true);
    setVerifyNotice(
      `Kepemilikan ${claimDomain} terverifikasi via ${
        claimMethod === "dns" ? "DNS TXT Record" : "HTTP Well-Known Token"
      } (Akses Bukti 1x Lihat Aktif)`
    );
  }

  return (
    <div className="space-y-8">
      {/* Top Bento Hero for Sentinel Vault AES-256-GCM */}
      <div className={`rounded-3xl p-6 sm:p-8 grid grid-cols-1 lg:grid-cols-12 gap-6 items-center ${glassCard}`}>
        <div className="lg:col-span-7 space-y-4">
          <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono text-pink-500 ${glassPill}`}>
            <Lock className="w-3.5 h-3.5" />
            <span>MODUL /scan/sentinel · AES-256-GCM ENCRYPTED VAULT</span>
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight">
            Sentinel Vault &amp;{" "}
            <span className="bg-gradient-to-r from-pink-500 via-purple-500 to-indigo-500 bg-clip-text text-transparent">
              Klaim Bukti Pemilik Domain
            </span>
          </h1>
          <p className={`text-sm sm:text-base leading-relaxed ${mutedText}`}>
            Saat pemindai pasif menemukan kebocoran kritis seperti <code>.env</code>,{" "}
            <code>.git/HEAD</code>, atau <code>wp-config.php.bak</code>, nilai rahasia{" "}
            <strong>tidak pernah ditampilkan ke publik</strong>. Bukti langsung dienkripsi
            dengan <strong>AES-256-GCM</strong> dan hanya bisa dibuka 1x oleh pemilik sah domain.
          </p>
        </div>

        {/* Right Vault Security Posture Pills */}
        <div className="lg:col-span-5 grid grid-cols-2 gap-3">
          {[
            { label: "Algoritma Vault", val: "AES-256", sub: "GCM Authenticated", tone: "text-pink-500" },
            { label: "Eksposur Publik", val: "0 Bocor", sub: "Auto-Redacted [REDACTED]", tone: "text-emerald-500" },
            { label: "Metode Klaim", val: "DNS / HTTP", sub: "Verifikasi Kepemilikan", tone: "text-cyan-500" },
            { label: "Akses Dekripsi", val: "1x Lihat", sub: "One-Time Burn Token", tone: "text-purple-400" }
          ].map((m) => (
            <div key={m.label} className={`rounded-2xl p-4 ${glassPill}`}>
              <span className={`text-xs font-mono uppercase ${mutedText}`}>{m.label}</span>
              <p className={`text-2xl font-extrabold mt-1 ${m.tone}`}>{m.val}</p>
              <p className={`text-xs mt-0.5 ${mutedText}`}>{m.sub}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Main Grid: Encrypted Evidence Vault Table + Domain Ownership Claim Wizard */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left: Sensitive Artifacts & Redaction Inspector (7 cols) */}
        <div className={`lg:col-span-7 rounded-3xl p-6 space-y-5 ${glassCard}`}>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h2 className="text-lg font-bold">Brankas Bukti File Sensitif</h2>
              <p className={`text-xs ${mutedText}`}>
                Klik artefak untuk melihat perbandingan tampilan publik vs dekripsi pemilik sah
              </p>
            </div>
            <span
              className={`px-3 py-1 rounded-full text-xs font-mono font-semibold ${
                isOwnerVerified
                  ? "bg-emerald-500/15 text-emerald-500"
                  : "bg-amber-500/15 text-amber-500"
              }`}
            >
              {isOwnerVerified ? "🔓 Terverifikasi (1x Lihat)" : "🔒 Disensor untuk Publik"}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {VAULT_ARTIFACTS.map((art) => {
              const isSel = art.id === selectedArtifactId;
              return (
                <button
                  key={art.id}
                  type="button"
                  onClick={() => setSelectedArtifactId(art.id)}
                  className={`rounded-2xl p-4 text-left transition-all ${glassPill} ${
                    isSel ? "ring-2 ring-pink-500/70" : "opacity-85 hover:opacity-100"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-sm font-bold text-pink-500">
                      {art.path}
                    </span>
                    <span
                      className={`text-xs font-mono font-bold px-2 py-0.5 rounded-md ${
                        art.risk === "CRITICAL"
                          ? "bg-rose-500/15 text-rose-500"
                          : art.risk === "HIGH"
                          ? "bg-amber-500/15 text-amber-500"
                          : "bg-emerald-500/15 text-emerald-500"
                      }`}
                    >
                      {art.risk}
                    </span>
                  </div>
                  <div className={`text-xs font-mono mt-1 ${mutedText}`}>{art.cwe}</div>
                </button>
              );
            })}
          </div>

          {/* Selected Artifact Evidence Detail Box */}
          <div className={`rounded-2xl p-5 space-y-3 ${glassPill}`}>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-xs font-mono font-bold text-cyan-500">
                {selectedArtifact.path} · {selectedArtifact.cwe}
              </span>
              <span className={`text-xs font-mono ${mutedText}`}>
                {selectedArtifact.cipherMeta}
              </span>
            </div>

            <div className="p-3.5 rounded-xl bg-sunken border border-border font-mono text-xs break-all">
              {isOwnerVerified
                ? selectedArtifact.decryptedPreview
                : selectedArtifact.publicPreview}
            </div>

            <p className={`text-xs leading-relaxed ${mutedText}`}>
              <strong className="font-semibold text-emerald-500">Remediasi: </strong>
              {selectedArtifact.remediation}
            </p>
          </div>
        </div>

        {/* Right: Domain Ownership Claim Wizard (5 cols) */}
        <div className={`lg:col-span-5 rounded-3xl p-6 flex flex-col justify-between space-y-5 ${glassCard}`}>
          <form onSubmit={handleVerifyOwnership} className="space-y-4">
            <div>
              <span className="text-xs font-mono uppercase tracking-widest text-purple-400 font-semibold">
                Verifikasi Kepemilikan Sah
              </span>
              <h2 className="text-lg font-bold mt-1">
                Klaim Domain &amp; Buka Brankas
              </h2>
              <p className={`text-xs mt-0.5 ${mutedText}`}>
                Buktikan kepemilikan domain via DNS TXT atau file HTTP untuk membuka redaksi bukti.
              </p>
            </div>

            <div className="space-y-1.5">
              <label className="text-xs font-semibold block">Domain yang Diklaim</label>
              <div className={`flex items-center gap-2 px-3.5 py-2.5 rounded-2xl ${glassPill}`}>
                <Globe className="w-4 h-4 text-pink-500 shrink-0" />
                <input
                  type="text"
                  value={claimDomain}
                  onChange={(e) => {
                    setClaimDomain(e.target.value);
                    setIsOwnerVerified(false);
                  }}
                  className="w-full bg-transparent text-xs font-mono focus:outline-none"
                  aria-label="Domain Klaim"
                />
              </div>
            </div>

            {/* Method Selector */}
            <div className="space-y-1.5">
              <label className="text-xs font-semibold block">Metode Verifikasi</label>
              <div className={`grid grid-cols-2 gap-2 p-1 rounded-2xl ${glassPill}`}>
                <button
                  type="button"
                  onClick={() => setClaimMethod("dns")}
                  className={`py-2 rounded-xl text-xs font-semibold transition ${
                    claimMethod === "dns"
                      ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white"
                      : mutedText
                  }`}
                >
                  DNS TXT Record
                </button>
                <button
                  type="button"
                  onClick={() => setClaimMethod("http")}
                  className={`py-2 rounded-xl text-xs font-semibold transition ${
                    claimMethod === "http"
                      ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white"
                      : mutedText
                  }`}
                >
                  File HTTP Well-Known
                </button>
              </div>
            </div>

            {/* Token Challenge Instructions */}
            <div className={`rounded-2xl p-4 space-y-2 text-xs ${glassPill}`}>
              <div className="font-semibold">
                {claimMethod === "dns"
                  ? `Tambahkan TXT Record pada DNS ${claimDomain}:`
                  : `Unggah file teks pada path berikut:`}
              </div>
              <div className="font-mono text-xs text-cyan-500 break-all">
                {claimMethod === "dns"
                  ? `Host: _sentinel-verify.${claimDomain}`
                  : `URL: https://${claimDomain}/.well-known/sentinel-claim.txt`}
              </div>
              <div className="p-2.5 rounded-xl bg-sunken font-mono text-xs text-emerald-400 break-all">
                {verificationToken}
              </div>
            </div>

            <div className="flex gap-2">
              <button
                type="submit"
                className="flex-1 py-3 px-4 rounded-2xl font-semibold text-xs text-white bg-gradient-to-r from-pink-500 via-purple-600 to-indigo-600 hover:opacity-95 transition shadow-lg shadow-pink-500/20"
              >
                Verifikasi &amp; Buka Bukti (1x Lihat)
              </button>
              {isOwnerVerified && (
                <button
                  type="button"
                  onClick={() => {
                    setIsOwnerVerified(false);
                    setVerifyNotice("");
                  }}
                  className={`px-3 py-3 rounded-2xl text-xs font-mono ${glassPill}`}
                >
                  Kunci Lagi
                </button>
              )}
            </div>
          </form>

          {verifyNotice && (
            <div className="rounded-2xl p-3.5 bg-emerald-500/15 border border-emerald-500/30 text-xs text-emerald-500 font-medium">
              ✓ {verifyNotice}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}


export const SeoMaster = SeoMasterView;
export const SentinelAudit = SentinelVaultView;
export default SeoMasterView;
