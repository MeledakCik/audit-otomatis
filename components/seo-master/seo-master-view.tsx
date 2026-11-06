"use client";

import { useState, useEffect } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import {
  Globe2,
  Search,
  Sparkles,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Code2,
  Copy,
  Check,
  ShieldCheck,
  TrendingUp,
  Languages,
  FileCode2,
  ArrowLeft,
  ExternalLink,
  Award,
  Zap,
} from "lucide-react";
import { VerifiedBadge } from "@/components/verified-badge";
import type { SeoMasterTargetAudit } from "@/lib/seo-master-scanner";

const PRESET_DOMAINS = [
  { domain: "sentinel-id.net", kw: "passive website security scanner & SEO master" },
  { domain: "vercel.com", kw: "frontend cloud deployment platform" },
  { domain: "nextjs.org", kw: "react framework for the web" },
];

export function SeoMasterView() {
  const searchParams = useSearchParams();
  const initialDomain = searchParams?.get("domain") || "";

  const [domain, setDomain] = useState(initialDomain);
  const [keyword, setKeyword] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [audit, setAudit] = useState<SeoMasterTargetAudit | null>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "international" | "keywords" | "generator">("overview");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  useEffect(() => {
    if (initialDomain) {
      runScan(initialDomain, "");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function runScan(targetDomain: string, targetKw: string) {
    if (!targetDomain.trim()) return;
    setLoading(true);
    setError(null);

    try {
      const res = await fetch("/api/seo-master", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: targetDomain.trim(), keyword: targetKw.trim() }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setError(data.error ?? "Gagal menganalisis domain.");
        setLoading(false);
        return;
      }
      setAudit(data.audit);
    } catch {
      setError("Gagal terhubung ke server SEO Master.");
    } finally {
      setLoading(false);
    }
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    runScan(domain, keyword);
  }

  function copyCode(key: string, code: string) {
    try {
      navigator.clipboard.writeText(code);
      setCopiedKey(key);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch {
      // ignore
    }
  }

  return (
    <div className="w-full min-h-full">
      <div className="mx-auto max-w-6xl px-5 sm:px-6 lg:px-8 py-8 space-y-8">
        {/* Top Bar Navigation & Verification */}
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <Link
              href="/"
              className="inline-flex items-center gap-1.5 rounded-xl border border-white/10 bg-white/[0.03] hover:bg-white/[0.08] px-3 py-1.5 text-xs font-mono text-slate-300 transition-colors"
            >
              <ArrowLeft className="h-3.5 w-3.5" />
              Kembali ke Overview
            </Link>
            <span className="inline-flex items-center gap-1.5 rounded-full bg-gradient-to-r from-purple-500/20 to-emerald-500/20 border border-purple-500/35 px-3 py-1 text-xs font-mono font-bold text-purple-200">
              <Globe2 className="h-3.5 w-3.5 text-emerald-400" />
              SEO MASTER &amp; INTERNATIONAL RANK #1 ENGINE
            </span>
          </div>
          <VerifiedBadge variant="header" />
        </div>

        {/* Hero & Search Input Panel */}
        <div className="rounded-2xl border border-purple-500/30 bg-gradient-to-br from-[#171128] via-[#120d1e] to-[#0c141d] p-6 sm:p-8 shadow-2xl space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-[1.15fr_0.85fr] gap-6 items-center">
            <div className="space-y-3">
              <div className="inline-flex items-center gap-2 rounded-full bg-emerald-500/15 border border-emerald-500/30 px-3 py-1 text-[11px] font-mono font-bold text-emerald-300">
                <TrendingUp className="h-3.5 w-3.5" />
                35+ PARAMETER GOOGLE SERP · HREFLANG · JSON-LD · CORE TRUST
              </div>
              <h1 className="text-2xl sm:text-4xl font-extrabold tracking-tight text-white leading-tight">
                SEO Master &amp;{" "}
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-purple-400 via-pink-400 to-emerald-400">
                  Global Rank #1 Analyzer
                </span>
              </h1>
              <p className="text-xs sm:text-sm text-slate-300 leading-relaxed max-w-2xl">
                Audit menyeluruh kesiapan domain untuk menembus <strong>Rank #1 Google</strong> dan tampil di hasil pencarian <strong>Internasional</strong> (US, UK, SG, AU, ID, MY, JP, DE, Global <code>x-default</code>). Dilengkapi generator otomatis tag Hreflang, Schema.org JSON-LD Graph, dan konfigurasi Next.js Metadata.
              </p>
            </div>

            {/* Active Self-Platform SEO Status Card */}
            <div className="rounded-xl border border-emerald-500/30 bg-black/40 p-4 space-y-2.5">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-emerald-300 flex items-center gap-1.5">
                  <Award className="h-4 w-4 text-emerald-400" />
                  STATUS SEO SENTINEL-ID: AKTIF
                </span>
                <span className="rounded-md bg-emerald-500/20 border border-emerald-500/40 px-2 py-0.5 text-[10px] font-mono font-bold text-emerald-200">
                  GRADE A+ (100%)
                </span>
              </div>
              <div className="grid grid-cols-2 gap-2 text-[11px] font-mono text-slate-300">
                <div className="rounded-lg bg-white/[0.03] border border-white/[0.07] px-2.5 py-1.5">
                  ✓ 13 Locale Hreflang
                </div>
                <div className="rounded-lg bg-white/[0.03] border border-white/[0.07] px-2.5 py-1.5">
                  ✓ JSON-LD @graph (5x)
                </div>
                <div className="rounded-lg bg-white/[0.03] border border-white/[0.07] px-2.5 py-1.5">
                  ✓ Sitemap + RSS 2.0
                </div>
                <div className="rounded-lg bg-white/[0.03] border border-white/[0.07] px-2.5 py-1.5">
                  ✓ Google + AI Bots Ready
                </div>
              </div>
            </div>
          </div>

          {/* Audit Form */}
          <form onSubmit={handleSubmit} className="space-y-3 pt-2 border-t border-white/10">
            <div className="grid grid-cols-1 md:grid-cols-[1.2fr_1fr_auto] gap-3">
              <div className="relative">
                <Globe2 className="h-4 w-4 text-purple-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="text"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  placeholder="Masukkan domain target (mis. sentinel-id.net atau example.com)"
                  required
                  disabled={loading}
                  className="w-full h-11 rounded-xl border border-white/15 bg-black/50 pl-10 pr-3.5 text-xs sm:text-sm font-mono text-white placeholder:text-slate-500 outline-none focus:border-purple-400"
                />
              </div>
              <div className="relative">
                <Search className="h-4 w-4 text-emerald-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  type="text"
                  value={keyword}
                  onChange={(e) => setKeyword(e.target.value)}
                  placeholder="Target keyword utama (opsional, mis. passive security scanner)"
                  disabled={loading}
                  className="w-full h-11 rounded-xl border border-white/15 bg-black/50 pl-10 pr-3.5 text-xs sm:text-sm font-mono text-white placeholder:text-slate-500 outline-none focus:border-emerald-400"
                />
              </div>
              <button
                type="submit"
                disabled={loading}
                className="h-11 px-6 rounded-xl bg-gradient-to-r from-purple-600 via-fuchsia-600 to-emerald-600 hover:brightness-110 text-xs sm:text-sm font-mono font-extrabold text-white shadow-lg shadow-purple-900/40 transition-all cursor-pointer disabled:opacity-50"
              >
                {loading ? "MENGANALISIS SERP..." : "AUDIT SEO MASTER →"}
              </button>
            </div>

            <div className="flex flex-wrap items-center gap-2 text-xs font-mono text-slate-400">
              <span>Coba preset:</span>
              {PRESET_DOMAINS.map((p) => (
                <button
                  key={p.domain}
                  type="button"
                  onClick={() => {
                    setDomain(p.domain);
                    setKeyword(p.kw);
                    runScan(p.domain, p.kw);
                  }}
                  className="rounded-lg border border-white/10 bg-white/[0.03] hover:bg-white/[0.08] hover:text-white px-2.5 py-1 text-[11px] transition-colors cursor-pointer"
                >
                  {p.domain}
                </button>
              ))}
            </div>
          </form>

          {error && (
            <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 px-4 py-3 text-xs font-mono text-rose-200 flex items-center gap-2">
              <XCircle className="h-4 w-4 text-rose-400 shrink-0" />
              <span>{error}</span>
            </div>
          )}
        </div>

        {/* Audit Results Dashboard */}
        {audit && (
          <div className="space-y-6 animate-fade-up">
            {/* Top Score Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3.5">
              <ScoreCard
                label="SEO Master Score"
                score={audit.overallMasterScore}
                sub={`Grade ${audit.rankReadinessGrade} · ${audit.responseTimeMs}ms`}
                highlight
              />
              <ScoreCard
                label="Technical & Schema"
                score={audit.seo.technicalScore}
                sub={`${audit.seo.meta.jsonLdCount} JSON-LD · Canonical`}
              />
              <ScoreCard
                label="International SEO"
                score={audit.seo.internationalScore}
                sub={`${audit.seo.meta.hreflangTags.length} Hreflang · lang="${audit.seo.meta.htmlLang ?? "-"}"`}
              />
              <ScoreCard
                label="Content & Keywords"
                score={audit.seo.contentScore}
                sub={`${audit.seo.meta.wordCount} kata · ${audit.seo.meta.h1Count} H1 / ${audit.seo.meta.h2Count} H2`}
              />
              <ScoreCard
                label="Security-SEO Trust"
                score={audit.securitySeoTrust.trustScore}
                sub={`HTTPS · ${audit.securitySeoTrust.hasHsts ? "HSTS ✓" : "No HSTS"}`}
              />
            </div>

            {/* Live Google Search Result Preview (Desktop + International) */}
            <div className="rounded-2xl border border-white/10 bg-[#120d1d] p-5 space-y-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="text-xs font-mono uppercase tracking-wider text-purple-300 font-bold flex items-center gap-2">
                  <Sparkles className="h-4 w-4 text-purple-400" />
                  Simulasi Tampilan Google SERP Internasional ({audit.origin})
                </div>
                <span className="text-[11px] font-mono text-slate-400">
                  Title: {audit.seo.meta.titleLength} char · Description: {audit.seo.meta.metaDescriptionLength} char
                </span>
              </div>
              <div className="rounded-xl bg-[#1f1f23] border border-white/10 p-4 max-w-3xl space-y-1.5">
                <div className="flex items-center gap-2 text-xs text-slate-300">
                  <span className="h-6 w-6 rounded-full bg-purple-500/20 border border-purple-400/30 grid place-items-center text-[11px] font-bold text-purple-200">
                    {audit.domain.slice(0, 1).toUpperCase()}
                  </span>
                  <div className="leading-tight">
                    <div className="text-xs text-slate-200 font-medium">{audit.domain}</div>
                    <div className="text-[11px] text-slate-400">{audit.origin}</div>
                  </div>
                </div>
                <div className="text-base sm:text-lg font-semibold text-[#8ab4f8] hover:underline cursor-pointer line-clamp-1">
                  {audit.seo.meta.title || `${audit.domain} — (Title Tag Kosong)`}
                </div>
                <p className="text-xs sm:text-sm text-[#bdc1c6] leading-relaxed line-clamp-2">
                  {audit.seo.meta.metaDescription ||
                    "Meta description tidak ditemukan. Google akan mengambil cuplikan acak dari teks halaman."}
                </p>
                {audit.seo.meta.jsonLdTypes.length > 0 && (
                  <div className="pt-1 flex flex-wrap items-center gap-2 text-[11px] font-mono text-emerald-300">
                    <span>★ Rich Snippets Detected:</span>
                    {audit.seo.meta.jsonLdTypes.map((t) => (
                      <span
                        key={t}
                        className="rounded bg-emerald-500/15 border border-emerald-500/30 px-1.5 py-0.5"
                      >
                        {t}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Navigation Tabs */}
            <div className="flex flex-wrap gap-2 border-b border-white/10 pb-3">
              {[
                { id: "overview", label: "1. Temuan & Rekomendasi Rank #1", icon: CheckCircle2 },
                { id: "international", label: "2. International Hreflang & Crawlability", icon: Languages },
                { id: "keywords", label: "3. Keyword Density & Heading Matrix", icon: TrendingUp },
                { id: "generator", label: "4. Generator Kode SEO Master (Copy-Paste)", icon: FileCode2 },
              ].map((tab) => {
                const Icon = tab.icon;
                const active = activeTab === tab.id;
                return (
                  <button
                    key={tab.id}
                    type="button"
                    onClick={() => setActiveTab(tab.id as typeof activeTab)}
                    className={`inline-flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-mono font-bold transition-all cursor-pointer ${
                      active
                        ? "bg-gradient-to-r from-purple-600/35 to-emerald-600/25 text-white border border-purple-400/50 shadow"
                        : "bg-white/[0.03] text-slate-400 hover:text-white border border-white/[0.07]"
                    }`}
                  >
                    <Icon className="h-3.5 w-3.5" />
                    <span>{tab.label}</span>
                  </button>
                );
              })}
            </div>

            {/* TAB 1: OVERVIEW & ISSUES */}
            {activeTab === "overview" && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                {/* Left: Issues */}
                <div className="rounded-2xl border border-white/10 bg-[#120d1d] p-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <h2 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                      Temuan Audit SEO ({audit.seo.issues.length})
                    </h2>
                    <span className="text-xs font-mono text-slate-400">
                      Status HTTP {audit.statusCode}
                    </span>
                  </div>
                  {audit.seo.issues.length === 0 ? (
                    <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/10 p-4 text-xs text-emerald-200 flex items-center gap-2.5">
                      <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0" />
                      <span>
                        Luar biasa! Tidak ditemukan masalah SEO pada halaman ini. Semua sinyal Rank #1 dan International SEO telah terpenuhi.
                      </span>
                    </div>
                  ) : (
                    <div className="space-y-2 max-h-[420px] overflow-y-auto thin-scroll pr-1">
                      {audit.seo.issues.map((iss, idx) => (
                        <div
                          key={idx}
                          className={`rounded-xl border p-3 text-xs flex items-start gap-2.5 ${
                            iss.level === "critical"
                              ? "border-rose-500/40 bg-rose-500/10 text-rose-200"
                              : iss.level === "warning"
                              ? "border-amber-500/40 bg-amber-500/10 text-amber-200"
                              : "border-sky-500/30 bg-sky-500/10 text-sky-200"
                          }`}
                        >
                          <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                          <div className="space-y-0.5">
                            <span className="text-[10px] font-mono uppercase font-bold block opacity-80">
                              {iss.level}
                            </span>
                            <span>{iss.msg}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>

                {/* Right: Actionable Recommendations & Technical Checklist */}
                <div className="space-y-4">
                  <div className="rounded-2xl border border-emerald-500/30 bg-gradient-to-b from-emerald-950/25 to-[#120d1d] p-5 space-y-3">
                    <h2 className="text-sm font-bold text-emerald-300 font-mono uppercase tracking-wider flex items-center gap-2">
                      <Zap className="h-4 w-4 text-emerald-400" />
                      Action Plan Menuju Rank #1 Google
                    </h2>
                    <ul className="space-y-2 text-xs text-slate-200 leading-relaxed">
                      {audit.seo.recommendations.map((rec, i) => (
                        <li key={i} className="flex items-start gap-2">
                          <span className="text-emerald-400 font-bold">→</span>
                          <span>{rec}</span>
                        </li>
                      ))}
                    </ul>
                  </div>

                  <div className="rounded-2xl border border-white/10 bg-[#120d1d] p-5 space-y-3">
                    <h3 className="text-xs font-mono uppercase tracking-wider text-slate-300 font-bold">
                      Checklist Sinyal Teknis &amp; Keamanan SERP
                    </h3>
                    <div className="grid grid-cols-2 gap-2.5 text-xs font-mono">
                      <CheckPill label="Canonical Tag" ok={Boolean(audit.seo.meta.canonical)} />
                      <CheckPill label="JSON-LD Schema" ok={audit.seo.meta.jsonLdCount > 0} />
                      <CheckPill label="Open Graph (OG)" ok={audit.seo.meta.ogTagsFound.length >= 4} />
                      <CheckPill label="Twitter Large Card" ok={Boolean(audit.seo.meta.twitterCard)} />
                      <CheckPill label="Robots.txt Valid" ok={audit.crawlability.robotsTxtPresent} />
                      <CheckPill label="Sitemap.xml Valid" ok={audit.crawlability.sitemapXmlPresent} />
                      <CheckPill label="HSTS Security Signal" ok={audit.securitySeoTrust.hasHsts} />
                      <CheckPill label="Web App Manifest" ok={audit.seo.meta.hasManifest} />
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* TAB 2: INTERNATIONAL HREFLANG & CRAWLABILITY */}
            {activeTab === "international" && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                <div className="rounded-2xl border border-white/10 bg-[#120d1d] p-5 space-y-4">
                  <div className="flex items-center justify-between">
                    <h2 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                      Distribusi Hreflang Internasional ({audit.seo.meta.hreflangTags.length} Locale)
                    </h2>
                    <span className="rounded-full bg-purple-500/20 border border-purple-500/40 px-2.5 py-0.5 text-[11px] font-mono text-purple-200">
                      html lang=&quot;{audit.seo.meta.htmlLang ?? "none"}&quot;
                    </span>
                  </div>

                  {audit.seo.meta.hreflangTags.length === 0 ? (
                    <div className="rounded-xl border border-amber-500/35 bg-amber-500/10 p-4 text-xs text-amber-200 space-y-2">
                      <div className="font-bold">Belum ada tag Hreflang ditemukan di halaman ini.</div>
                      <p>
                        Agar website muncul di Google Internasional (US, UK, Singapura, Australia, Jepang, Eropa), buka tab <strong>4. Generator Kode SEO Master</strong> dan salin blok Hreflang yang sudah disiapkan.
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-2 max-h-80 overflow-y-auto thin-scroll">
                      {audit.seo.meta.hreflangTags.map((h, i) => (
                        <div
                          key={i}
                          className="flex items-center justify-between gap-3 rounded-xl border border-white/[0.08] bg-white/[0.02] px-3.5 py-2 text-xs font-mono"
                        >
                          <span className="rounded bg-emerald-500/15 border border-emerald-500/30 px-2 py-0.5 text-emerald-300 font-bold">
                            {h.lang}
                          </span>
                          <span className="text-slate-300 truncate">{h.href}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  <div className="pt-2 border-t border-white/10 grid grid-cols-2 gap-2.5 text-xs font-mono">
                    <div className="rounded-xl bg-white/[0.03] p-3">
                      <div className="text-slate-400 text-[10px] uppercase">OG Primary Locale</div>
                      <div className="text-white font-bold mt-0.5">{audit.seo.meta.ogLocale ?? "Tidak disetel"}</div>
                    </div>
                    <div className="rounded-xl bg-white/[0.03] p-3">
                      <div className="text-slate-400 text-[10px] uppercase">x-default Fallback</div>
                      <div className="text-white font-bold mt-0.5">
                        {audit.seo.meta.hasXDefaultHreflang ? "✓ Aktif (Global Ready)" : "✗ Belum Ada"}
                      </div>
                    </div>
                  </div>
                </div>

                <div className="rounded-2xl border border-white/10 bg-[#120d1d] p-5 space-y-4">
                  <h2 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                    Crawlability (/robots.txt &amp; /sitemap.xml)
                  </h2>
                  <div className="grid grid-cols-2 gap-3 text-xs font-mono">
                    <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3.5 space-y-1">
                      <div className="text-slate-400 text-[10px] uppercase">/robots.txt</div>
                      <div className="text-sm font-bold text-white">
                        {audit.crawlability.robotsTxtPresent ? "✓ Ditemukan" : "✗ Tidak Ada"}
                      </div>
                      <div className="text-[11px] text-slate-400">
                        Root Crawl: {audit.crawlability.robotsTxtAllowsRoot ? "Diizinkan" : "Diblokir"}
                      </div>
                    </div>
                    <div className="rounded-xl border border-white/10 bg-white/[0.03] p-3.5 space-y-1">
                      <div className="text-slate-400 text-[10px] uppercase">/sitemap.xml</div>
                      <div className="text-sm font-bold text-white">
                        {audit.crawlability.sitemapXmlPresent ? "✓ Ditemukan" : "✗ Tidak Ada"}
                      </div>
                      <div className="text-[11px] text-slate-400">
                        Total URL Terindeks: {audit.crawlability.sitemapUrlCount}
                      </div>
                    </div>
                  </div>

                  {audit.crawlability.robotsTxtSnippet && (
                    <div className="space-y-1.5">
                      <div className="text-[11px] font-mono text-slate-400">Cuplikan /robots.txt aktif:</div>
                      <pre className="rounded-xl border border-white/10 bg-black/60 p-3 text-[11px] font-mono text-emerald-300 overflow-x-auto max-h-48">
                        {audit.crawlability.robotsTxtSnippet}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* TAB 3: KEYWORD DENSITY & HEADINGS */}
            {activeTab === "keywords" && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                <div className="rounded-2xl border border-white/10 bg-[#120d1d] p-5 space-y-3">
                  <div className="flex items-center justify-between">
                    <h2 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                      Top 10 Keyword Density Matrix
                    </h2>
                    <span className="text-xs font-mono text-slate-400">
                      Total: {audit.seo.meta.wordCount} kata
                    </span>
                  </div>
                  {audit.seo.meta.topKeywords.length === 0 ? (
                    <p className="text-xs text-slate-400">Tidak cukup teks untuk menghitung densitas keyword.</p>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs font-mono">
                        <thead>
                          <tr className="border-b border-white/10 text-slate-400 text-left">
                            <th className="py-2 px-2.5">Keyword</th>
                            <th className="py-2 px-2.5 text-right">Frekuensi</th>
                            <th className="py-2 px-2.5 text-right">Densitas</th>
                          </tr>
                        </thead>
                        <tbody>
                          {audit.seo.meta.topKeywords.map((kw) => (
                            <tr key={kw.word} className="border-b border-white/[0.05]">
                              <td className="py-2 px-2.5 text-purple-200 font-bold">{kw.word}</td>
                              <td className="py-2 px-2.5 text-right text-slate-300">{kw.count}x</td>
                              <td className="py-2 px-2.5 text-right text-emerald-300">{kw.densityPct}%</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>

                <div className="rounded-2xl border border-white/10 bg-[#120d1d] p-5 space-y-4">
                  <h2 className="text-sm font-bold text-white font-mono uppercase tracking-wider">
                    Struktur Semantik Heading &amp; Tautan
                  </h2>
                  <div className="rounded-xl border border-white/10 bg-white/[0.02] p-3.5 space-y-1">
                    <div className="text-[10px] font-mono uppercase text-purple-300">Primary H1 Heading</div>
                    <div className="text-sm font-bold text-white">
                      {audit.seo.meta.h1Text || "(Tidak ditemukan tag H1)"}
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-2.5 text-center font-mono">
                    <div className="rounded-xl border border-white/10 bg-white/[0.02] p-3">
                      <div className="text-lg font-extrabold text-white">{audit.seo.meta.h1Count}</div>
                      <div className="text-[10px] text-slate-400">Tag &lt;h1&gt;</div>
                    </div>
                    <div className="rounded-xl border border-white/10 bg-white/[0.02] p-3">
                      <div className="text-lg font-extrabold text-white">{audit.seo.meta.h2Count}</div>
                      <div className="text-[10px] text-slate-400">Tag &lt;h2&gt;</div>
                    </div>
                    <div className="rounded-xl border border-white/10 bg-white/[0.02] p-3">
                      <div className="text-lg font-extrabold text-white">{audit.seo.meta.h3Count}</div>
                      <div className="text-[10px] text-slate-400">Tag &lt;h3&gt;</div>
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-2.5 text-center font-mono">
                    <div className="rounded-xl border border-white/10 bg-white/[0.02] p-3">
                      <div className="text-lg font-extrabold text-emerald-300">
                        {audit.seo.meta.internalLinkCount}
                      </div>
                      <div className="text-[10px] text-slate-400">Internal Links</div>
                    </div>
                    <div className="rounded-xl border border-white/10 bg-white/[0.02] p-3">
                      <div className="text-lg font-extrabold text-purple-300">
                        {audit.seo.meta.externalLinkCount}
                      </div>
                      <div className="text-[10px] text-slate-400">External Links</div>
                    </div>
                  </div>
                </div>
              </div>
            )}

            {/* TAB 4: CODE GENERATOR */}
            {activeTab === "generator" && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
                <CodeSnippetCard
                  title="1. HTML <head> Master & International Hreflang"
                  subtitle="Pasang di <head> untuk penargetan Google Global & Multi-Bahasa"
                  code={audit.generatedSnippets.htmlHeadTags}
                  copied={copiedKey === "html"}
                  onCopy={() => copyCode("html", audit.generatedSnippets.htmlHeadTags)}
                />
                <CodeSnippetCard
                  title="2. Schema.org JSON-LD Rich Snippets (@graph)"
                  subtitle="Memunculkan Rich Results, Organization & Sitelinks Searchbox di Google"
                  code={audit.generatedSnippets.jsonLdSchemaCode}
                  copied={copiedKey === "jsonld"}
                  onCopy={() => copyCode("jsonld", audit.generatedSnippets.jsonLdSchemaCode)}
                />
                <CodeSnippetCard
                  title="3. Next.js App Router Metadata (app/layout.tsx)"
                  subtitle="Konfigurasi siap pakai untuk proyek Next.js 15/16 App Router"
                  code={audit.generatedSnippets.nextJsMetadataCode}
                  copied={copiedKey === "nextjs"}
                  onCopy={() => copyCode("nextjs", audit.generatedSnippets.nextJsMetadataCode)}
                />
                <CodeSnippetCard
                  title="4. Rekomendasi /robots.txt (Googlebot + AI Search Ready)"
                  subtitle="Membuka akses ke halaman publik untuk Google, Bing, ChatGPT & Perplexity"
                  code={audit.generatedSnippets.robotsTxtRecommended}
                  copied={copiedKey === "robots"}
                  onCopy={() => copyCode("robots", audit.generatedSnippets.robotsTxtRecommended)}
                />
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

function ScoreCard({
  label,
  score,
  sub,
  highlight,
}: {
  label: string;
  score: number;
  sub: string;
  highlight?: boolean;
}) {
  const color =
    score >= 85
      ? "text-emerald-400"
      : score >= 65
      ? "text-amber-300"
      : "text-rose-400";

  return (
    <div
      className={`rounded-2xl border p-4 space-y-1 ${
        highlight
          ? "border-purple-400/50 bg-gradient-to-br from-purple-900/35 to-[#130e20]"
          : "border-white/10 bg-[#120d1d]"
      }`}
    >
      <div className="text-[11px] font-mono text-slate-400 uppercase tracking-wider">{label}</div>
      <div className={`text-2xl sm:text-3xl font-extrabold font-mono ${color}`}>
        {score}
        <span className="text-xs text-slate-500 font-normal">/100</span>
      </div>
      <div className="text-[11px] font-mono text-slate-400 truncate">{sub}</div>
    </div>
  );
}

function CheckPill({ label, ok }: { label: string; ok: boolean }) {
  return (
    <div
      className={`flex items-center justify-between rounded-xl border px-3 py-2 ${
        ok
          ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-200"
          : "border-rose-500/30 bg-rose-500/10 text-rose-200"
      }`}
    >
      <span className="truncate">{label}</span>
      <span className="font-bold ml-2">{ok ? "✓" : "✗"}</span>
    </div>
  );
}

function CodeSnippetCard({
  title,
  subtitle,
  code,
  copied,
  onCopy,
}: {
  title: string;
  subtitle: string;
  code: string;
  copied: boolean;
  onCopy: () => void;
}) {
  return (
    <div className="rounded-2xl border border-white/10 bg-[#120d1d] p-5 flex flex-col justify-between space-y-3">
      <div className="flex items-start justify-between gap-2">
        <div>
          <h3 className="text-xs sm:text-sm font-bold text-white font-mono flex items-center gap-1.5">
            <Code2 className="h-4 w-4 text-purple-400 shrink-0" />
            <span>{title}</span>
          </h3>
          <p className="text-[11px] text-slate-400 mt-0.5">{subtitle}</p>
        </div>
        <button
          type="button"
          onClick={onCopy}
          className="inline-flex items-center gap-1.5 rounded-lg border border-purple-400/40 bg-purple-500/15 hover:bg-purple-500/30 px-2.5 py-1 text-xs font-mono text-purple-200 transition-colors shrink-0 cursor-pointer"
        >
          {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
          <span>{copied ? "Tersalin" : "Salin"}</span>
        </button>
      </div>
      <pre className="rounded-xl border border-white/10 bg-black/70 p-3.5 text-[11px] font-mono text-emerald-300 overflow-x-auto max-h-72 thin-scroll">
        <code>{code}</code>
      </pre>
    </div>
  );
}
