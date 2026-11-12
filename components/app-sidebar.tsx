"use client";

import React, { useState, useEffect, useMemo } from "react";
import {
  Shield,
  Search,
  TrendingUp,
  Lock,
  ClipboardCheck,
  Clock,
  Terminal,
  ShieldAlert,
  KeyRound,
  AlertTriangle,
  FileCode2,
  Award,
  Wrench,
  Network,
  Globe,
  Radio,
  Layers,
  Eye,
  UserCheck,
  ShieldCheck,
  BookOpen,
  Code2,
  Settings,
  Sun,
  Moon,
  ChevronRight,
  ChevronDown,
  PanelLeftClose,
  PanelLeftOpen,
  CheckCircle2,
  ExternalLink,
  Sparkles,
  X
} from "lucide-react";

export interface NavModuleItem {
  id: string;
  title: string;
  route: string;
  badge?: string;
  badgeTone?: "pink" | "emerald" | "purple" | "cyan" | "amber" | "rose";
  category:
    | "Core Audit & Scan"
    | "Vulnerability & Code"
    | "Recon & Threat Intel"
    | "Resources & Admin";
  description: string;
  iconName: string;
}

export interface AppSidebarProps {
  open?: boolean;
  onClose?: () => void;
  activeRoute?: string;
  onSelectRoute?: (item: NavModuleItem) => void;
  defaultCollapsed?: boolean;
}

export const SENTINEL_NAV_ITEMS: NavModuleItem[] = [
  // 1. CORE AUDIT & SCAN
  {
    id: "overview",
    title: "Overview & Scan",
    route: "/",
    badge: "VAULT",
    badgeTone: "purple",
    category: "Core Audit & Scan",
    description: "Unified Deep Security Scanner (8 engine pasif sekaligus) & ringkasan postur domain.",
    iconName: "shield"
  },
  {
    id: "seo-master",
    title: "SEO Master & Rank #1",
    route: "/scan/seo-master",
    badge: "GLOBAL",
    badgeTone: "emerald",
    category: "Core Audit & Scan",
    description: "Audit 35+ sinyal Google SERP, 13 tag hreflang internasional & JSON-LD Schema.org.",
    iconName: "trending"
  },
  {
    id: "sentinel-vault",
    title: "Sentinel Vault & Klaim",
    route: "/scan/sentinel",
    badge: "AES",
    badgeTone: "pink",
    category: "Core Audit & Scan",
    description: "Audit file sensitif (.env, .git/HEAD, backup.zip) & Brankas Bukti AES-256-GCM.",
    iconName: "lock"
  },
  {
    id: "qc-otomatis",
    title: "QC Otomatis",
    route: "/qc",
    badge: "QC",
    badgeTone: "cyan",
    category: "Core Audit & Scan",
    description: "Audit kualitas SEO on-page, performa Core Web Vitals & pemeriksaan broken link.",
    iconName: "clipboard"
  },
  {
    id: "scan-history",
    title: "Scan History",
    route: "/history",
    category: "Core Audit & Scan",
    description: "Riwayat pemindaian domain dan perbandingan temuan antar waktu.",
    iconName: "clock"
  },
  {
    id: "request-inspector",
    title: "Request Inspector",
    route: "/requests",
    category: "Core Audit & Scan",
    description: "Log transparan seluruh HTTP GET/HEAD request dalam batas 100 request budget.",
    iconName: "terminal"
  },

  // 2. VULNERABILITY & CODE
  {
    id: "header-armor",
    title: "Header Armor",
    route: "/scan/headers",
    badge: "HTTP",
    badgeTone: "pink",
    category: "Vulnerability & Code",
    description: "Skor dan analisis keamanan HTTP response headers (CSP, HSTS, XFO, Permissions-Policy).",
    iconName: "shield-alert"
  },
  {
    id: "secret-hunter",
    title: "Secret Hunter",
    route: "/scan/secrets",
    badge: "AST",
    badgeTone: "amber",
    category: "Vulnerability & Code",
    description: "Deteksi API key, token & kredensial bocor pada bundle JavaScript.",
    iconName: "key"
  },
  {
    id: "exposure-check",
    title: "Exposure Check",
    route: "/scan/exposure",
    category: "Vulnerability & Code",
    description: "Pemeriksaan pasif eksposur file konfigurasi, wp2shell, php2shell, node2shell, go2shell & py2shell.",
    iconName: "alert"
  },
  {
    id: "js-supply-chain",
    title: "JS Supply Chain",
    route: "/scan/js",
    badge: "CVE",
    badgeTone: "purple",
    category: "Vulnerability & Code",
    description: "Deteksi pustaka pihak ketiga usang, pencocokan database OSV/NVD CVE & tracker skrip.",
    iconName: "file-code"
  },
  {
    id: "ssl-tls-checker",
    title: "SSL/TLS Checker",
    route: "/scan/ssl",
    badge: "TLS",
    badgeTone: "emerald",
    category: "Vulnerability & Code",
    description: "Inspeksi rantai sertifikat, masa berlaku, cipher suite & protokol TLS 1.3.",
    iconName: "award"
  },
  {
    id: "maintenance-log-ai",
    title: "Maintenance Log AI",
    route: "/maintenance-log",
    badge: "AI",
    badgeTone: "pink",
    category: "Vulnerability & Code",
    description: "Rekomendasi perbaikan terstruktur dan catatan pemeliharaan berbasis AI.",
    iconName: "wrench"
  },

  // 3. RECON & THREAT INTEL
  {
    id: "attack-surface-map",
    title: "Attack Surface Map",
    route: "/scan/map",
    badge: "GRAPH",
    badgeTone: "cyan",
    category: "Recon & Threat Intel",
    description: "Visualisasi graf interaktif relasi halaman, bundle JS, dan endpoint API.",
    iconName: "network"
  },
  {
    id: "subdomain-watch",
    title: "Subdomain Watch",
    route: "/scan/subdomain",
    badge: "CT",
    badgeTone: "cyan",
    category: "Recon & Threat Intel",
    description: "Enumerasi Certificate Transparency (crt.sh) & deteksi risiko subdomain takeover.",
    iconName: "globe"
  },
  {
    id: "dns-intelligence",
    title: "DNS Intelligence",
    route: "/scan/dns",
    badge: "DoH",
    badgeTone: "emerald",
    category: "Recon & Threat Intel",
    description: "Audit record A/MX/TXT serta proteksi anti-spoofing email SPF & DMARC.",
    iconName: "radio"
  },
  {
    id: "tech-stack",
    title: "Tech Stack",
    route: "/scan/stack",
    category: "Recon & Threat Intel",
    description: "Identifikasi framework, CMS, CDN, WAF, dan server web secara pasif.",
    iconName: "layers"
  },
  {
    id: "breach-peek",
    title: "Breach Peek",
    route: "/scan/breach",
    badge: "OSINT",
    badgeTone: "rose",
    category: "Recon & Threat Intel",
    description: "Pemeriksaan eksposur domain/email pada insiden kebocoran data publik.",
    iconName: "eye"
  },
  {
    id: "osint-lookup",
    title: "OSINT Lookup",
    route: "/scan/osint",
    badge: "RECON",
    badgeTone: "amber",
    category: "Recon & Threat Intel",
    description: "Reconnaissance publik untuk username, email (MX/Gravatar), domain & nama.",
    iconName: "user-check"
  },
  {
    id: "shield-status",
    title: "Shield Status",
    route: "/scan/shield-status",
    category: "Recon & Threat Intel",
    description: "Pemantauan ketahanan WAF/Cloudflare Edge dan status proteksi domain.",
    iconName: "shield-check"
  },

  // 4. RESOURCES & ADMIN
  {
    id: "documentation",
    title: "Documentation",
    route: "/docs",
    category: "Resources & Admin",
    description: "Dokumentasi arsitektur modular v2/v3.6 dan standar audit pasif GET-only.",
    iconName: "book"
  },
  {
    id: "api-reference",
    title: "API Reference",
    route: "/api-docs",
    category: "Resources & Admin",
    description: "Spesifikasi endpoint REST API pasif (termasuk GET /api/osint).",
    iconName: "code"
  },
  {
    id: "admin-console",
    title: "Admin Console",
    route: "/admin",
    badge: "ADMIN",
    badgeTone: "amber",
    category: "Resources & Admin",
    description: "Command Center untuk manajemen Sentinel Vault AES-256-GCM dan klaim pemilik domain.",
    iconName: "settings"
  }
];

const CATEGORIES: NavModuleItem["category"][] = [
  "Core Audit & Scan",
  "Vulnerability & Code",
  "Recon & Threat Intel",
  "Resources & Admin"
];

function ModuleIcon({ name, className = "w-4 h-4" }: { name: string; className?: string }) {
  switch (name) {
    case "shield":
      return <Shield className={className} />;
    case "trending":
      return <TrendingUp className={className} />;
    case "lock":
      return <Lock className={className} />;
    case "clipboard":
      return <ClipboardCheck className={className} />;
    case "clock":
      return <Clock className={className} />;
    case "terminal":
      return <Terminal className={className} />;
    case "shield-alert":
      return <ShieldAlert className={className} />;
    case "key":
      return <KeyRound className={className} />;
    case "alert":
      return <AlertTriangle className={className} />;
    case "file-code":
      return <FileCode2 className={className} />;
    case "award":
      return <Award className={className} />;
    case "wrench":
      return <Wrench className={className} />;
    case "network":
      return <Network className={className} />;
    case "globe":
      return <Globe className={className} />;
    case "radio":
      return <Radio className={className} />;
    case "layers":
      return <Layers className={className} />;
    case "eye":
      return <Eye className={className} />;
    case "user-check":
      return <UserCheck className={className} />;
    case "shield-check":
      return <ShieldCheck className={className} />;
    case "book":
      return <BookOpen className={className} />;
    case "code":
      return <Code2 className={className} />;
    case "settings":
      return <Settings className={className} />;
    default:
      return <Shield className={className} />;
  }
}

function getBadgeStyle(tone: NavModuleItem["badgeTone"], isDark: boolean) {
  switch (tone) {
    case "emerald":
      return isDark
        ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
        : "bg-emerald-500/10 text-emerald-700 border-emerald-500/25";
    case "pink":
      return isDark
        ? "bg-pink-500/15 text-pink-400 border-pink-500/30"
        : "bg-pink-500/10 text-pink-700 border-pink-500/25";
    case "purple":
      return isDark
        ? "bg-purple-500/15 text-purple-300 border-purple-500/30"
        : "bg-purple-500/10 text-purple-700 border-purple-500/25";
    case "cyan":
      return isDark
        ? "bg-cyan-500/15 text-cyan-300 border-cyan-500/30"
        : "bg-cyan-500/10 text-cyan-700 border-cyan-500/25";
    case "amber":
      return isDark
        ? "bg-amber-500/15 text-amber-300 border-amber-500/30"
        : "bg-amber-500/10 text-amber-700 border-amber-500/25";
    case "rose":
      return isDark
        ? "bg-rose-500/15 text-rose-300 border-rose-500/30"
        : "bg-rose-500/10 text-rose-700 border-rose-500/25";
    default:
      return isDark
        ? "bg-white/10 text-slate-300 border-white/15"
        : "bg-slate-900/5 text-slate-700 border-slate-900/10";
  }
}

/**
 * Komponen `AppSidebar` untuk `components/app-sidebar.tsx` pada repositori `MeledakCik/audit-otomatis`.
 * Mendukung pemanggilan tanpa props (`<AppSidebar />`) maupun dengan props kontrol drawer/rute.
 */
export function AppSidebar({
  open = false,
  onClose,
  activeRoute: controlledRoute,
  onSelectRoute,
  defaultCollapsed = false
}: AppSidebarProps = {}) {
  const [isDark, setIsDark] = useState<boolean>(true);
  const [isCollapsed, setIsCollapsed] = useState<boolean>(defaultCollapsed);
  const [searchQuery, setSearchQuery] = useState<string>("");
  const [internalRoute, setInternalRoute] = useState<string>("/");
  const [openCategories, setOpenCategories] = useState<Record<string, boolean>>({
    "Core Audit & Scan": true,
    "Vulnerability & Code": true,
    "Recon & Threat Intel": true,
    "Resources & Admin": true
  });

  const currentRoute = controlledRoute !== undefined ? controlledRoute : internalRoute;

  // Sinkronisasi awal dengan class `dark` pada <html> (next-themes) dan pathname browser
  useEffect(() => {
    try {
      const root = document.documentElement;
      const saved = localStorage.getItem("theme");
      if (saved === "light") {
        root.classList.remove("dark");
        setIsDark(false);
      } else if (saved === "dark") {
        root.classList.add("dark");
        setIsDark(true);
      } else {
        setIsDark(root.classList.contains("dark"));
      }
      if (typeof window !== "undefined" && window.location?.pathname) {
        const path = window.location.pathname;
        if (SENTINEL_NAV_ITEMS.some((it) => it.route === path)) {
          setInternalRoute(path);
        }
      }
    } catch {
      // Abaikan pada lingkungan SSR/sandbox terbatas
    }
  }, []);

  function toggleTheme() {
    const nextDark = !isDark;
    setIsDark(nextDark);
    try {
      const root = document.documentElement;
      if (nextDark) {
        root.classList.add("dark");
        localStorage.setItem("theme", "dark");
      } else {
        root.classList.remove("dark");
        localStorage.setItem("theme", "light");
      }
    } catch {
      // Abaikan bila localStorage diblokir
    }
  }

  function toggleCategory(cat: string) {
    setOpenCategories((prev) => ({
      ...prev,
      [cat]: !prev[cat]
    }));
  }

  const filteredItems = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return SENTINEL_NAV_ITEMS;
    return SENTINEL_NAV_ITEMS.filter(
      (item) =>
        item.title.toLowerCase().includes(q) ||
        item.route.toLowerCase().includes(q) ||
        (item.badge && item.badge.toLowerCase().includes(q)) ||
        item.category.toLowerCase().includes(q)
    );
  }, [searchQuery]);

  // Token kelas Glassmorphism adaptif untuk Dark Glass & Light Glass
  const sidebarSurface = isDark
    ? "bg-[#0B0914]/75 backdrop-blur-2xl border-white/[0.11] text-slate-100 shadow-[0_24px_60px_-15px_rgba(0,0,0,0.75)]"
    : "bg-white/80 backdrop-blur-2xl border-slate-900/[0.08] text-slate-900 shadow-[0_20px_50px_-12px_rgba(15,23,42,0.08)]";

  const glassPill = isDark
    ? "bg-white/[0.05] border border-white/[0.1] text-slate-200"
    : "bg-slate-900/[0.04] border border-slate-900/[0.08] text-slate-800";

  const mutedText = isDark ? "text-slate-400" : "text-slate-500";

  const sidebarContent = (
    <aside
      aria-label="Navigasi Modul Sentinel-ID"
      className={`flex flex-col h-full rounded-3xl border transition-all duration-300 select-none ${sidebarSurface} ${
        isCollapsed ? "w-20 p-3" : "w-72 p-4"
      }`}
    >
      {/* Top Header: Brand Logo + Collapse Toggle */}
      <div className="flex items-center justify-between gap-2 pb-3 border-b border-current/10">
        <a
          href="/"
          onClick={(e) => {
            if (onSelectRoute) {
              e.preventDefault();
              setInternalRoute("/");
              onSelectRoute(SENTINEL_NAV_ITEMS[0]);
            }
          }}
          className="flex items-center gap-2.5 min-w-0 group"
        >
          <div className="w-9 h-9 rounded-2xl bg-gradient-to-br from-pink-500 via-purple-600 to-indigo-600 flex items-center justify-center text-white shadow-lg shadow-pink-500/25 shrink-0 group-hover:scale-105 transition">
            <Shield className="w-5 h-5" />
          </div>
          {!isCollapsed && (
            <div className="min-w-0">
              <div className="flex items-center gap-1.5">
                <span className="font-extrabold tracking-tight text-sm truncate">
                  SENTINEL-ID
                </span>
                <span
                  className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse shrink-0"
                  title="100% Passive GET-Only"
                />
              </div>
              <p className={`text-[10px] font-mono uppercase tracking-wider truncate ${mutedText}`}>
                Security &amp; SEO Master
              </p>
            </div>
          )}
        </a>

        <div className="flex items-center gap-1 shrink-0">
          <button
            type="button"
            onClick={() => setIsCollapsed(!isCollapsed)}
            className={`p-2 rounded-xl transition hover:opacity-80 ${glassPill}`}
            title={isCollapsed ? "Perluas Sidebar" : "Ciutkan Sidebar (Mode Ringkas)"}
            aria-label="Ubah Ukuran Sidebar"
          >
            {isCollapsed ? (
              <PanelLeftOpen className="w-4 h-4" />
            ) : (
              <PanelLeftClose className="w-4 h-4" />
            )}
          </button>

          {onClose && (
            <button
              type="button"
              onClick={onClose}
              className={`lg:hidden p-2 rounded-xl ${glassPill}`}
              aria-label="Tutup Menu"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>
      </div>

      {/* Search Bar & Theme Switcher Row */}
      {!isCollapsed ? (
        <div className="pt-3 space-y-2">
          <div className={`flex items-center gap-2 px-3 py-2 rounded-2xl ${glassPill}`}>
            <Search className="w-3.5 h-3.5 text-pink-500 shrink-0" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter 22 modul audit..."
              className="w-full bg-transparent text-xs focus:outline-none"
              aria-label="Filter modul audit"
            />
            {searchQuery && (
              <button
                type="button"
                onClick={() => setSearchQuery("")}
                className={`text-[10px] font-mono ${mutedText}`}
              >
                Reset
              </button>
            )}
          </div>

          {/* Built-in Dark / Light Glass Switcher */}
          <div className="flex items-center justify-between gap-2">
            <button
              type="button"
              onClick={toggleTheme}
              className={`flex-1 py-1.5 px-3 rounded-xl text-xs font-medium flex items-center justify-between transition ${glassPill}`}
            >
              <span className="flex items-center gap-1.5">
                {isDark ? (
                  <Moon className="w-3.5 h-3.5 text-purple-400" />
                ) : (
                  <Sun className="w-3.5 h-3.5 text-amber-500" />
                )}
                <span>{isDark ? "Dark Glass" : "Light Glass"}</span>
              </span>
              <span className={`text-[10px] font-mono ${mutedText}`}>Ubah</span>
            </button>
          </div>
        </div>
      ) : (
        <div className="pt-3 flex flex-col items-center gap-2">
          <button
            type="button"
            onClick={toggleTheme}
            className={`p-2.5 rounded-2xl transition ${glassPill}`}
            title={isDark ? "Beralih ke Light Glass" : "Beralih ke Dark Glass"}
            aria-label="Ganti Tema"
          >
            {isDark ? (
              <Sun className="w-4 h-4 text-amber-400" />
            ) : (
              <Moon className="w-4 h-4 text-indigo-600" />
            )}
          </button>
        </div>
      )}

      {/* Navigation Categories & Module List */}
      <nav className="flex-1 overflow-y-auto py-3 space-y-3 pr-1">
        {CATEGORIES.map((category) => {
          const groupItems = filteredItems.filter((item) => item.category === category);
          if (groupItems.length === 0) return null;
          const isOpen = openCategories[category] ?? true;

          return (
            <div key={category} className="space-y-1">
              {!isCollapsed && (
                <button
                  type="button"
                  onClick={() => toggleCategory(category)}
                  className={`w-full flex items-center justify-between px-2 py-1 text-[10px] font-mono uppercase tracking-wider ${mutedText} hover:opacity-80`}
                >
                  <span>{category}</span>
                  {isOpen ? (
                    <ChevronDown className="w-3 h-3" />
                  ) : (
                    <ChevronRight className="w-3 h-3" />
                  )}
                </button>
              )}

              {(isOpen || isCollapsed) && (
                <div className="space-y-1">
                  {groupItems.map((item) => {
                    const isActive = currentRoute === item.route;
                    return (
                      <a
                        key={item.id}
                        href={item.route}
                        onClick={(e) => {
                          if (onSelectRoute) {
                            e.preventDefault();
                            setInternalRoute(item.route);
                            onSelectRoute(item);
                            if (onClose) onClose();
                          }
                        }}
                        title={isCollapsed ? `${item.title} (${item.route})` : item.description}
                        className={`group flex items-center justify-between gap-2 rounded-2xl transition-all ${
                          isCollapsed ? "p-2.5 justify-center" : "px-3 py-2"
                        } ${
                          isActive
                            ? isDark
                              ? "bg-gradient-to-r from-pink-500/20 via-purple-500/20 to-indigo-500/15 border border-pink-500/40 text-white font-semibold shadow-sm"
                              : "bg-gradient-to-r from-pink-500/15 via-purple-500/15 to-indigo-500/10 border border-purple-500/35 text-slate-900 font-semibold shadow-sm"
                            : isDark
                            ? "text-slate-300 hover:bg-white/[0.05] border border-transparent"
                            : "text-slate-700 hover:bg-slate-900/[0.04] border border-transparent"
                        }`}
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          <span
                            className={`shrink-0 transition-transform group-hover:scale-105 ${
                              isActive
                                ? "text-pink-500"
                                : isDark
                                ? "text-slate-400 group-hover:text-pink-400"
                                : "text-slate-500 group-hover:text-purple-600"
                            }`}
                          >
                            <ModuleIcon name={item.iconName} className="w-4 h-4" />
                          </span>
                          {!isCollapsed && (
                            <span className="text-xs truncate">{item.title}</span>
                          )}
                        </div>

                        {!isCollapsed && item.badge && (
                          <span
                            className={`text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded-md border shrink-0 ${getBadgeStyle(
                              item.badgeTone,
                              isDark
                            )}`}
                          >
                            {item.badge}
                          </span>
                        )}
                      </a>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </nav>

      {/* Bottom Footer: GDG Bandung Verified Badge & Lead Author Kasyaf */}
      <div className="pt-3 border-t border-current/10 space-y-2">
        {!isCollapsed ? (
          <>
            <div
              className={`rounded-2xl p-2.5 flex items-center justify-between ${
                isDark
                  ? "bg-emerald-950/40 border border-emerald-500/30"
                  : "bg-emerald-500/10 border border-emerald-600/25"
              }`}
            >
              <div className="min-w-0">
                <div className="flex items-center gap-1 text-[10px] font-mono font-semibold text-emerald-500">
                  <span>&lt;&gt;</span>
                  <span>SUDAH TERVERIFIKASI</span>
                </div>
                <div className="text-xs font-bold truncate mt-0.5">
                  Google Developer Bandung
                </div>
              </div>
              <CheckCircle2 className="w-4 h-4 text-emerald-500 shrink-0" />
            </div>

            <div className={`rounded-2xl p-2.5 flex items-center justify-between ${glassPill}`}>
              <div className="flex items-center gap-2.5 min-w-0">
                <div className="w-8 h-8 rounded-full bg-gradient-to-br from-pink-500 to-purple-600 flex items-center justify-center text-white text-xs font-bold shrink-0">
                  K
                </div>
                <div className="min-w-0">
                  <div className={`text-[10px] font-mono uppercase ${mutedText}`}>
                    Lead Author
                  </div>
                  <div className="text-xs font-bold truncate">Kasyaf</div>
                </div>
              </div>
              <ExternalLink className={`w-3.5 h-3.5 shrink-0 ${mutedText}`} />
            </div>
          </>
        ) : (
          <div className="flex flex-col items-center gap-2">
            <div
              className="w-9 h-9 rounded-2xl bg-emerald-500/15 border border-emerald-500/30 flex items-center justify-center text-emerald-500"
              title="Terverifikasi: Google Developer Bandung"
            >
              <CheckCircle2 className="w-4 h-4" />
            </div>
            <div
              className="w-8 h-8 rounded-full bg-gradient-to-br from-pink-500 to-purple-600 flex items-center justify-center text-white text-xs font-bold"
              title="Lead Author: Kasyaf"
            >
              K
            </div>
          </div>
        )}
      </div>
    </aside>
  );

  return (
    <>
      {/* Desktop Sidebar */}
      <div className="hidden lg:block h-[calc(100vh-2rem)] sticky top-4 shrink-0">
        {sidebarContent}
      </div>

      {/* Mobile Drawer Overlay */}
      {open && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div
            className="fixed inset-0 bg-black/50 backdrop-blur-sm"
            onClick={onClose}
          />
          <div className="relative z-10 h-full p-3">{sidebarContent}</div>
        </div>
      )}
    </>
  );
}

/**
 * Default export untuk pratinjau langsung di Canvas sekaligus kompatibel bila diimpor sebagai default.
 */
export default function App() {
  const [selectedItem, setSelectedItem] = useState<NavModuleItem>(SENTINEL_NAV_ITEMS[0]);
  const [mobileDrawerOpen, setMobileDrawerOpen] = useState<boolean>(false);
  const [isDarkPreview, setIsDarkPreview] = useState<boolean>(true);

  useEffect(() => {
    const observer = new MutationObserver(() => {
      setIsDarkPreview(document.documentElement.classList.contains("dark"));
    });
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ["class"]
    });
    return () => observer.disconnect();
  }, []);

  const stageBg = isDarkPreview
    ? "bg-[#07070C] text-slate-100"
    : "bg-[#F5F5F7] text-slate-900";
  const stageCard = isDarkPreview
    ? "bg-white/[0.04] backdrop-blur-2xl border border-white/[0.11]"
    : "bg-white/75 backdrop-blur-2xl border border-slate-900/[0.08]";
  const stageMuted = isDarkPreview ? "text-slate-400" : "text-slate-600";

  return (
    <div className={`min-h-screen transition-colors duration-300 ${stageBg} p-3 sm:p-4`}>
      {/* Ambient Background Glow */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden z-0">
        <div className="absolute -top-24 -left-24 w-96 h-96 rounded-full bg-pink-500/15 blur-[110px]" />
        <div className="absolute top-1/3 -right-24 w-96 h-96 rounded-full bg-purple-600/15 blur-[110px]" />
      </div>

      <div className="relative z-10 max-w-7xl mx-auto flex gap-5 items-start">
        <AppSidebar
          open={mobileDrawerOpen}
          onClose={() => setMobileDrawerOpen(false)}
          activeRoute={selectedItem.route}
          onSelectRoute={(item) => setSelectedItem(item)}
        />

        {/* Interactive Stage Previewing the Selected Sidebar Module */}
        <main className="flex-1 min-w-0 space-y-5">
          <div className={`rounded-3xl p-5 sm:p-6 flex flex-wrap items-center justify-between gap-4 ${stageCard}`}>
            <div className="flex items-center gap-3">
              <button
                type="button"
                onClick={() => setMobileDrawerOpen(true)}
                className="lg:hidden px-3 py-2 rounded-xl border border-current/15 text-xs font-semibold"
              >
                ☰ Buka Sidebar
              </button>
              <div>
                <div className="flex items-center gap-2 text-xs font-mono text-pink-500">
                  <Sparkles className="w-3.5 h-3.5" />
                  <span>PRATINJAU KOMPONEN: components/app-sidebar.tsx</span>
                </div>
                <h1 className="text-xl sm:text-2xl font-bold mt-1">
                  {selectedItem.title}
                </h1>
              </div>
            </div>

            <span className="px-3 py-1.5 rounded-xl font-mono text-xs bg-cyan-500/10 text-cyan-500 border border-cyan-500/25">
              Rute Aktif: {selectedItem.route}
            </span>
          </div>

          <div className={`rounded-3xl p-6 space-y-4 ${stageCard}`}>
            <div className="flex flex-wrap items-center gap-2 text-xs font-mono">
              <span className="px-2.5 py-1 rounded-lg bg-pink-500/15 text-pink-500 font-semibold">
                {selectedItem.category}
              </span>
              {selectedItem.badge && (
                <span className="px-2.5 py-1 rounded-lg bg-purple-500/15 text-purple-400 font-semibold">
                  Badge: {selectedItem.badge}
                </span>
              )}
            </div>

            <p className={`text-sm sm:text-base leading-relaxed ${stageMuted}`}>
              {selectedItem.description}
            </p>

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
              <div className={`p-4 rounded-2xl ${stageCard}`}>
                <div className={`text-[11px] font-mono uppercase ${stageMuted}`}>
                  Mode Sidebar
                </div>
                <div className="text-sm font-bold mt-1">
                  Expanded &amp; Mini Icon Dock
                </div>
                <p className={`text-xs mt-1 ${stageMuted}`}>
                  Klik ikon di kanan atas sidebar untuk menciutkan menjadi dock ikon ramping.
                </p>
              </div>
              <div className={`p-4 rounded-2xl ${stageCard}`}>
                <div className={`text-[11px] font-mono uppercase ${stageMuted}`}>
                  Tema Kaca (Glass)
                </div>
                <div className="text-sm font-bold mt-1">
                  Dark Glass &amp; Light Glass
                </div>
                <p className={`text-xs mt-1 ${stageMuted}`}>
                  Gunakan tombol tema di dalam sidebar untuk menguji kontras gelap dan terang.
                </p>
              </div>
              <div className={`p-4 rounded-2xl ${stageCard}`}>
                <div className={`text-[11px] font-mono uppercase ${stageMuted}`}>
                  Kompatibilitas Repo
                </div>
                <div className="text-sm font-bold mt-1">
                  Drop-in `AppSidebar`
                </div>
                <p className={`text-xs mt-1 ${stageMuted}`}>
                  Mengekspor `AppSidebar` dengan seluruh props opsional sehingga langsung cocok dengan `AppShell`.
                </p>
              </div>
            </div>
          </div>
        </main>
      </div>
    </div>
  );
}
