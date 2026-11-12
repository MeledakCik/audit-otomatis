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
  ArrowRight,
  Activity,
  Copy,
  Check,
  Menu,
  X
} from "lucide-react";

// ============================================================================
// DATA KONFIGURASI 22 MODUL & 8 ENGINE PASIF (GROUNDED IN REPO AUDIT-OTOMATIS)
// ============================================================================
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

export const SENTINEL_NAV_ITEMS: NavModuleItem[] = [
  { id: "overview", title: "Overview & Scan", route: "/", badge: "VAULT", badgeTone: "purple", category: "Core Audit & Scan", description: "Unified Deep Security Scanner (8 engine pasif sekaligus) & ringkasan postur domain.", iconName: "shield" },
  { id: "seo-master", title: "SEO Master & Rank #1", route: "/scan/seo-master", badge: "GLOBAL", badgeTone: "emerald", category: "Core Audit & Scan", description: "Audit 35+ sinyal Google SERP, 13 tag hreflang internasional & JSON-LD Schema.org.", iconName: "trending" },
  { id: "sentinel-vault", title: "Sentinel Vault & Klaim", route: "/scan/sentinel", badge: "AES", badgeTone: "pink", category: "Core Audit & Scan", description: "Audit file sensitif (.env, .git/HEAD, backup.zip) & Brankas Bukti AES-256-GCM.", iconName: "lock" },
  { id: "qc-otomatis", title: "QC Otomatis", route: "/qc", badge: "QC", badgeTone: "cyan", category: "Core Audit & Scan", description: "Audit kualitas SEO on-page, performa Core Web Vitals & pemeriksaan broken link.", iconName: "clipboard" },
  { id: "scan-history", title: "Scan History", route: "/history", category: "Core Audit & Scan", description: "Riwayat pemindaian domain dan perbandingan temuan antar waktu.", iconName: "clock" },
  { id: "request-inspector", title: "Request Inspector", route: "/requests", category: "Core Audit & Scan", description: "Log transparan seluruh HTTP GET/HEAD request dalam batas 100 request budget.", iconName: "terminal" },
  { id: "header-armor", title: "Header Armor", route: "/scan/headers", badge: "HTTP", badgeTone: "pink", category: "Vulnerability & Code", description: "Skor dan analisis keamanan HTTP response headers (CSP, HSTS, XFO, Permissions-Policy).", iconName: "shield-alert" },
  { id: "secret-hunter", title: "Secret Hunter", route: "/scan/secrets", badge: "AST", badgeTone: "amber", category: "Vulnerability & Code", description: "Deteksi API key, token & kredensial bocor pada bundle JavaScript.", iconName: "key" },
  { id: "exposure-check", title: "Exposure Check", route: "/scan/exposure", category: "Vulnerability & Code", description: "Pemeriksaan pasif eksposur file konfigurasi, wp2shell, php2shell, node2shell, go2shell & py2shell.", iconName: "alert" },
  { id: "js-supply-chain", title: "JS Supply Chain", route: "/scan/js", badge: "CVE", badgeTone: "purple", category: "Vulnerability & Code", description: "Deteksi pustaka pihak ketiga usang, pencocokan database OSV/NVD CVE & tracker skrip.", iconName: "file-code" },
  { id: "ssl-tls-checker", title: "SSL/TLS Checker", route: "/scan/ssl", badge: "TLS", badgeTone: "emerald", category: "Vulnerability & Code", description: "Inspeksi rantai sertifikat, masa berlaku, cipher suite & protokol TLS 1.3.", iconName: "award" },
  { id: "maintenance-log-ai", title: "Maintenance Log AI", route: "/maintenance-log", badge: "AI", badgeTone: "pink", category: "Vulnerability & Code", description: "Rekomendasi perbaikan terstruktur dan catatan pemeliharaan berbasis AI.", iconName: "wrench" },
  { id: "attack-surface-map", title: "Attack Surface Map", route: "/scan/map", badge: "GRAPH", badgeTone: "cyan", category: "Recon & Threat Intel", description: "Visualisasi graf interaktif relasi halaman, bundle JS, dan endpoint API.", iconName: "network" },
  { id: "subdomain-watch", title: "Subdomain Watch", route: "/scan/subdomain", badge: "CT", badgeTone: "cyan", category: "Recon & Threat Intel", description: "Enumerasi Certificate Transparency (crt.sh) & deteksi risiko subdomain takeover.", iconName: "globe" },
  { id: "dns-intelligence", title: "DNS Intelligence", route: "/scan/dns", badge: "DoH", badgeTone: "emerald", category: "Recon & Threat Intel", description: "Audit record A/MX/TXT serta proteksi anti-spoofing email SPF & DMARC.", iconName: "radio" },
  { id: "tech-stack", title: "Tech Stack", route: "/scan/stack", category: "Recon & Threat Intel", description: "Identifikasi framework, CMS, CDN, WAF, dan server web secara pasif.", iconName: "layers" },
  { id: "breach-peek", title: "Breach Peek", route: "/scan/breach", badge: "OSINT", badgeTone: "rose", category: "Recon & Threat Intel", description: "Pemeriksaan eksposur domain/email pada insiden kebocoran data publik.", iconName: "eye" },
  { id: "osint-lookup", title: "OSINT Lookup", route: "/scan/osint", badge: "RECON", badgeTone: "amber", category: "Recon & Threat Intel", description: "Reconnaissance publik untuk username, email (MX/Gravatar), domain & nama.", iconName: "user-check" },
  { id: "shield-status", title: "Shield Status", route: "/scan/shield-status", category: "Recon & Threat Intel", description: "Pemantauan ketahanan WAF/Cloudflare Edge dan status proteksi domain.", iconName: "shield-check" },
  { id: "documentation", title: "Documentation", route: "/docs", category: "Resources & Admin", description: "Dokumentasi arsitektur modular v2/v3.6 dan standar audit pasif GET-only.", iconName: "book" },
  { id: "api-reference", title: "API Reference", route: "/api-docs", category: "Resources & Admin", description: "Spesifikasi endpoint REST API pasif (termasuk GET /api/osint).", iconName: "code" },
  { id: "admin-console", title: "Admin Console", route: "/admin", badge: "ADMIN", badgeTone: "amber", category: "Resources & Admin", description: "Command Center untuk manajemen Sentinel Vault AES-256-GCM dan klaim pemilik domain.", iconName: "settings" }
];

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

function ModuleIcon({ name, className = "w-4 h-4" }: { name: string; className?: string }) {
  switch (name) {
    case "shield": return <Shield className={className} />;
    case "trending": return <TrendingUp className={className} />;
    case "lock": return <Lock className={className} />;
    case "clipboard": return <ClipboardCheck className={className} />;
    case "clock": return <Clock className={className} />;
    case "terminal": return <Terminal className={className} />;
    case "shield-alert": return <ShieldAlert className={className} />;
    case "key": return <KeyRound className={className} />;
    case "alert": return <AlertTriangle className={className} />;
    case "file-code": return <FileCode2 className={className} />;
    case "award": return <Award className={className} />;
    case "wrench": return <Wrench className={className} />;
    case "network": return <Network className={className} />;
    case "globe": return <Globe className={className} />;
    case "radio": return <Radio className={className} />;
    case "layers": return <Layers className={className} />;
    case "eye": return <Eye className={className} />;
    case "user-check": return <UserCheck className={className} />;
    case "shield-check": return <ShieldCheck className={className} />;
    case "book": return <BookOpen className={className} />;
    case "code": return <Code2 className={className} />;
    case "settings": return <Settings className={className} />;
    default: return <Shield className={className} />;
  }
}

// ============================================================================
// KOMPONEN 1: AppSidebar (TANPA DUPLIKASI LOGO HEADER — LANGSUNG FILTER & MENU)
// ============================================================================
export function AppSidebar({
  open = false,
  onClose,
  collapsed = false,
  onToggleCollapse,
  activeRoute = "/",
  onSelectRoute,
  isDark = true
}: {
  open?: boolean;
  onClose?: () => void;
  collapsed?: boolean;
  onToggleCollapse?: () => void;
  activeRoute?: string;
  onSelectRoute?: (item: NavModuleItem) => void;
  isDark?: boolean;
}) {
  const [searchQuery, setSearchQuery] = useState("");
  const [openCats, setOpenCats] = useState<Record<string, boolean>>({
    "Core Audit & Scan": true,
    "Vulnerability & Code": true,
    "Recon & Threat Intel": true,
    "Resources & Admin": true
  });

  const filteredItems = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    if (!q) return SENTINEL_NAV_ITEMS;
    return SENTINEL_NAV_ITEMS.filter(
      (it) =>
        it.title.toLowerCase().includes(q) ||
        it.route.toLowerCase().includes(q) ||
        (it.badge && it.badge.toLowerCase().includes(q))
    );
  }, [searchQuery]);

  const cardSurface = isDark
    ? "bg-[#0D0B18]/75 backdrop-blur-2xl border-white/[0.09] text-slate-100 shadow-[0_20px_50px_-15px_rgba(0,0,0,0.7)]"
    : "bg-white/80 backdrop-blur-2xl border-slate-900/[0.08] text-slate-900 shadow-[0_16px_40px_-12px_rgba(15,23,42,0.07)]";
  const pillSurface = isDark
    ? "bg-white/[0.05] border border-white/[0.09] text-slate-200"
    : "bg-slate-900/[0.04] border border-slate-900/[0.08] text-slate-800";
  const mutedText = isDark ? "text-slate-400" : "text-slate-500";

  const categories: NavModuleItem["category"][] = [
    "Core Audit & Scan",
    "Vulnerability & Code",
    "Recon & Threat Intel",
    "Resources & Admin"
  ];

  const inner = (
    <aside
      aria-label="Navigasi Modul"
      className={`flex flex-col h-full rounded-3xl border transition-all duration-300 ${cardSurface} ${
        collapsed ? "w-[72px] p-2.5" : "w-64 p-3.5"
      }`}
    >
      {/* Baris Pencarian & Tombol Ciutkan (TIDAK ADA LAGI LOGO GANDA DI SINI) */}
      <div className="flex items-center gap-2 pb-3 border-b border-current/10">
        {!collapsed && (
          <div className={`flex-1 flex items-center gap-2 px-3 py-2 rounded-xl ${pillSurface}`}>
            <Search className="w-3.5 h-3.5 text-pink-500 shrink-0" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter modul audit..."
              className="w-full bg-transparent text-xs focus:outline-none"
              aria-label="Filter modul audit"
            />
          </div>
        )}
        {onToggleCollapse && (
          <button
            type="button"
            onClick={onToggleCollapse}
            className={`p-2 rounded-xl transition hover:opacity-80 ${pillSurface} ${
              collapsed ? "mx-auto" : "shrink-0"
            }`}
            title={collapsed ? "Perluas Sidebar" : "Ciutkan Sidebar"}
          >
            {collapsed ? <PanelLeftOpen className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
          </button>
        )}
        {onClose && (
          <button
            type="button"
            onClick={onClose}
            className={`lg:hidden p-2 rounded-xl ${pillSurface}`}
          >
            <X className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Daftar 22 Modul */}
      <nav className="flex-1 overflow-y-auto py-3 space-y-3 pr-0.5">
        {categories.map((cat) => {
          const items = filteredItems.filter((i) => i.category === cat);
          if (!items.length) return null;
          const isOpen = openCats[cat] ?? true;

          return (
            <div key={cat} className="space-y-1">
              {!collapsed && (
                <button
                  type="button"
                  onClick={() => setOpenCats((p) => ({ ...p, [cat]: !isOpen }))}
                  className={`w-full flex items-center justify-between px-2 py-1 text-[10px] font-mono uppercase tracking-wider ${mutedText}`}
                >
                  <span>{cat}</span>
                  {isOpen ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                </button>
              )}

              {(isOpen || collapsed) && (
                <div className="space-y-1">
                  {items.map((item) => {
                    const isAct = activeRoute === item.route;
                    return (
                      <a
                        key={item.id}
                        href={item.route}
                        onClick={(e) => {
                          if (onSelectRoute) {
                            e.preventDefault();
                            onSelectRoute(item);
                            if (onClose) onClose();
                          }
                        }}
                        title={collapsed ? item.title : item.description}
                        className={`flex items-center justify-between gap-2 rounded-xl transition-all ${
                          collapsed ? "p-2.5 justify-center" : "px-2.5 py-2"
                        } ${
                          isAct
                            ? isDark
                              ? "bg-gradient-to-r from-pink-500/20 to-purple-600/20 border border-pink-500/40 text-white font-semibold"
                              : "bg-gradient-to-r from-pink-500/15 to-purple-600/15 border border-purple-500/35 text-slate-900 font-semibold"
                            : isDark
                            ? "text-slate-300 hover:bg-white/[0.05] border border-transparent"
                            : "text-slate-700 hover:bg-slate-900/[0.04] border border-transparent"
                        }`}
                      >
                        <div className="flex items-center gap-2.5 min-w-0">
                          <span className={isAct ? "text-pink-500" : mutedText}>
                            <ModuleIcon name={item.iconName} className="w-4 h-4" />
                          </span>
                          {!collapsed && <span className="text-xs truncate">{item.title}</span>}
                        </div>
                        {!collapsed && item.badge && (
                          <span className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded-md bg-pink-500/15 text-pink-500 border border-pink-500/25 shrink-0">
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

      {/* Footer Sidebar: Author Kasyaf */}
      {!collapsed && (
        <div className="pt-2.5 border-t border-current/10">
          <div className={`rounded-2xl p-2.5 flex items-center justify-between ${pillSurface}`}>
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="w-7 h-7 rounded-full bg-gradient-to-br from-pink-500 to-purple-600 flex items-center justify-center text-white text-xs font-bold shrink-0">
                K
              </div>
              <div className="min-w-0">
                <div className={`text-[9px] font-mono uppercase ${mutedText}`}>Lead Author</div>
                <div className="text-xs font-bold truncate">Kasyaf · v3.6</div>
              </div>
            </div>
            <ExternalLink className={`w-3.5 h-3.5 shrink-0 ${mutedText}`} />
          </div>
        </div>
      )}
    </aside>
  );

  return (
    <>
      <div className="hidden lg:block h-[calc(100vh-5.75rem)] sticky top-20 shrink-0">
        {inner}
      </div>
      {open && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div className="fixed inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
          <div className="relative z-10 h-full p-3">{inner}</div>
        </div>
      )}
    </>
  );
}

// ============================================================================
// KOMPONEN 2: HomePage (`app/page.tsx` — TANPA HEADER GANDA, TOP-ALIGNED GRID)
// ============================================================================
export function HomePage({
  isDark = true,
  onNavigateRoute
}: {
  isDark?: boolean;
  onNavigateRoute?: (route: string) => void;
}) {
  const [pageSubTab, setPageSubTab] = useState<"landing" | "scanner" | "modules">("landing");
  const [targetDomain, setTargetDomain] = useState("kasyaf-cv.my.id");
  const [scanMode, setScanMode] = useState<"full" | "vault">("full");
  const [cfResilient, setCfResilient] = useState(true);
  const [consentChecked, setConsentChecked] = useState(true);
  const [isScanning, setIsScanning] = useState(false);
  const [lastScannedDomain, setLastScannedDomain] = useState("kasyaf-cv.my.id");

  const [activeShellId, setActiveShellId] = useState("wp2shell");
  const [activeVaultStep, setActiveVaultStep] = useState(0);
  const [moduleCategory, setModuleCategory] = useState("Semua");
  const [severityFilter, setSeverityFilter] = useState<"ALL" | "MEDIUM" | "LOW" | "INFO">("ALL");
  const [faqLang, setFaqLang] = useState<"id" | "en">("id");
  const [openFaqIdx, setOpenFaqIdx] = useState(0);
  const [copiedNotice, setCopiedNotice] = useState("");

  const activeShell = useMemo(
    () => SHELL_SURFACES.find((s) => s.id === activeShellId) || SHELL_SURFACES[0],
    [activeShellId]
  );

  const filteredModules = useMemo(() => {
    if (moduleCategory === "Semua") return SENTINEL_NAV_ITEMS;
    return SENTINEL_NAV_ITEMS.filter((m) => m.category === moduleCategory);
  }, [moduleCategory]);

  const filteredFindings = useMemo(() => {
    if (severityFilter === "ALL") return INITIAL_FINDINGS;
    return INITIAL_FINDINGS.filter((f) => f.sev === severityFilter);
  }, [severityFilter]);

  function handleRunScan(e: React.FormEvent) {
    e.preventDefault();
    if (!consentChecked) return;
    const cleaned = targetDomain.trim().replace(/^https?:\/\//i, "").split("/")[0] || "kasyaf-cv.my.id";
    setTargetDomain(cleaned);
    setIsScanning(true);
    setTimeout(() => {
      setIsScanning(false);
      setLastScannedDomain(cleaned);
      setPageSubTab("scanner");
    }, 400);
  }

  function handleCopyReport() {
    const txt = `# Sentinel-ID Passive Security Report (${lastScannedDomain})\n- 1 URL Crawled | 11 JS Unpacked | 29/100 Requests\n- 0 CRITICAL, 0 HIGH, 6 MEDIUM (POTENTIAL), 4 LOW, 2 INFO`;
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(txt);
      }
    } catch {}
    setCopiedNotice("Tersalin!");
    setTimeout(() => setCopiedNotice(""), 2000);
  }

  const glassCard = isDark
    ? "bg-[#110E20]/70 backdrop-blur-2xl border border-white/[0.09] shadow-[0_20px_50px_-15px_rgba(0,0,0,0.65)]"
    : "bg-white/80 backdrop-blur-2xl border border-slate-900/[0.08] shadow-[0_16px_40px_-12px_rgba(15,23,42,0.06)]";
  const glassPill = isDark
    ? "bg-white/[0.05] border border-white/[0.09]"
    : "bg-slate-900/[0.04] border border-slate-900/[0.08]";
  const mutedText = isDark ? "text-slate-400" : "text-slate-600";

  return (
    <div className="space-y-8">
      {/* Compact Sub-View Bar (Tanpa Duplikasi Logo / GDG Badge / Tombol Tema!) */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className={`inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs ${glassPill}`}>
          <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="font-mono font-semibold text-emerald-500">100% GET-ONLY · ZERO-EXPLOIT</span>
          <span className={`hidden sm:inline ${mutedText}`}>· Standar Audit Pasif &amp; Brankas AES-256-GCM</span>
        </div>

        <div className={`inline-flex p-1 rounded-xl ${glassPill}`}>
          {(
            [
              { id: "landing", label: "Ringkasan & Scanner" },
              { id: "scanner", label: "Hasil Audit (12)" },
              { id: "modules", label: "Katalog 22 Modul" }
            ] as const
          ).map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setPageSubTab(t.id)}
              className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                pageSubTab === t.id
                  ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white shadow-sm"
                  : `${mutedText} hover:opacity-90`
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>
      </div>

      {pageSubTab === "landing" && (
        <>
          {/* HERO SECTION — TOP-ALIGNED (items-start), PROPORTIONAL FONT, ZERO EMPTY RIGHT VOID */}
          <section className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
            {/* Left Column (7 cols): Headline + Scanner Form */}
            <div className={`xl:col-span-7 rounded-3xl p-6 sm:p-7 space-y-5 ${glassCard}`}>
              <div className="space-y-3">
                <h1 className="text-2xl sm:text-3xl lg:text-4xl font-extrabold tracking-tight leading-[1.15]">
                  Keamanan Web Pasif.{" "}
                  <span className="bg-gradient-to-r from-pink-500 via-purple-500 to-cyan-500 bg-clip-text text-transparent">
                    Jernih, Ringan, Tanpa Risiko.
                  </span>
                </h1>
                <p className={`text-sm sm:text-base leading-relaxed ${mutedText}`}>
                  Analisis postur keamanan domain dan kesiapan SERP Google Global tanpa menembakkan payload yang merusak server. Menggabungkan{" "}
                  <strong className="text-pink-500 font-semibold">Multi-Page Crawler</strong>,{" "}
                  <strong className="text-purple-400 font-semibold">8 Engine Deep Shell &amp; OOB</strong>, dan{" "}
                  <strong className="text-emerald-500 font-semibold">Brankas Bukti AES-256-GCM</strong>.
                </p>
              </div>

              {/* Integrated Unified Deep Security Scanner Form */}
              <form onSubmit={handleRunScan} className={`p-4 rounded-2xl space-y-3.5 ${glassPill}`}>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5">
                    <button
                      type="button"
                      onClick={() => setScanMode("full")}
                      className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition ${
                        scanMode === "full"
                          ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white"
                          : mutedText
                      }`}
                    >
                      Full Scan + Deep Shell
                    </button>
                    <button
                      type="button"
                      onClick={() => setScanMode("vault")}
                      className={`px-3 py-1.5 rounded-xl text-xs font-semibold transition ${
                        scanMode === "vault"
                          ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white"
                          : mutedText
                      }`}
                    >
                      Brankas AES-256-GCM
                    </button>
                  </div>

                  <button
                    type="button"
                    onClick={() => setCfResilient(!cfResilient)}
                    className={`text-[11px] font-mono px-2.5 py-1 rounded-lg ${
                      cfResilient ? "bg-emerald-500/15 text-emerald-500" : mutedText
                    }`}
                  >
                    {cfResilient ? "✓ CF & WAF Resilient" : "Standard Mode"}
                  </button>
                </div>

                <div className="flex flex-col sm:flex-row gap-2.5">
                  <div className={`flex-1 flex items-center gap-2.5 px-3.5 py-2.5 rounded-xl ${glassCard}`}>
                    <Search className="w-4 h-4 text-pink-500 shrink-0" />
                    <input
                      type="text"
                      value={targetDomain}
                      onChange={(e) => setTargetDomain(e.target.value)}
                      placeholder="Masukkan domain (contoh: sentinel-id.net)"
                      className="w-full bg-transparent text-sm font-mono focus:outline-none"
                      aria-label="Target Domain"
                    />
                  </div>
                  <button
                    type="submit"
                    disabled={!consentChecked || isScanning}
                    className="px-5 py-2.5 rounded-xl font-semibold text-xs sm:text-sm text-white bg-gradient-to-r from-pink-500 via-purple-600 to-indigo-600 hover:opacity-95 disabled:opacity-50 transition shadow-lg shadow-pink-500/20 flex items-center justify-center gap-2 shrink-0"
                  >
                    <span>{isScanning ? "Memindai..." : "Mulai Deep Audit"}</span>
                    <ArrowRight className="w-4 h-4" />
                  </button>
                </div>

                <label className={`flex items-center gap-2 text-xs cursor-pointer ${mutedText}`}>
                  <input
                    type="checkbox"
                    checked={consentChecked}
                    onChange={(e) => setConsentChecked(e.target.checked)}
                    className="rounded text-pink-500"
                  />
                  <span>Saya adalah pemilik sah atau memiliki izin tertulis untuk mengaudit domain ini secara pasif.</span>
                </label>
              </form>

              {/* 4 Compact Stat Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5">
                {[
                  { label: "Deep Crawl", val: "50 URL", sub: "Depth 3 · 100 Req" },
                  { label: "Shell Surface", val: "8 Engine", sub: "wp/php/node/go/py" },
                  { label: "Sentinel Vault", val: "AES-256", sub: "Redaksi Publik" },
                  { label: "SEO Master #1", val: "13 Locale", sub: "Hreflang · JSON-LD" }
                ].map((st) => (
                  <div key={st.label} className={`rounded-2xl p-3 ${glassPill}`}>
                    <div className={`text-[10px] font-mono uppercase ${mutedText}`}>{st.label}</div>
                    <div className="text-base font-bold mt-0.5">{st.val}</div>
                    <div className={`text-[11px] truncate ${mutedText}`}>{st.sub}</div>
                  </div>
                ))}
              </div>
            </div>

            {/* Right Column (5 cols): Top-Aligned Architecture & 8-Engine Card (Zero Vertical Offset!) */}
            <div className={`xl:col-span-5 rounded-3xl p-6 space-y-4 ${glassCard}`}>
              <div className="flex items-center gap-3.5">
                <div className="w-12 h-12 rounded-2xl bg-gradient-to-br from-pink-500 via-purple-600 to-indigo-600 flex items-center justify-center text-white shadow-lg shadow-pink-500/25 shrink-0">
                  <Shield className="w-6 h-6" />
                </div>
                <div>
                  <span className="text-[10px] font-mono uppercase tracking-widest text-emerald-500 font-semibold">
                    PASSIVE ARCHITECTURE v2 + v3.6
                  </span>
                  <h2 className="text-lg font-bold leading-snug">
                    Unified Deep Security &amp; Vault Engine
                  </h2>
                  <p className={`text-xs font-mono ${mutedText}`}>
                    discovery → parsers → fingerprint → vuln → fuzzer
                  </p>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-xs">
                {[
                  "1. Multi-Page & Edge Crawler",
                  "2. AST JS & Secret Scan",
                  "3. wp/php/node/go/py Shell",
                  "4. WebShell & FileManager",
                  "5. Node Out-of-Bounds (OOB)",
                  "6. Brankas Bukti AES-256-GCM",
                  "7. Cloudflare/WAF & DoH Intel",
                  "8. Header & OSV/NVD CVE Intel"
                ].map((eng) => (
                  <div key={eng} className={`px-3 py-2.5 rounded-xl font-mono text-[11px] truncate ${glassPill}`}>
                    {eng}
                  </div>
                ))}
              </div>

              {/* Quick Links to SEO Master & Sentinel Vault */}
              <div className="grid grid-cols-2 gap-2.5 pt-1">
                <button
                  type="button"
                  onClick={() => onNavigateRoute && onNavigateRoute("/scan/sentinel")}
                  className={`p-3 rounded-2xl text-left transition hover:opacity-90 ${glassPill}`}
                >
                  <div className="text-[10px] font-mono text-pink-500 font-semibold">AES-256-GCM</div>
                  <div className="text-xs font-bold mt-0.5">Buka Sentinel Vault →</div>
                </button>
                <button
                  type="button"
                  onClick={() => onNavigateRoute && onNavigateRoute("/scan/seo-master")}
                  className={`p-3 rounded-2xl text-left transition hover:opacity-90 ${glassPill}`}
                >
                  <div className="text-[10px] font-mono text-emerald-500 font-semibold">13 HREFLANG</div>
                  <div className="text-xs font-bold mt-0.5">Buka SEO Master #1 →</div>
                </button>
              </div>
            </div>
          </section>

          {/* Interactive 8 Runtime Shell Selector */}
          <section className={`rounded-3xl p-6 space-y-5 ${glassCard}`}>
            <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-3">
              <div>
                <span className="text-[11px] font-mono uppercase tracking-widest text-pink-500 font-semibold">
                  Deep Passive Runtime &amp; Shell-Surface Engine
                </span>
                <h2 className="text-xl sm:text-2xl font-bold mt-0.5">
                  Inspeksi 8 Permukaan Runtime Secara Pasif
                </h2>
              </div>
              <div className={`flex flex-wrap gap-1 p-1 rounded-2xl ${glassPill}`}>
                {SHELL_SURFACES.map((s) => (
                  <button
                    key={s.id}
                    type="button"
                    onClick={() => setActiveShellId(s.id)}
                    className={`px-2.5 py-1.5 rounded-xl text-xs font-mono font-semibold transition ${
                      activeShellId === s.id
                        ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white"
                        : mutedText
                    }`}
                  >
                    {s.label}
                  </button>
                ))}
              </div>
            </div>

            <div className={`rounded-2xl p-5 grid grid-cols-1 lg:grid-cols-12 gap-5 items-center ${glassPill}`}>
              <div className="lg:col-span-7 space-y-1.5">
                <div className="text-xs font-mono text-pink-500 font-semibold">
                  {activeShell.label} · {activeShell.cwe}
                </div>
                <h3 className="text-lg font-bold">{activeShell.title}</h3>
                <p className={`text-xs sm:text-sm leading-relaxed ${mutedText}`}>{activeShell.desc}</p>
              </div>
              <div className="lg:col-span-5 grid grid-cols-1 sm:grid-cols-2 gap-2">
                {activeShell.paths.map((p) => (
                  <div key={p} className={`px-3 py-2 rounded-xl font-mono text-xs text-cyan-500 truncate ${glassCard}`}>
                    {p}
                  </div>
                ))}
              </div>
            </div>
          </section>

          {/* 4-Step AES-256-GCM Vault Stepper */}
          <section className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3.5">
            {VAULT_STEPS.map((st, idx) => (
              <button
                key={st.step}
                type="button"
                onClick={() => setActiveVaultStep(idx)}
                className={`rounded-2xl p-4 text-left transition ${glassCard} ${
                  activeVaultStep === idx ? "ring-2 ring-pink-500/70" : "opacity-85 hover:opacity-100"
                }`}
              >
                <div className="flex items-center justify-between">
                  <span className="text-xs font-mono font-bold text-pink-500">{st.step}</span>
                  <span className="text-[10px] font-mono text-emerald-500">{st.badge}</span>
                </div>
                <h3 className="text-sm font-bold mt-1.5">{st.title}</h3>
                <p className={`text-xs mt-1 leading-relaxed ${mutedText}`}>{st.summary}</p>
              </button>
            ))}
          </section>

          {/* Bilingual FAQ Accordion (1-Click ID/EN) */}
          <section className={`rounded-3xl p-6 space-y-4 ${glassCard}`}>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <span className="text-[11px] font-mono uppercase tracking-widest text-cyan-500 font-semibold">
                  Schema.org FAQPage · 13 Hreflang
                </span>
                <h2 className="text-xl font-bold mt-0.5">Pertanyaan Umum (FAQ)</h2>
              </div>
              <div className={`inline-flex p-1 rounded-xl ${glassPill}`}>
                <button
                  type="button"
                  onClick={() => setFaqLang("id")}
                  className={`px-3 py-1 rounded-lg text-xs font-semibold ${
                    faqLang === "id" ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white" : mutedText
                  }`}
                >
                  Indonesia
                </button>
                <button
                  type="button"
                  onClick={() => setFaqLang("en")}
                  className={`px-3 py-1 rounded-lg text-xs font-semibold ${
                    faqLang === "en" ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white" : mutedText
                  }`}
                >
                  English
                </button>
              </div>
            </div>

            <div className="space-y-2.5">
              {FAQ_DATA.map((item, idx) => {
                const isOpen = openFaqIdx === idx;
                return (
                  <div key={item.q_id} className={`rounded-2xl p-4 ${glassPill}`}>
                    <button
                      type="button"
                      onClick={() => setOpenFaqIdx(isOpen ? -1 : idx)}
                      className="w-full flex items-center justify-between gap-3 text-left"
                    >
                      <span className="text-xs sm:text-sm font-bold">
                        {faqLang === "id" ? item.q_id : item.q_en}
                      </span>
                      <ChevronDown className={`w-4 h-4 shrink-0 transition ${isOpen ? "rotate-180 text-pink-500" : mutedText}`} />
                    </button>
                    {isOpen && (
                      <p className={`mt-2.5 pt-2.5 border-t border-current/10 text-xs leading-relaxed ${mutedText}`}>
                        {faqLang === "id" ? item.a_id : item.a_en}
                      </p>
                    )}
                  </div>
                );
              })}
            </div>
          </section>
        </>
      )}

      {pageSubTab === "scanner" && (
        <section className={`rounded-3xl p-6 space-y-5 ${glassCard}`}>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <span className="text-xs font-mono text-emerald-500 font-semibold">
                HASIL PEMINDAIAN PASIF ({lastScannedDomain})
              </span>
              <h2 className="text-xl font-bold mt-0.5">
                1 URL Crawled · 11 JS Unpacked · 29/100 Requests · 0 Critical
              </h2>
            </div>
            <div className="flex items-center gap-2">
              {copiedNotice && <span className="text-xs font-mono text-emerald-500">{copiedNotice}</span>}
              <button
                type="button"
                onClick={handleCopyReport}
                className="px-3.5 py-2 rounded-xl text-xs font-semibold text-white bg-gradient-to-r from-pink-500 to-purple-600 flex items-center gap-1.5"
              >
                <Copy className="w-3.5 h-3.5" />
                <span>Salin Markdown</span>
              </button>
            </div>
          </div>

          <div className={`inline-flex p-1 rounded-xl ${glassPill}`}>
            {(["ALL", "MEDIUM", "LOW", "INFO"] as const).map((sev) => (
              <button
                key={sev}
                type="button"
                onClick={() => setSeverityFilter(sev)}
                className={`px-3 py-1 rounded-lg text-xs font-mono font-semibold ${
                  severityFilter === sev ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white" : mutedText
                }`}
              >
                {sev}
              </button>
            ))}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {filteredFindings.map((f) => (
              <div key={f.id} className={`rounded-2xl p-4 space-y-1.5 ${glassPill}`}>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-amber-500/15 text-amber-500">
                    {f.sev}
                  </span>
                  <span className="text-xs font-mono text-cyan-500 truncate">{f.path}</span>
                </div>
                <div className="text-sm font-bold">{f.module}</div>
                <p className={`text-xs leading-relaxed ${mutedText}`}>{f.detail}</p>
              </div>
            ))}
          </div>
        </section>
      )}

      {pageSubTab === "modules" && (
        <section className={`rounded-3xl p-6 space-y-5 ${glassCard}`}>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <h2 className="text-xl font-bold">Katalog 22 Modul Keamanan &amp; SEO</h2>
            <div className={`flex flex-wrap gap-1 p-1 rounded-xl ${glassPill}`}>
              {["Semua", "Core Audit & Scan", "Vulnerability & Code", "Recon & Threat Intel", "Resources & Admin"].map((c) => (
                <button
                  key={c}
                  type="button"
                  onClick={() => setModuleCategory(c)}
                  className={`px-2.5 py-1 rounded-lg text-xs font-medium ${
                    moduleCategory === c ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white" : mutedText
                  }`}
                >
                  {c}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3.5">
            {filteredModules.map((m) => (
              <div
                key={m.id}
                onClick={() => onNavigateRoute && onNavigateRoute(m.route)}
                className={`rounded-2xl p-4 cursor-pointer flex flex-col justify-between gap-3 transition hover:-translate-y-0.5 ${glassPill}`}
              >
                <div>
                  <div className="flex items-center justify-between text-[10px] font-mono">
                    <span className={mutedText}>{m.category}</span>
                    {m.badge && <span className="text-pink-500 font-bold">{m.badge}</span>}
                  </div>
                  <h3 className="text-sm font-bold mt-1">{m.title}</h3>
                  <p className={`text-xs mt-1 ${mutedText}`}>{m.description}</p>
                </div>
                <div className="flex items-center justify-between text-xs font-mono pt-2 border-t border-current/10">
                  <span className="text-cyan-500">{m.route}</span>
                  <span className="text-pink-500 font-sans font-semibold">Buka →</span>
                </div>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}

// ============================================================================
// KOMPONEN 3: UNIFIED APPSHELL PREVIEW (MEMPERLIHATKAN TATA LETAK BERSIH TANPA BUG)
// ============================================================================
export default function App() {
  const [isDark, setIsDark] = useState(true);
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [activeRoute, setActiveRoute] = useState("/");

  useEffect(() => {
    const root = document.documentElement;
    if (isDark) {
      root.classList.add("dark");
    } else {
      root.classList.remove("dark");
    }
  }, [isDark]);

  const activeItem = useMemo(
    () => SENTINEL_NAV_ITEMS.find((i) => i.route === activeRoute) || SENTINEL_NAV_ITEMS[0],
    [activeRoute]
  );

  const shellBg = isDark ? "bg-[#07070C] text-slate-50" : "bg-[#F5F5F7] text-slate-900";
  const headerGlass = isDark
    ? "bg-[#0D0B18]/80 backdrop-blur-2xl border border-white/[0.09] shadow-[0_12px_36px_rgba(0,0,0,0.6)]"
    : "bg-white/85 backdrop-blur-2xl border border-slate-900/[0.08] shadow-[0_12px_30px_rgba(15,23,42,0.06)]";
  const pillGlass = isDark
    ? "bg-white/[0.05] border border-white/[0.1]"
    : "bg-slate-900/[0.04] border border-slate-900/[0.08]";
  const mutedText = isDark ? "text-slate-400" : "text-slate-600";

  return (
    <div className={`min-h-screen relative transition-colors duration-300 ${shellBg}`}>
      {/* Ambient Liquid Glow */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden z-0">
        <div className="absolute -top-28 -left-24 w-96 h-96 rounded-full bg-pink-500/15 blur-[120px]" />
        <div className="absolute top-1/3 -right-24 w-96 h-96 rounded-full bg-purple-600/15 blur-[120px]" />
      </div>

      {/* SATU-SATUNYA HEADER BAR DI SELURUH APLIKASI (TIDAK ADA DUPLIKASI) */}
      <header className="sticky top-3 z-40 px-4 sm:px-6 pt-2">
        <div className={`max-w-[1400px] mx-auto rounded-2xl px-4 py-2.5 flex items-center justify-between gap-3 ${headerGlass}`}>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className={`lg:hidden p-2 rounded-xl ${pillGlass}`}
              aria-label="Buka Navigasi"
            >
              <Menu className="w-4 h-4" />
            </button>
            <button
              type="button"
              onClick={() => setActiveRoute("/")}
              className="flex items-center gap-2.5 text-left"
            >
              <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-pink-500 via-purple-600 to-indigo-600 flex items-center justify-center text-white shadow-md shadow-pink-500/20">
                <Shield className="w-4 h-4" />
              </div>
              <div>
                <div className="flex items-center gap-1.5">
                  <span className="font-extrabold tracking-tight text-sm sm:text-base">SENTINEL-ID</span>
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded-md bg-emerald-500/15 text-emerald-500 font-semibold">
                    v3.6
                  </span>
                </div>
              </div>
            </button>
          </div>

          {/* Rute Aktif / Breadcrumb Ringkas di Tengah */}
          <div className={`hidden md:flex items-center gap-2 px-3 py-1 rounded-xl text-xs font-mono ${pillGlass}`}>
            <span className={mutedText}>{activeItem.category}</span>
            <span className={mutedText}>/</span>
            <span className="text-pink-500 font-semibold">{activeItem.title}</span>
          </div>

          {/* Kanan: 1 Badge GDG Bandung & 1 Tombol Tema (Dark/Light) */}
          <div className="flex items-center gap-2">
            <div className="hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium bg-emerald-500/10 text-emerald-500 border border-emerald-500/25">
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>GDG Bandung Verified</span>
            </div>

            <button
              type="button"
              onClick={() => setIsDark(!isDark)}
              className={`px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition hover:scale-[1.02] ${pillGlass}`}
            >
              {isDark ? (
                <>
                  <Sun className="w-3.5 h-3.5 text-amber-400" />
                  <span>Light Glass</span>
                </>
              ) : (
                <>
                  <Moon className="w-3.5 h-3.5 text-indigo-600" />
                  <span>Dark Glass</span>
                </>
              )}
            </button>
          </div>
        </div>
      </header>

      {/* BODY LAYOUT: SIDEBAR KIRI + KONTEN UTAMA SEJAJAR DI ATAS (items-start) */}
      <div className="relative z-10 max-w-[1400px] mx-auto px-4 sm:px-6 pt-5 pb-16 flex gap-5 items-start">
        <AppSidebar
          open={sidebarOpen}
          onClose={() => setSidebarOpen(false)}
          collapsed={sidebarCollapsed}
          onToggleCollapse={() => setSidebarCollapsed(!sidebarCollapsed)}
          activeRoute={activeRoute}
          onSelectRoute={(item) => setActiveRoute(item.route)}
          isDark={isDark}
        />

        <main className="flex-1 min-w-0">
          <HomePage
            isDark={isDark}
            onNavigateRoute={(route) => setActiveRoute(route)}
          />
        </main>
      </div>
    </div>
  );
}
