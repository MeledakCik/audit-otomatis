"use client";

import React, { useState, useEffect, useMemo } from "react";
import {
  Shield,
  Sparkles,
  Search,
  Lock,
  Globe,
  Code2,
  Cpu,
  Eye,
  FileText,
  Server,
  Terminal,
  CheckCircle2,
  AlertTriangle,
  Info,
  ArrowRight,
  Sun,
  Moon,
  Layers,
  Activity,
  KeyRound,
  Copy,
  Check,
  RefreshCw,
  ChevronDown
} from "lucide-react";

type ScanMode = "full" | "vault";
type ViewTab = "overview" | "scanner" | "modules";
type SeverityFilter = "ALL" | "MEDIUM" | "LOW" | "INFO";
type FaqLang = "id" | "en";

interface ShellSurface {
  id: string;
  label: string;
  cwe: string;
  title: string;
  desc: string;
  paths: string[];
}

interface VaultStep {
  step: string;
  title: string;
  badge: string;
  summary: string;
}

interface SentinelModule {
  id: number;
  title: string;
  cat: "Core Audit & Scan" | "Vulnerability & Code" | "Recon & Threat Intel" | "Resources & Admin";
  route: string;
  badge: string;
  desc: string;
}

interface AuditFinding {
  id: string;
  sev: "MEDIUM" | "LOW" | "INFO";
  module: string;
  path: string;
  detail: string;
}

const SHELL_SURFACES: ShellSurface[] = [
  {
    id: "wp2shell",
    label: "wp2shell",
    cwe: "CWE-434 · CWE-538 · CWE-284",
    title: "WordPress RCE & Config Surface",
    desc: "Deteksi pasif wp-config.php.bak/~/.save, debug.log terbuka, xmlrpc.php aktif, enumerasi user REST API (/wp-json/wp/v2/users), installer terbuka, dan indeks /wp-content/uploads/.",
    paths: ["/wp-config.php.bak", "/wp-content/debug.log", "/xmlrpc.php", "/wp-json/wp/v2/users"]
  },
  {
    id: "php2shell",
    label: "php2shell",
    cwe: "CWE-94 · CWE-95 · CWE-489",
    title: "PHP Eval, Ignition & Profiler",
    desc: "Audit pasif Laravel Ignition debug RCE (CVE-2021-3129), PHPUnit eval-stdin.php (CVE-2017-9841), Symfony Profiler, phpinfo(), PHP-FPM status, dan eksposur composer.json.",
    paths: ["/_ignition/health-check", "/vendor/phpunit/.../eval-stdin.php", "/phpinfo.php", "/fpm-status"]
  },
  {
    id: "node2shell",
    label: "node2shell",
    cwe: "CWE-94 · CWE-502 · CWE-1321",
    title: "Node.js V8 Inspector & SSR Sinks",
    desc: "Deteksi port debug V8 Inspector (/json/version), PM2 ecosystem.config.js, Next.js dev stack-frame, serta sink AST child_process, vm.runInNewContext & prototype pollution.",
    paths: ["/json/version", "/ecosystem.config.js", "child_process / vm", "__proto__ pollution"]
  },
  {
    id: "go2shell",
    label: "go2shell",
    cwe: "CWE-215 · CWE-200 · CWE-489",
    title: "Go Runtime pprof & Expvar",
    desc: "Inspeksi pasif profil runtime Go (/debug/pprof/), kebocoran argumen binary (/debug/pprof/cmdline), goroutine/heap dump, serta variabel runtime expvar (/debug/vars).",
    paths: ["/debug/pprof/", "/debug/pprof/cmdline", "/debug/vars", "Go panic trace"]
  },
  {
    id: "py2shell",
    label: "py2shell",
    cwe: "CWE-94 · CWE-306 · CWE-489",
    title: "Python Werkzeug, Jupyter & Celery",
    desc: "Deteksi Werkzeug/Flask interactive debugger (/console), Jupyter Notebook kernel API tanpa autentikasi (/api/kernels), Celery Flower monitor (/api/workers), dan Django Debug Toolbar.",
    paths: ["/console", "/api/kernels", "/api/workers", "/__debug__/"]
  },
  {
    id: "node-oob",
    label: "node OOB",
    cwe: "CWE-119 · CWE-125 · CWE-787 · CWE-918",
    title: "Node Out-of-Bounds (OOB) & Memory",
    desc: "Deteksi snapshot memori V8 (/heapdump), alokasi Buffer.allocUnsafe & pembacaan TypedArray/DataView out-of-bounds, RangeError buffer leak, serta kandidat OOB SSRF/Webhook.",
    paths: ["/heapdump", "Buffer.allocUnsafe", "TypedArray OOB", "OOB Callback/SSRF"]
  },
  {
    id: "webshell",
    label: "webshell",
    cwe: "CWE-434 · CWE-94 · CWE-506",
    title: "Active WebShell & Stealth Backdoor",
    desc: "Deteksi tajam artefak WebShell aktif (WSO, FilesMan, b374k, ALFA Team, MariJUANA, Gel4y, IndoXploit, Mini Shell, c99/r57, p0wny) serta source PHP ter-obfuscate.",
    paths: ["/shell.php", "/wso.php", "/alfa.php", "/b374k.php"]
  },
  {
    id: "filemanager",
    label: "filemanager",
    cwe: "CWE-434 · CWE-306 · CWE-284",
    title: "FileManager WebShell & Connector Audit",
    desc: "Inspeksi pasif panel Web File Manager yang terekspos: TinyFileManager (CVE-2021-45010), Studio-42 elFinder & WP File Manager (CVE-2020-25213), Responsive FileManager, KCFinder.",
    paths: ["/tinyfilemanager.php", "/fm.php", "/elfinder/...", "/filemanager/dialog.php"]
  }
];

const VAULT_STEPS: VaultStep[] = [
  {
    step: "STEP 01",
    title: "Crawl & Recon Pasif",
    badge: "lib/discovery · Max 100 Req",
    summary: "Menelusuri tautan internal (maks. 50 URL, Depth 3), well-known files (robots.txt, sitemap.xml), dan header HTTP dengan metode GET-only."
  },
  {
    step: "STEP 02",
    title: "Deep Shell & OOB Audit",
    badge: "lib/parsers + lib/vuln",
    summary: "Membongkar bundle JS dan memeriksa 8 permukaan runtime (wp2shell, php2shell, node2shell, go2shell, py2shell, Node OOB) secara 100% pasif."
  },
  {
    step: "STEP 03",
    title: "Brankas AES-256-GCM",
    badge: "Redaksi Publik Otomatis",
    summary: "Kebocoran kritis (.env, .git/HEAD, backup.zip, wp-config.php.bak, AWS keys) langsung disensor dari publik dan dienkripsi ke Vault Admin."
  },
  {
    step: "STEP 04",
    title: "Klaim Pemilik Sah Domain",
    badge: "Verifikasi DNS TXT / HTTP",
    summary: "Pemilik sah domain memverifikasi DNS TXT atau file token HTTP untuk membuka bukti 1x lihat dan mengunduh laporan lengkap."
  }
];

const MODULES_22: SentinelModule[] = [
  { id: 1, title: "Overview & Scan", cat: "Core Audit & Scan", route: "/", badge: "VAULT", desc: "Pemindai terpadu 8 engine keamanan pasif dan ringkasan postur domain." },
  { id: 2, title: "SEO Master & Rank #1", cat: "Core Audit & Scan", route: "/scan/seo-master", badge: "GLOBAL", desc: "Audit 35+ sinyal Google SERP, 13 tag hreflang internasional & JSON-LD Schema.org." },
  { id: 3, title: "Sentinel Vault & Klaim", cat: "Core Audit & Scan", route: "/scan/sentinel", badge: "AES-256", desc: "Audit file sensitif (.env, .git/HEAD, backup.zip) & Brankas Bukti AES-256-GCM." },
  { id: 4, title: "QC Otomatis", cat: "Core Audit & Scan", route: "/qc", badge: "SEO+PERF", desc: "Audit kualitas SEO on-page, performa Core Web Vitals & tautan rusak." },
  { id: 5, title: "Scan History", cat: "Core Audit & Scan", route: "/history", badge: "LOG", desc: "Riwayat pemindaian domain dan perbandingan skor keamanan antar waktu." },
  { id: 6, title: "Request Inspector", cat: "Core Audit & Scan", route: "/requests", badge: "HTTP", desc: "Inspeksi transparan seluruh request GET/HEAD yang dikirim selama pemindaian." },
  { id: 7, title: "Header Armor", cat: "Vulnerability & Code", route: "/scan/headers", badge: "CSP/HSTS", desc: "Skor dan analisis HTTP security headers (CSP, HSTS, X-Frame-Options)." },
  { id: 8, title: "Secret Hunter", cat: "Vulnerability & Code", route: "/scan/secrets", badge: "AST/REGEX", desc: "Deteksi API key, token & kredensial bocor di dalam bundle JavaScript." },
  { id: 9, title: "Exposure Check", cat: "Vulnerability & Code", route: "/scan/exposure", badge: "PASSIVE", desc: "Verifikasi kebocoran file konfigurasi, shell surface & informasi sensitif." },
  { id: 10, title: "JS Supply Chain", cat: "Vulnerability & Code", route: "/scan/js", badge: "CVE DB", desc: "Deteksi library pihak ketiga usang, pencocokan CVE OSV/NVD & tracker skrip." },
  { id: 11, title: "SSL/TLS Checker", cat: "Vulnerability & Code", route: "/scan/ssl", badge: "TLS 1.3", desc: "Inspeksi rantai sertifikat, masa aktif, cipher suite & protokol TLS." },
  { id: 12, title: "Maintenance Log AI", cat: "Vulnerability & Code", route: "/maintenance-log", badge: "AI", desc: "Rekomendasi remediasi terstruktur dan log pemeliharaan keamanan berbasis AI." },
  { id: 13, title: "Attack Surface Map", cat: "Recon & Threat Intel", route: "/scan/map", badge: "GRAPH", desc: "Visualisasi graf interaktif relasi halaman, bundle JS, dan endpoint API." },
  { id: 14, title: "Subdomain Watch", cat: "Recon & Threat Intel", route: "/scan/subdomain", badge: "CT LOGS", desc: "Enumerasi CT logs crt.sh & deteksi risiko subdomain takeover." },
  { id: 15, title: "DNS Intelligence", cat: "Recon & Threat Intel", route: "/scan/dns", badge: "DoH/SPF", desc: "Audit record A/MX/TXT serta proteksi anti-spoofing SPF & DMARC." },
  { id: 16, title: "Tech Stack", cat: "Recon & Threat Intel", route: "/scan/stack", badge: "STACK", desc: "Identifikasi framework, CMS, CDN, WAF & server web secara pasif." },
  { id: 17, title: "Breach Peek", cat: "Recon & Threat Intel", route: "/scan/breach", badge: "OSINT", desc: "Cek eksposur email/domain pada insiden kebocoran data publik." },
  { id: 18, title: "OSINT Lookup", cat: "Recon & Threat Intel", route: "/scan/osint", badge: "RECON", desc: "Reconnaissance publik untuk username, email, domain & nama (rate-limit 10 req/min)." },
  { id: 19, title: "Shield Status", cat: "Recon & Threat Intel", route: "/scan/shield-status", badge: "STATUS", desc: "Pemantauan ketahanan WAF/Cloudflare Edge dan postur perlindungan aktif." },
  { id: 20, title: "Documentation", cat: "Resources & Admin", route: "/docs", badge: "DOCS", desc: "Dokumentasi arsitektur modular Sentinel-ID dan prinsip audit pasif." },
  { id: 21, title: "API Reference", cat: "Resources & Admin", route: "/api-docs", badge: "REST API", desc: "Referensi endpoint API pasif dan integrasi JSON." },
  { id: 22, title: "Admin Console", cat: "Resources & Admin", route: "/admin", badge: "ADMIN", desc: "Panel manajemen Sentinel Vault AES-256-GCM dan persetujuan klaim domain." }
];

const INITIAL_FINDINGS: AuditFinding[] = [
  {
    id: "F-01",
    sev: "MEDIUM",
    module: "lib/vuln (DOM Sink)",
    path: "/_next/static/chunks/main-app.js",
    detail: "Pola innerHTML pada chunk internal Next.js (status: POTENTIAL — false-positive wajar dari renderer React)."
  },
  {
    id: "F-02",
    sev: "MEDIUM",
    module: "lib/vuln (DOM Sink)",
    path: "/_next/static/chunks/framework.js",
    detail: "Pola location.search / innerHTML pada bundle framework (POTENTIAL — tinjau manual penggunaan dangerouslySetInnerHTML)."
  },
  {
    id: "F-03",
    sev: "MEDIUM",
    module: "Header Armor",
    path: "Content-Security-Policy",
    detail: "Direktif script-src memuat unsafe-inline untuk hidrasi skrip Next.js."
  },
  {
    id: "F-04",
    sev: "MEDIUM",
    module: "lib/parsers",
    path: "/_next/static/chunks/pages/_app.js",
    detail: "Ekstraksi 4 endpoint API internal (/api/osint, /api/scan, /api/qc, /api/vault) — pastikan rate-limit aktif."
  },
  {
    id: "F-05",
    sev: "MEDIUM",
    module: "JS Supply Chain",
    path: "OSV / NVD Fingerprint",
    detail: "0 CVE kritis pada dependensi utama; disarankan rotasi berkala integritas SRI."
  },
  {
    id: "F-06",
    sev: "MEDIUM",
    module: "Sentinel Vault",
    path: "/.env & /.git/HEAD",
    detail: "Tidak terekspos ke publik (404). Enkripsi otomatis AES-256-GCM siaga bila terdeteksi kebocoran."
  },
  {
    id: "F-07",
    sev: "LOW",
    module: "Header Armor",
    path: "Permissions-Policy",
    detail: "Disarankan membatasi akses geolocation, camera, dan microphone secara eksplisit."
  },
  {
    id: "F-08",
    sev: "LOW",
    module: "Header Armor",
    path: "Referrer-Policy",
    detail: "Gunakan strict-origin-when-cross-origin untuk menjaga privasi query parameter."
  },
  {
    id: "F-09",
    sev: "LOW",
    module: "SEO Master",
    path: "Hreflang International",
    detail: "Tag hreflang id-ID, en-US, dan x-default aktif; siap diperluas ke 13 locale penuh."
  },
  {
    id: "F-10",
    sev: "LOW",
    module: "SSL/TLS Checker",
    path: "HSTS Preload",
    detail: "TLS 1.3 aktif; tambahkan direktif preload pada Strict-Transport-Security."
  },
  {
    id: "F-11",
    sev: "INFO",
    module: "lib/discovery",
    path: "/robots.txt",
    detail: "File well-known robots.txt ditemukan (200 OK) dan dipatuhi oleh crawler pasif."
  },
  {
    id: "F-12",
    sev: "INFO",
    module: "lib/discovery",
    path: "/sitemap.xml",
    detail: "Sitemap XML ditemukan dan mengindeks seluruh modul utama."
  }
];

const FAQ_DATA = [
  {
    q_id: "Apakah Sentinel-ID 100% aman dan tidak merusak server produksi?",
    a_id: "Ya. Sentinel-ID beroperasi secara 100% pasif menggunakan metode HTTP GET/HEAD-only tanpa injeksi payload, tanpa brute-force, dilengkapi SSRF Guard serta pembatas RequestBudget maksimal 100 request.",
    q_en: "Is Sentinel-ID 100% safe for production servers (zero-exploit)?",
    a_en: "Yes. Sentinel-ID is a strictly passive, non-intrusive website security auditor using read-only HTTP GET/HEAD requests with zero exploit payloads, strict SSRF protection, and a 100-request budget."
  },
  {
    q_id: "Bagaimana cara kerja Brankas Bukti Terenkripsi AES-256-GCM (Sentinel Vault)?",
    a_id: "Ketika pemindai mendeteksi file sensitif seperti .env, .git/HEAD, wp-config.php.bak, atau kunci AWS, isi rahasia langsung di-redact dari publik dan dienkripsi menggunakan AES-256-GCM di Vault Admin. Hanya pemilik sah domain yang dapat mengklaim bukti tersebut melalui verifikasi DNS TXT atau file HTTP.",
    q_en: "How does the AES-256-GCM Encrypted Evidence Vault protect leaked secrets?",
    a_en: "When Sentinel-ID detects exposed .env files, .git repositories, database backups, or API keys, raw values are never shown publicly. Evidence is encrypted with AES-256-GCM and can only be unlocked once by the verified domain owner via DNS TXT or HTTP token verification."
  },
  {
    q_id: "Apa saja celah RCE & Shell Surface yang diperiksa secara pasif?",
    a_id: "Mesin Deep Shell & OOB memeriksa permukaan runtime utama secara pasif: wp2shell, php2shell (Laravel Ignition CVE-2021-3129, PHPUnit), node2shell (V8 Inspector, child_process/vm sinks), go2shell (Go pprof & expvar), py2shell (Werkzeug console, Jupyter API), serta Node Out-of-Bounds memory & heapdump.",
    q_en: "Which RCE and runtime shell surfaces does Sentinel-ID detect?",
    a_en: "Sentinel-ID passively audits runtime surfaces: wp2shell, php2shell (Laravel Ignition, PHPUnit, phpinfo), node2shell (V8 inspector, SSR AST sinks), go2shell (Go pprof/expvar), py2shell (Werkzeug debugger, Jupyter kernels), and Node.js Out-of-Bounds heap/memory exposures."
  },
  {
    q_id: "Bagaimana fitur SEO Master membantu website naik ke Rank #1 Google Internasional?",
    a_id: "Modul SEO Master memeriksa lebih dari 35 sinyal teknis Google: tag Hreflang 13 locale (id-ID, en-US, en-GB, x-default, dll.), struktur JSON-LD Schema.org, Open Graph, Core Web Vitals, serta Security-SEO Trust Signals (HTTPS/HSTS/CSP).",
    q_en: "How does the SEO Master module help websites rank #1 on Google internationally?",
    a_en: "SEO Master audits 35+ Google ranking factors including 13 international hreflang tags, Schema.org JSON-LD graphs, Core Web Vitals, keyword density, Open Graph, and HTTPS/HSTS security trust signals."
  }
];

export default function App() {
  const [isDark, setIsDark] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<ViewTab>("overview");
  const [targetDomain, setTargetDomain] = useState<string>("kasyaf-cv.my.id");
  const [scanMode, setScanMode] = useState<ScanMode>("full");
  const [cfResilient, setCfResilient] = useState<boolean>(true);
  const [consentChecked, setConsentChecked] = useState<boolean>(true);
  const [isScanning, setIsScanning] = useState<boolean>(false);
  const [lastScannedDomain, setLastScannedDomain] = useState<string>("kasyaf-cv.my.id");

  const [activeShellId, setActiveShellId] = useState<string>("wp2shell");
  const [activeVaultStep, setActiveVaultStep] = useState<number>(0);
  const [moduleCategory, setModuleCategory] = useState<string>("Semua");
  const [moduleSearch, setModuleSearch] = useState<string>("");
  const [selectedModule, setSelectedModule] = useState<SentinelModule>(MODULES_22[0]);

  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("ALL");
  const [faqLang, setFaqLang] = useState<FaqLang>("id");
  const [openFaqIdx, setOpenFaqIdx] = useState<number>(0);
  const [copiedNotice, setCopiedNotice] = useState<string>("");

  // Sync Dark/Light class on <html> so both Next.js ThemeProvider and standalone preview work seamlessly
  useEffect(() => {
    const root = document.documentElement;
    if (isDark) {
      root.classList.add("dark");
    } else {
      root.classList.remove("dark");
    }
  }, [isDark]);

  const activeShell = useMemo(
    () => SHELL_SURFACES.find((s) => s.id === activeShellId) || SHELL_SURFACES[0],
    [activeShellId]
  );

  const filteredModules = useMemo(() => {
    return MODULES_22.filter((m) => {
      const matchCat = moduleCategory === "Semua" || m.cat === moduleCategory;
      const q = moduleSearch.trim().toLowerCase();
      const matchQuery =
        !q ||
        m.title.toLowerCase().includes(q) ||
        m.route.toLowerCase().includes(q) ||
        m.badge.toLowerCase().includes(q) ||
        m.desc.toLowerCase().includes(q);
      return matchCat && matchQuery;
    });
  }, [moduleCategory, moduleSearch]);

  const filteredFindings = useMemo(() => {
    if (severityFilter === "ALL") return INITIAL_FINDINGS;
    return INITIAL_FINDINGS.filter((f) => f.sev === severityFilter);
  }, [severityFilter]);

  function handleRunScan(e: React.FormEvent) {
    e.preventDefault();
    if (!consentChecked) return;
    const cleaned =
      targetDomain.trim().replace(/^https?:\/\//i, "").split("/")[0] || "kasyaf-cv.my.id";
    setTargetDomain(cleaned);
    setIsScanning(true);
    setTimeout(() => {
      setIsScanning(false);
      setLastScannedDomain(cleaned);
      setActiveTab("scanner");
    }, 450);
  }

  function handleCopyReport() {
    const reportText = [
      `# Sentinel-ID Passive Security Report (${lastScannedDomain})`,
      `- Mode: ${scanMode === "full" ? "Full Scan + Deep Shell (8 Engines)" : "Sentinel Vault AES-256-GCM"}`,
      `- Cloudflare / WAF Resilient: ${cfResilient ? "Active (Edge + DoH)" : "Standard"}`,
      `- Metrics: 1 URL Crawled / 50 | 11 JS Unpacked | 29 / 100 Requests | 14 Nodes / 13 Edges`,
      `- Severity: 0 CRITICAL, 0 HIGH, 6 MEDIUM (POTENTIAL), 4 LOW, 2 INFO`,
      ``,
      `## Findings`,
      ...INITIAL_FINDINGS.map((f) => `- [${f.sev}] ${f.module} (${f.path}): ${f.detail}`)
    ].join("\n");

    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(reportText);
      }
    } catch {
      // Fallback handled silently
    }
    setCopiedNotice("Laporan Markdown berhasil disalin!");
    setTimeout(() => setCopiedNotice(""), 2500);
  }

  // Dynamic Glassmorphism Theme Tokens
  const themeBg = isDark
    ? "bg-[#07070C] text-slate-50"
    : "bg-[#F5F5F7] text-slate-900";
  const glassCard = isDark
    ? "bg-white/[0.04] backdrop-blur-2xl border border-white/[0.11] shadow-[0_24px_60px_-15px_rgba(0,0,0,0.65)]"
    : "bg-white/75 backdrop-blur-2xl border border-slate-900/[0.08] shadow-[0_20px_50px_-12px_rgba(15,23,42,0.07)]";
  const glassPill = isDark
    ? "bg-white/[0.06] backdrop-blur-xl border border-white/[0.1]"
    : "bg-white/85 backdrop-blur-xl border border-slate-900/[0.08]";
  const mutedText = isDark ? "text-slate-400" : "text-slate-600";

  return (
    <div className={`min-h-screen relative transition-colors duration-300 ${themeBg}`}>
      {/* Ambient Liquid Prism Glow (Apple / Stitch Aesthetic) */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden z-0">
        <div
          className={`absolute -top-28 -left-24 w-[420px] h-[420px] rounded-full blur-[110px] ${
            isDark ? "bg-pink-500/15" : "bg-pink-400/15"
          }`}
        />
        <div
          className={`absolute top-1/4 -right-24 w-[460px] h-[460px] rounded-full blur-[120px] ${
            isDark ? "bg-purple-600/15" : "bg-purple-400/15"
          }`}
        />
        <div
          className={`absolute bottom-0 left-1/3 w-[380px] h-[380px] rounded-full blur-[110px] ${
            isDark ? "bg-emerald-500/10" : "bg-emerald-400/15"
          }`}
        />
      </div>

      {/* Floating Glass Top Dock */}
      <header className="sticky top-3 z-40 px-4 sm:px-6 pt-2">
        <div
          className={`max-w-7xl mx-auto rounded-2xl px-4 sm:px-5 py-2.5 flex flex-wrap items-center justify-between gap-3 ${glassCard}`}
        >
          {/* Brand Logo */}
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-pink-500 via-purple-600 to-indigo-600 flex items-center justify-center text-white shadow-lg shadow-pink-500/20">
              <Shield className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold tracking-tight text-sm sm:text-base">
                  SENTINEL-ID
                </span>
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
                <span
                  className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${glassPill} text-emerald-500`}
                >
                  v3.6
                </span>
              </div>
              <p className={`text-[11px] hidden sm:block ${mutedText}`}>
                Passive Security Auditor &amp; Global SEO Master
              </p>
            </div>
          </div>

          {/* Apple-Style Segmented View Switcher (De-clutters the page) */}
          <nav
            className={`flex items-center gap-1 p-1 rounded-xl ${glassPill}`}
            aria-label="Navigasi Utama"
          >
            {(
              [
                { id: "overview", label: "Landing Page" },
                { id: "scanner", label: "Live Scanner & Hasil" },
                { id: "modules", label: "22 Modul Audit" }
              ] as { id: ViewTab; label: string }[]
            ).map((tab) => (
              <button
                key={tab.id}
                type="button"
                onClick={() => setActiveTab(tab.id)}
                className={`px-3 sm:px-4 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                  activeTab === tab.id
                    ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white shadow-sm"
                    : `${mutedText} hover:opacity-90`
                }`}
              >
                {tab.label}
              </button>
            ))}
          </nav>

          {/* GDG Bandung Verified Badge & Dark/Light Mode Switch */}
          <div className="flex items-center gap-2">
            <div
              className={`hidden xl:flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs font-medium text-emerald-500 ${glassPill}`}
            >
              <CheckCircle2 className="w-3.5 h-3.5" />
              <span>GDG Bandung Verified</span>
            </div>

            <button
              type="button"
              onClick={() => setIsDark(!isDark)}
              className={`px-3 py-1.5 rounded-xl text-xs font-semibold flex items-center gap-1.5 transition hover:scale-[1.02] ${glassPill}`}
              aria-label="Ganti Mode Gelap atau Terang"
            >
              {isDark ? (
                <>
                  <Sun className="w-3.5 h-3.5 text-amber-400" />
                  <span className="hidden sm:inline">Light Glass</span>
                </>
              ) : (
                <>
                  <Moon className="w-3.5 h-3.5 text-indigo-600" />
                  <span className="hidden sm:inline">Dark Glass</span>
                </>
              )}
            </button>
          </div>
        </div>
      </header>

      {/* Main Content Container */}
      <main className="relative z-10 max-w-7xl mx-auto px-4 sm:px-6 pt-8 pb-20 space-y-16">
        {/* ================================================================= */}
        {/* TAB 1: APPLE-STYLE GLASSMORPHIC LANDING PAGE                      */}
        {/* ================================================================= */}
        {activeTab === "overview" && (
          <>
            {/* Hero Section */}
            <section className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
              <div className="lg:col-span-7 space-y-6">
                <div
                  className={`inline-flex flex-wrap items-center gap-2 px-3.5 py-1.5 rounded-full text-xs ${glassPill}`}
                >
                  <span className="px-2 py-0.5 rounded-full bg-emerald-500/15 text-emerald-500 font-mono font-semibold">
                    100% GET-ONLY · ZERO-EXPLOIT
                  </span>
                  <span className={mutedText}>
                    Terverifikasi Google Developer Bandung · Lead Author: Kasyaf
                  </span>
                </div>

                <h1 className="text-4xl sm:text-5xl lg:text-6xl font-extrabold tracking-tight leading-[1.08]">
                  Keamanan Web Pasif.{" "}
                  <span className="bg-gradient-to-r from-pink-500 via-purple-500 to-cyan-500 bg-clip-text text-transparent">
                    Jernih, Ringan, Tanpa Risiko.
                  </span>
                </h1>

                <p className={`text-base sm:text-lg leading-relaxed max-w-2xl ${mutedText}`}>
                  Analisis postur keamanan domain dan kesiapan SERP Google Global
                  tanpa menembakkan payload yang merusak server. Menggabungkan{" "}
                  <strong className="font-semibold text-pink-500">
                    Multi-Page Passive Crawler
                  </strong>
                  ,{" "}
                  <strong className="font-semibold text-purple-500">
                    8 Engine Deep Shell &amp; OOB
                  </strong>
                  , serta{" "}
                  <strong className="font-semibold text-emerald-500">
                    Brankas Bukti AES-256-GCM
                  </strong>
                  .
                </p>

                {/* Sleek Glass Scanner Bar */}
                <form
                  onSubmit={handleRunScan}
                  className={`p-3 sm:p-4 rounded-3xl space-y-3 max-w-2xl ${glassCard}`}
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <div className={`inline-flex p-1 rounded-xl ${glassPill}`}>
                      <button
                        type="button"
                        onClick={() => setScanMode("full")}
                        className={`px-3 py-1 rounded-lg text-xs font-semibold transition ${
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
                        className={`px-3 py-1 rounded-lg text-xs font-semibold transition ${
                          scanMode === "vault"
                            ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white"
                            : mutedText
                        }`}
                      >
                        Brankas AES-256-GCM &amp; Klaim
                      </button>
                    </div>
                    <button
                      type="button"
                      onClick={() => setCfResilient(!cfResilient)}
                      className={`text-[11px] font-mono px-2.5 py-1 rounded-lg transition ${
                        cfResilient
                          ? "bg-emerald-500/15 text-emerald-500"
                          : `${glassPill} ${mutedText}`
                      }`}
                    >
                      {cfResilient ? "✓ Cloudflare / WAF Resilient" : "Standard Mode"}
                    </button>
                  </div>

                  <div className="flex flex-col sm:flex-row gap-2">
                    <div
                      className={`flex-1 flex items-center gap-2.5 px-3.5 py-2.5 rounded-2xl ${glassPill}`}
                    >
                      <Search className="w-4 h-4 text-pink-500 shrink-0" />
                      <input
                        type="text"
                        value={targetDomain}
                        onChange={(e) => setTargetDomain(e.target.value)}
                        placeholder="Masukkan domain (contoh: sentinel-id.net)"
                        className="w-full bg-transparent text-sm font-mono focus:outline-none"
                        aria-label="Domain atau URL Target"
                      />
                    </div>
                    <button
                      type="submit"
                      disabled={!consentChecked || isScanning}
                      className="px-5 py-3 rounded-2xl font-semibold text-sm text-white bg-gradient-to-r from-pink-500 via-purple-600 to-indigo-600 hover:opacity-95 disabled:opacity-50 transition shadow-lg shadow-pink-500/20 flex items-center justify-center gap-2 shrink-0"
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
                    <span>
                      Saya adalah pemilik sah atau memiliki izin tertulis untuk mengaudit domain ini secara pasif.
                    </span>
                  </label>
                </form>

                {/* 4 Clean Glass Stat Pills */}
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                  {[
                    { label: "Deep Crawl", val: "Max 50 URL", sub: "Depth 3 · 100 Req" },
                    { label: "Shell & OOB", val: "8 Engine", sub: "wp/php/node/go/py" },
                    { label: "Sentinel Vault", val: "AES-256", sub: "Redaksi Publik" },
                    { label: "SEO Master #1", val: "13 Locale", sub: "Hreflang · JSON-LD" }
                  ].map((item) => (
                    <div key={item.label} className={`rounded-2xl p-3.5 ${glassCard}`}>
                      <p className={`text-[11px] font-mono uppercase ${mutedText}`}>
                        {item.label}
                      </p>
                      <p className="text-lg font-bold mt-0.5">{item.val}</p>
                      <p className={`text-xs ${mutedText}`}>{item.sub}</p>
                    </div>
                  ))}
                </div>
              </div>

              {/* Right Column: Apple Frosted Glass Visual Showcase Card */}
              <div className="lg:col-span-5">
                <div className={`rounded-3xl p-6 space-y-5 relative overflow-hidden ${glassCard}`}>
                  {/* Frosted 3D Prism Shield Visual */}
                  <div
                    className={`rounded-2xl p-6 flex flex-col items-center justify-center text-center relative overflow-hidden ${
                      isDark
                        ? "bg-gradient-to-br from-pink-500/15 via-purple-900/25 to-cyan-500/15 border border-white/10"
                        : "bg-gradient-to-br from-pink-500/10 via-purple-500/10 to-cyan-500/10 border border-slate-900/10"
                    }`}
                  >
                    <div className="w-24 h-24 rounded-3xl bg-gradient-to-br from-pink-500 via-purple-600 to-indigo-600 flex items-center justify-center shadow-2xl shadow-pink-500/30 mb-4">
                      <Shield className="w-12 h-12 text-white" />
                    </div>
                    <span className="text-[11px] font-mono uppercase tracking-widest text-emerald-500 font-semibold">
                      PASSIVE ARCHITECTURE v2 + v3.6
                    </span>
                    <h3 className="text-lg font-bold mt-1">
                      Unified Deep Security &amp; Vault Engine
                    </h3>
                    <p className={`text-xs mt-1 max-w-xs ${mutedText}`}>
                      discovery → parsers → fingerprint → vuln → fuzzer
                    </p>
                  </div>

                  {/* Compact 8-Engine Pills (Clean 2-Column Grid) */}
                  <div className="space-y-2">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-semibold">8 Engine Otomatis Sekaligus</span>
                      <span className="font-mono text-emerald-500">GET-Only</span>
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
                        <div
                          key={eng}
                          className={`px-3 py-2 rounded-xl font-mono text-[11px] truncate ${glassPill}`}
                        >
                          {eng}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              </div>
            </section>

            {/* Interactive 8 Runtime Shell Selector (Replaces Stacked 8-Card Text Wall) */}
            <section className={`rounded-3xl p-6 sm:p-8 space-y-6 ${glassCard}`}>
              <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
                <div>
                  <span className="text-xs font-mono uppercase tracking-widest text-pink-500 font-semibold">
                    Deep Passive Runtime Engine
                  </span>
                  <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mt-1">
                    Inspeksi 8 Permukaan Runtime &amp; Shell
                  </h2>
                  <p className={`text-sm mt-1 ${mutedText}`}>
                    Klik tab runtime di samping untuk melihat cakupan CWE dan path sensitif yang diperiksa tanpa menumpuk teks.
                  </p>
                </div>

                {/* Segmented Pill Selector */}
                <div className={`flex flex-wrap gap-1.5 p-1.5 rounded-2xl ${glassPill}`}>
                  {SHELL_SURFACES.map((s) => (
                    <button
                      key={s.id}
                      type="button"
                      onClick={() => setActiveShellId(s.id)}
                      className={`px-3 py-1.5 rounded-xl text-xs font-mono font-semibold transition ${
                        activeShellId === s.id
                          ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white shadow-sm"
                          : `${mutedText} hover:opacity-80`
                      }`}
                    >
                      {s.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Selected Shell Card */}
              <div className={`rounded-2xl p-5 sm:p-6 grid grid-cols-1 lg:grid-cols-12 gap-6 items-center ${glassPill}`}>
                <div className="lg:col-span-7 space-y-2">
                  <div className="inline-flex items-center gap-2 text-xs font-mono text-pink-500 font-semibold">
                    <Terminal className="w-4 h-4" />
                    <span>{activeShell.label}</span>
                    <span>·</span>
                    <span>{activeShell.cwe}</span>
                  </div>
                  <h3 className="text-xl font-bold">{activeShell.title}</h3>
                  <p className={`text-sm leading-relaxed ${mutedText}`}>
                    {activeShell.desc}
                  </p>
                </div>
                <div className="lg:col-span-5 grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                  {activeShell.paths.map((pathStr) => (
                    <div
                      key={pathStr}
                      className={`px-3.5 py-2.5 rounded-xl font-mono text-xs text-cyan-500 truncate ${glassCard}`}
                    >
                      {pathStr}
                    </div>
                  ))}
                </div>
              </div>
            </section>

            {/* Interactive 4-Step AES-256-GCM Vault Workflow */}
            <section className="space-y-5">
              <div className="flex flex-col sm:flex-row sm:items-end justify-between gap-2">
                <div>
                  <span className="text-xs font-mono uppercase tracking-widest text-emerald-500 font-semibold">
                    Proteksi Bukti Kritis
                  </span>
                  <h2 className="text-2xl sm:text-3xl font-bold tracking-tight mt-1">
                    Alur Brankas Bukti AES-256-GCM &amp; Klaim Domain
                  </h2>
                </div>
                <span className={`text-xs font-mono ${mutedText}`}>
                  Pilih langkah untuk melihat detail
                </span>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
                {VAULT_STEPS.map((st, idx) => {
                  const isAct = activeVaultStep === idx;
                  return (
                    <button
                      key={st.step}
                      type="button"
                      onClick={() => setActiveVaultStep(idx)}
                      className={`rounded-2xl p-5 text-left transition-all ${glassCard} ${
                        isAct ? "ring-2 ring-pink-500/70" : "opacity-85 hover:opacity-100"
                      }`}
                    >
                      <div className="flex items-center justify-between">
                        <span className="text-xs font-mono font-bold text-pink-500">
                          {st.step}
                        </span>
                        <span
                          className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${glassPill} text-emerald-500`}
                        >
                          {st.badge}
                        </span>
                      </div>
                      <h3 className="text-base font-bold mt-2">{st.title}</h3>
                      <p className={`text-xs mt-1.5 leading-relaxed ${mutedText}`}>
                        {st.summary}
                      </p>
                    </button>
                  );
                })}
              </div>
            </section>

            {/* Clean Bilingual FAQ Accordion with 1-Click ID / EN Switch */}
            <section className={`rounded-3xl p-6 sm:p-8 space-y-6 ${glassCard}`}>
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <span className="text-xs font-mono uppercase tracking-widest text-cyan-500 font-semibold">
                    Schema.org FAQPage · 13 Hreflang Ready
                  </span>
                  <h2 className="text-2xl font-bold tracking-tight mt-1">
                    Pertanyaan Umum (FAQ)
                  </h2>
                </div>

                <div className={`inline-flex p-1 rounded-xl self-start ${glassPill}`}>
                  <button
                    type="button"
                    onClick={() => setFaqLang("id")}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                      faqLang === "id"
                        ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white"
                        : mutedText
                    }`}
                  >
                    Bahasa Indonesia
                  </button>
                  <button
                    type="button"
                    onClick={() => setFaqLang("en")}
                    className={`px-3 py-1.5 rounded-lg text-xs font-semibold transition ${
                      faqLang === "en"
                        ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white"
                        : mutedText
                    }`}
                  >
                    English (Global)
                  </button>
                </div>
              </div>

              <div className="space-y-3">
                {FAQ_DATA.map((item, idx) => {
                  const isOpen = openFaqIdx === idx;
                  const q = faqLang === "id" ? item.q_id : item.q_en;
                  const a = faqLang === "id" ? item.a_id : item.a_en;
                  return (
                    <div key={item.q_id} className={`rounded-2xl p-4 ${glassPill}`}>
                      <button
                        type="button"
                        onClick={() => setOpenFaqIdx(isOpen ? -1 : idx)}
                        className="w-full flex items-center justify-between gap-4 text-left"
                      >
                        <span className="text-sm font-bold">{q}</span>
                        <ChevronDown
                          className={`w-4 h-4 shrink-0 transition-transform ${
                            isOpen ? "rotate-180 text-pink-500" : mutedText
                          }`}
                        />
                      </button>
                      {isOpen && (
                        <p className={`mt-3 pt-3 border-t border-white/10 text-xs sm:text-sm leading-relaxed ${mutedText}`}>
                          {a}
                        </p>
                      )}
                    </div>
                  );
                })}
              </div>
            </section>
          </>
        )}

        {/* ================================================================= */}
        {/* TAB 2: LIVE SCANNER & BENCHMARK RESULTS (`kasyaf-cv.my.id`)        */}
        {/* ================================================================= */}
        {activeTab === "scanner" && (
          <section className="space-y-6">
            <div
              className={`rounded-3xl p-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${glassCard}`}
            >
              <div>
                <div className="flex items-center gap-2 text-xs font-mono text-emerald-500">
                  <Activity className="w-4 h-4" />
                  <span>HASIL AUDIT PASIF TERVERIFIKASI</span>
                </div>
                <h2 className="text-2xl font-bold mt-1">
                  Target Domain: {lastScannedDomain}
                </h2>
                <p className={`text-xs sm:text-sm mt-0.5 ${mutedText}`}>
                  1 URL Crawled · 11 JS Unpacked · 29 / 100 Requests · Graf 14 Node &amp; 13 Edge
                </p>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                {copiedNotice && (
                  <span className="text-xs font-mono text-emerald-500 px-3 py-1.5 rounded-xl bg-emerald-500/10">
                    {copiedNotice}
                  </span>
                )}
                <button
                  type="button"
                  onClick={handleCopyReport}
                  className="px-4 py-2.5 rounded-xl text-xs font-semibold text-white bg-gradient-to-r from-pink-500 to-purple-600 flex items-center gap-1.5 shadow-md"
                >
                  <Copy className="w-3.5 h-3.5" />
                  <span>Salin Markdown Report</span>
                </button>
              </div>
            </div>

            {/* 6 Summary Metric Cards */}
            <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
              {[
                { label: "URL CRAWLED", val: "1 / 50", color: "" },
                { label: "JS SCANNED", val: "11 Bundle", color: "" },
                { label: "REQ BUDGET", val: "29 / 100", color: "" },
                { label: "CRIT / HIGH", val: "0 / 0", color: "text-emerald-500" },
                { label: "MEDIUM (POTENTIAL)", val: "6", color: "text-amber-500" },
                { label: "LOW / INFO", val: "4 / 2", color: "text-cyan-500" }
              ].map((m) => (
                <div key={m.label} className={`rounded-2xl p-4 ${glassCard}`}>
                  <span className={`text-[10px] font-mono ${mutedText}`}>{m.label}</span>
                  <p className={`text-xl font-bold mt-1 ${m.color}`}>{m.val}</p>
                </div>
              ))}
            </div>

            {/* Findings List with Severity Filter */}
            <div className={`rounded-3xl p-6 space-y-4 ${glassCard}`}>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <h3 className="text-lg font-bold">
                  Daftar Temuan (`addFinding` Store)
                </h3>
                <div className={`flex flex-wrap gap-1 p-1 rounded-xl ${glassPill}`}>
                  {(["ALL", "MEDIUM", "LOW", "INFO"] as SeverityFilter[]).map((sev) => (
                    <button
                      key={sev}
                      type="button"
                      onClick={() => setSeverityFilter(sev)}
                      className={`px-3 py-1 rounded-lg text-xs font-mono font-semibold transition ${
                        severityFilter === sev
                          ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white"
                          : mutedText
                      }`}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {filteredFindings.map((f) => (
                  <div key={f.id} className={`rounded-2xl p-4 space-y-1.5 ${glassPill}`}>
                    <div className="flex items-center justify-between gap-2">
                      <span
                        className={`px-2 py-0.5 rounded-md text-[10px] font-mono font-bold ${
                          f.sev === "MEDIUM"
                            ? "bg-amber-500/15 text-amber-500"
                            : f.sev === "LOW"
                            ? "bg-cyan-500/15 text-cyan-500"
                            : "bg-emerald-500/15 text-emerald-500"
                        }`}
                      >
                        {f.sev}
                      </span>
                      <span className="text-xs font-mono text-cyan-500 truncate">
                        {f.path}
                      </span>
                    </div>
                    <div className="text-sm font-bold">{f.module}</div>
                    <p className={`text-xs leading-relaxed ${mutedText}`}>{f.detail}</p>
                  </div>
                ))}
              </div>
            </div>
          </section>
        )}

        {/* ================================================================= */}
        {/* TAB 3: 22-MODULE BENTO EXPLORER                                    */}
        {/* ================================================================= */}
        {activeTab === "modules" && (
          <section className="space-y-6">
            <div
              className={`rounded-3xl p-6 flex flex-col lg:flex-row lg:items-center justify-between gap-4 ${glassCard}`}
            >
              <div>
                <span className="text-xs font-mono uppercase tracking-widest text-pink-500 font-semibold">
                  Navigasi Terpadu
                </span>
                <h2 className="text-2xl font-bold mt-1">
                  22 Modul Keamanan Siber &amp; SEO Master Global
                </h2>
              </div>

              <div className="flex flex-wrap items-center gap-2">
                <div className={`flex items-center gap-2 px-3.5 py-2 rounded-xl ${glassPill}`}>
                  <Search className="w-4 h-4 text-pink-500" />
                  <input
                    type="text"
                    value={moduleSearch}
                    onChange={(e) => setModuleSearch(e.target.value)}
                    placeholder="Cari modul atau rute..."
                    className="bg-transparent text-xs focus:outline-none"
                    aria-label="Cari Modul"
                  />
                </div>

                <div className={`flex flex-wrap gap-1 p-1 rounded-xl ${glassPill}`}>
                  {[
                    "Semua",
                    "Core Audit & Scan",
                    "Vulnerability & Code",
                    "Recon & Threat Intel",
                    "Resources & Admin"
                  ].map((cat) => (
                    <button
                      key={cat}
                      type="button"
                      onClick={() => setModuleCategory(cat)}
                      className={`px-2.5 py-1 rounded-lg text-xs font-medium transition ${
                        moduleCategory === cat
                          ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white"
                          : mutedText
                      }`}
                    >
                      {cat}
                    </button>
                  ))}
                </div>
              </div>
            </div>

            {/* Selected Module Spotlight Banner */}
            <div
              className={`rounded-2xl p-5 flex flex-col sm:flex-row sm:items-center justify-between gap-4 ${glassPill}`}
            >
              <div>
                <div className="flex items-center gap-2 text-xs font-mono">
                  <span className="text-pink-500 font-semibold">{selectedModule.cat}</span>
                  <span>·</span>
                  <span className="text-cyan-500">{selectedModule.route}</span>
                </div>
                <h3 className="text-lg font-bold mt-0.5">{selectedModule.title}</h3>
                <p className={`text-xs sm:text-sm ${mutedText}`}>{selectedModule.desc}</p>
              </div>
              <a
                href={selectedModule.route}
                onClick={(e) => {
                  e.preventDefault();
                  setActiveTab("scanner");
                }}
                className="px-4 py-2.5 rounded-xl text-xs font-semibold text-white bg-gradient-to-r from-pink-500 to-purple-600 shrink-0 inline-flex items-center gap-1.5"
              >
                <span>Buka {selectedModule.route}</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </a>
            </div>

            {/* 22 Modules Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {filteredModules.map((mod) => (
                <div
                  key={mod.id}
                  onClick={() => setSelectedModule(mod)}
                  className={`rounded-2xl p-5 cursor-pointer flex flex-col justify-between gap-4 transition hover:-translate-y-0.5 ${glassCard} ${
                    selectedModule.id === mod.id ? "ring-2 ring-pink-500/70" : ""
                  }`}
                >
                  <div className="space-y-2">
                    <div className="flex items-center justify-between gap-2">
                      <span className={`text-[10px] font-mono uppercase ${mutedText}`}>
                        {mod.cat}
                      </span>
                      <span
                        className={`px-2 py-0.5 rounded-full text-[10px] font-mono font-semibold text-pink-500 ${glassPill}`}
                      >
                        {mod.badge}
                      </span>
                    </div>
                    <h3 className="text-base font-bold">{mod.title}</h3>
                    <p className={`text-xs leading-relaxed ${mutedText}`}>{mod.desc}</p>
                  </div>

                  <div className="flex items-center justify-between pt-3 border-t border-white/10 text-xs">
                    <span className="font-mono text-cyan-500">{mod.route}</span>
                    <span className="font-semibold text-pink-500">Pilih Modul →</span>
                  </div>
                </div>
              ))}
            </div>
          </section>
        )}
      </main>
    </div>
  );
}
