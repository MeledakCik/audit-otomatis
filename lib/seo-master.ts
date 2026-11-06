// lib/seo-master.ts
// Centralized SEO Master & International SERP Rank #1 Intelligence Hub
// Provides global keyword clusters (English + Indonesian + International),
// multi-region hreflang alternates, per-page metadata builder, and
// comprehensive Schema.org JSON-LD Graph generators for Google Rich Results.

import type { Metadata } from "next";

export const SITE_URL = "https://www.sentinel-id.net";
export const SITE_NAME = "Sentinel-ID";
export const SITE_BRAND = "Sentinel-ID — Global Passive Website Security Auditor & SEO Master";
export const GOOGLE_VERIFICATION_CODE = "SgwdHR7nkAHjCTR-2VgSjZ6YRh5w8jIc0NBQtDjnyxg";

/**
 * Supported International Hreflang Locales for Global Google Indexing
 * Enables Google Search across US, UK, SG, AU, ID, MY, JP, DE, IN, NL, and Global (x-default).
 */
export const INTERNATIONAL_HREFLANG_LOCALES = [
  "x-default",
  "id-ID",
  "id",
  "en-US",
  "en-GB",
  "en-SG",
  "en-AU",
  "en-CA",
  "en-IN",
  "en",
  "ms-MY",
  "ja-JP",
  "de-DE",
] as const;

export function buildLanguageAlternates(path = ""): Record<string, string> {
  const cleanPath = path.startsWith("/") ? path : path ? `/${path}` : "";
  const fullUrl = `${SITE_URL}${cleanPath}`;
  return {
    "x-default": fullUrl,
    "id-ID": fullUrl,
    id: fullUrl,
    "en-US": `${fullUrl}?hl=en`,
    "en-GB": `${fullUrl}?hl=en-gb`,
    "en-SG": `${fullUrl}?hl=en-sg`,
    "en-AU": `${fullUrl}?hl=en-au`,
    "en-CA": `${fullUrl}?hl=en-ca`,
    "en-IN": `${fullUrl}?hl=en-in`,
    en: `${fullUrl}?hl=en`,
    "ms-MY": `${fullUrl}?hl=ms`,
    "ja-JP": `${fullUrl}?hl=ja`,
    "de-DE": `${fullUrl}?hl=de`,
  };
}

/**
 * Master Keyword Clusters — Tier-1 Global English + Indonesian High-Intent Keywords
 * Engineered to target #1 rankings for passive web security auditing, vulnerability scanning,
 * sensitive file exposure (.env/.git), shell surface detection, and technical SEO auditing.
 */
export const MASTER_GLOBAL_KEYWORDS: string[] = [
  // Primary Global English Security Keywords
  "passive website security scanner",
  "free website vulnerability scanner online",
  "passive web security auditor",
  "non-intrusive vulnerability scanner",
  "check website security online free",
  "HTTP security headers checker",
  "CSP HSTS security header analyzer",
  "JavaScript secret scanner",
  "detect leaked API keys in JS",
  "exposed .env .git scanner",
  "sensitive file exposure checker",
  "AES-256-GCM encrypted vulnerability vault",
  "subdomain takeover scanner crt.sh",
  "passive DNS intelligence SPF DMARC DKIM checker",
  "SSL TLS certificate security grader",
  "JavaScript supply chain vulnerability scanner",
  "RCE shell surface detector wp2shell php2shell node2shell go2shell py2shell",
  "Node.js out-of-bounds memory leak scanner",
  "OSINT domain breach checker free",
  "attack surface mapping tool online",
  "website tech stack fingerprinter",
  // Primary Global SEO Master Keywords
  "technical SEO audit tool free",
  "international SEO hreflang checker",
  "JSON-LD schema markup validator",
  "Google rank 1 SEO analyzer",
  "Core Web Vitals PageSpeed SEO scanner",
  "open graph twitter card validator",
  // Primary Indonesian High-Intent Keywords
  "audit keamanan website",
  "cek celah keamanan web gratis",
  "scanner keamanan website pasif",
  "alat audit keamanan siber Indonesia",
  "cek kebocoran file .env dan .git",
  "deteksi backdoor web shell wp2shell php2shell",
  "cek header keamanan HTTP",
  "audit SEO otomatis gratis",
  "optimasi SEO internasional rank 1 Google",
  "Sentinel-ID Security Auditor",
  "Google Developer Bandung verified security tool",
];

export interface SeoRouteConfig {
  path: string;
  title: string;
  titleEn: string;
  description: string;
  descriptionEn: string;
  keywords: string[];
  category: "Security Scanner" | "Recon & OSINT" | "SEO & Quality Control" | "Documentation";
  priority: number;
  changeFrequency: "always" | "hourly" | "daily" | "weekly" | "monthly";
}

export const SEO_ROUTES_REGISTRY: Record<string, SeoRouteConfig> = {
  "/": {
    path: "",
    title: "Sentinel-ID — #1 Passive Website Security Auditor, Vulnerability Scanner & SEO Master",
    titleEn: "Sentinel-ID — Free Passive Website Security Scanner, RCE Surface Auditor & Global SEO Master",
    description:
      "Platform audit keamanan web pasif #1 (100% GET-only, zero-exploit) & SEO Master Internasional. Deteksi .env/.git, wp2shell, php2shell, node2shell, go2shell, py2shell, Brankas AES-256-GCM & optimasi SERP Google Global.",
    descriptionEn:
      "#1 Free Passive Website Security Auditor & International SEO Master. Non-intrusive GET-only vulnerability scanner for .env/.git leaks, RCE shell surfaces, HTTP headers, SSL/TLS, DNS, OSINT & Google Rank #1 SEO.",
    keywords: MASTER_GLOBAL_KEYWORDS,
    category: "Security Scanner",
    priority: 1.0,
    changeFrequency: "daily",
  },
  "/scan/seo-master": {
    path: "/scan/seo-master",
    title: "SEO Master & International Rank #1 Analyzer — Global Hreflang, JSON-LD & SERP Auditor",
    titleEn: "SEO Master & Global Google Rank #1 Scanner — International Hreflang, Schema & Technical SEO",
    description:
      "Audit SEO Master mendalam (35+ parameter teknik & internasional): analisis Hreflang multi-negara, JSON-LD Schema.org, Meta/OG/Twitter, Keyword Density, Security-SEO Trust Signals, serta generator kode SEO Rank #1.",
    descriptionEn:
      "Deep 35+ point Technical & International SEO Master Auditor. Check hreflang tags, JSON-LD structured data, Open Graph, keyword density, crawlability, security trust signals, and generate copy-paste Rank #1 meta tags.",
    keywords: [
      "SEO master analyzer",
      "international SEO checker",
      "hreflang tag validator",
      "JSON-LD schema generator",
      "Google rank 1 SEO audit tool",
      "technical SEO scanner online",
      "audit SEO website gratis",
      "cara rank 1 Google internasional",
    ],
    category: "SEO & Quality Control",
    priority: 0.98,
    changeFrequency: "daily",
  },
  "/scan/sentinel": {
    path: "/scan/sentinel",
    title: "Sentinel Vault Audit — Passive Sensitive File (.env, .git, Backup) & AES-256-GCM Claim",
    titleEn: "Sentinel Vault — Passive .env, .git & Backup Exposure Scanner with AES-256-GCM Evidence Vault",
    description:
      "Audit pasif kebocoran file sensitif (.env, .git/HEAD, backup.zip, wp-config.php.bak, AWS keys) dengan enkripsi bukti AES-256-GCM dan verifikasi klaim pemilik domain sah via DNS TXT / HTTP.",
    descriptionEn:
      "Passive sensitive file exposure scanner (.env, .git/HEAD, database dumps, wp-config.php.bak, cloud keys) protected inside an AES-256-GCM encrypted vault for verified domain owners.",
    keywords: [
      "exposed .env scanner",
      "git config exposure checker",
      "sensitive file leak detector",
      "AES-256-GCM security vault",
      "wp-config.php.bak scanner",
      "audit file sensitif website",
    ],
    category: "Security Scanner",
    priority: 0.95,
    changeFrequency: "daily",
  },
  "/qc": {
    path: "/qc",
    title: "Automated Website QC — Technical SEO, Core Web Vitals PageSpeed & Broken Link Auditor",
    titleEn: "Automated Web Quality Control — Technical SEO, Google PageSpeed & Accessibility Scanner",
    description:
      "Jalankan Quality Control (QC) website otomatis: audit 35+ indikator SEO Master & International SEO, skor Core Web Vitals via Google PageSpeed Insights (LCP, CLS, FCP, TBT), broken link & a11y.",
    descriptionEn:
      "Run automated website quality control in one click: 35+ technical & international SEO checks, Google PageSpeed Insights Core Web Vitals (LCP, CLS, TBT), broken link checker, and WCAG accessibility audit.",
    keywords: [
      "automated website quality control",
      "Core Web Vitals scanner",
      "Google PageSpeed Insights audit",
      "broken link checker online",
      "web accessibility a11y scanner",
      "QC website otomatis",
    ],
    category: "SEO & Quality Control",
    priority: 0.95,
    changeFrequency: "daily",
  },
  "/scan/headers": {
    path: "/scan/headers",
    title: "HTTP Security Headers Checker (Header Armor) — CSP, HSTS, X-Frame-Options & Referrer-Policy",
    titleEn: "Free HTTP Security Headers Analyzer — Check CSP, HSTS, XFO & Permissions-Policy",
    description:
      "Analisis & beri skor HTTP security headers domain secara pasif (Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).",
    descriptionEn:
      "Instant passive HTTP security headers scanner. Grade your Content-Security-Policy (CSP), HSTS, X-Frame-Options, Referrer-Policy, and CORS headers with one safe GET request.",
    keywords: [
      "HTTP security headers checker",
      "CSP analyzer online",
      "HSTS header checker",
      "securityheaders alternative",
      "cek security header website",
    ],
    category: "Security Scanner",
    priority: 0.9,
    changeFrequency: "weekly",
  },
  "/scan/secrets": {
    path: "/scan/secrets",
    title: "JavaScript Secret Hunter — Passive API Key, JWT, AWS & Credential Leak Scanner",
    titleEn: "JS Secret Hunter — Detect Hardcoded API Keys, Tokens & Credentials in JavaScript Bundles",
    description:
      "Pindai bundle JavaScript same-origin secara pasif menggunakan AST & regex presisi tinggi untuk mendeteksi kebocoran API key, AWS secret, Stripe token, Firebase config, dan private key.",
    descriptionEn:
      "Passively scan client-side JavaScript bundles for hardcoded secrets, AWS keys, Stripe tokens, OpenAI keys, and JWT secrets with zero value exploitation.",
    keywords: [
      "JavaScript secret scanner",
      "find API keys in JS bundles",
      "hardcoded credential detector",
      "client-side secret leak checker",
      "deteksi API key bocor di JS",
    ],
    category: "Security Scanner",
    priority: 0.9,
    changeFrequency: "weekly",
  },
  "/scan/exposure": {
    path: "/scan/exposure",
    title: "Cloud & Config Exposure Check — Passive RCE Shell Surface & Misconfiguration Scanner",
    titleEn: "Cloud Exposure & Misconfiguration Scanner — Detect Leaked Configs, Debuggers & Shell Surfaces",
    description:
      "Audit pasif misconfig cloud storage, eksposur .env/.git, debug endpoint (Laravel Ignition, Werkzeug, V8 Inspector, Go pprof), dan permukaan RCE (wp2shell, php2shell, node2shell, go2shell, py2shell).",
    descriptionEn:
      "Passive cloud exposure and misconfiguration scanner. Detect exposed debuggers, phpinfo, Laravel Ignition, Go pprof, Node V8 Inspector, and sensitive configuration files.",
    keywords: [
      "cloud misconfiguration scanner",
      "website exposure checker",
      "wp2shell php2shell node2shell scanner",
      "passive RCE surface audit",
      "cek kebocoran konfigurasi server",
    ],
    category: "Security Scanner",
    priority: 0.9,
    changeFrequency: "weekly",
  },
  "/scan/js": {
    path: "/scan/js",
    title: "JS Supply Chain & 3rd-Party Tracker Scanner — Outdated Libraries & CVE Detector",
    titleEn: "JavaScript Supply Chain Security Scanner — Detect Vulnerable JS Libraries & Trackers",
    description:
      "Inspeksi dependensi JavaScript eksternal dan tracker pihak ketiga. Deteksi library usang (jQuery, Lodash, React, Angular, Moment), kerentanan CVE publik, SRI hash, dan risiko privasi.",
    descriptionEn:
      "Audit client-side JavaScript supply chain security. Identify outdated frontend libraries, known CVEs, missing Subresource Integrity (SRI), and third-party tracking scripts.",
    keywords: [
      "JavaScript supply chain scanner",
      "frontend library CVE checker",
      "outdated JS library detector",
      "third-party script privacy audit",
      "Subresource Integrity SRI checker",
    ],
    category: "Security Scanner",
    priority: 0.88,
    changeFrequency: "weekly",
  },
  "/scan/ssl": {
    path: "/scan/ssl",
    title: "SSL/TLS Certificate & Cipher Intelligence Scanner — Expiry, Chain & Grade Analyzer",
    titleEn: "Free SSL/TLS Certificate Scanner — Check TLS 1.3, Cipher Suite, SANs & Expiry Grade",
    description:
      "Analisis handshake SSL/TLS pasif: periksa validitas rantai sertifikat, sisa masa aktif, protokol TLS 1.2/1.3, kekuatan cipher suite, Subject Alternative Names (SAN), dan skor keamanan kriptografi.",
    descriptionEn:
      "Passive SSL/TLS certificate analyzer. Inspect certificate chain validity, expiration countdown, TLS protocol support, cipher strength, and security grade.",
    keywords: [
      "SSL certificate checker online",
      "TLS security scanner",
      "check SSL expiry and chain",
      "SSL grade analyzer free",
      "cek sertifikat SSL domain",
    ],
    category: "Security Scanner",
    priority: 0.88,
    changeFrequency: "weekly",
  },
  "/scan/map": {
    path: "/scan/map",
    title: "Interactive Attack Surface Map — Visual Domain Endpoint & Asset Graph Explorer",
    titleEn: "Visual Attack Surface Mapper — Interactive Website Crawl, JS & API Endpoint Graph",
    description:
      "Pemetaan visual attack surface domain secara interaktif. Telusuri relasi halaman HTML, bundle JavaScript, form input, dan endpoint API dengan metode passive same-origin crawl.",
    descriptionEn:
      "Visualize your domain's attack surface in an interactive node graph. Map pages, JavaScript assets, forms, and discovered API endpoints with passive GET-only crawling.",
    keywords: [
      "attack surface mapping tool",
      "visual website endpoint graph",
      "passive webrecon graph",
      "API endpoint discovery scanner",
      "peta attack surface website",
    ],
    category: "Recon & OSINT",
    priority: 0.88,
    changeFrequency: "weekly",
  },
  "/scan/subdomain": {
    path: "/scan/subdomain",
    title: "Subdomain Takeover Watch & CT Log Enumerator — Passive crt.sh Recon Scanner",
    titleEn: "Passive Subdomain Finder & Subdomain Takeover Scanner via Certificate Transparency (crt.sh)",
    description:
      "Temukan seluruh subdomain via Certificate Transparency (crt.sh) secara pasif tanpa DNS brute-force, dan deteksi dangling CNAME yang rentan terhadap Subdomain Takeover (GitHub Pages, S3, Vercel, Heroku).",
    descriptionEn:
      "Discover subdomains passively via Certificate Transparency logs (crt.sh) and detect dangling CNAME records vulnerable to subdomain takeover across AWS S3, GitHub, Vercel, and Azure.",
    keywords: [
      "subdomain takeover scanner",
      "passive subdomain finder crt.sh",
      "certificate transparency subdomain enum",
      "dangling CNAME checker",
      "cek subdomain takeover gratis",
    ],
    category: "Recon & OSINT",
    priority: 0.88,
    changeFrequency: "weekly",
  },
  "/scan/dns": {
    path: "/scan/dns",
    title: "DNS Intelligence & Email Anti-Spoofing Scanner — SPF, DMARC, CAA, MX & NS Auditor",
    titleEn: "Passive DNS Intelligence & Email Security Posture Scanner (SPF, DMARC, CAA, DoH)",
    description:
      "Reconnaissance DNS pasif berbasis DNS-over-HTTPS (DoH): audit record A, AAAA, MX, NS, TXT, CAA, evaluasi postur anti-phishing/spoofing email (SPF & DMARC), dan deteksi permukaan serangan infrastruktur.",
    descriptionEn:
      "Passive DNS-over-HTTPS reconnaissance and email security analyzer. Audit A, AAAA, MX, NS, TXT, CAA records and validate SPF & DMARC anti-spoofing policies.",
    keywords: [
      "DNS intelligence scanner",
      "SPF DMARC email security checker",
      "DNS over HTTPS lookup tool",
      "CAA record validator",
      "cek DNS SPF DMARC domain",
    ],
    category: "Recon & OSINT",
    priority: 0.88,
    changeFrequency: "weekly",
  },
  "/scan/stack": {
    path: "/scan/stack",
    title: "Tech Stack Fingerprinter — Passive CMS, Framework, CDN, WAF & Server Detector",
    titleEn: "Website Technology Stack Detector — Identify CMS, Frontend Frameworks, WAF & CDN Passively",
    description:
      "Deteksi teknologi website secara pasif dari HTTP response headers, cookie signatures, dan HTML DOM markers: kenali Next.js, WordPress, Laravel, Cloudflare, Vercel, Nginx, dan ratusan stack lainnya.",
    descriptionEn:
      "Passively fingerprint website technologies from HTTP headers and HTML signatures. Identify frameworks, CMS, CDN, WAF, analytics, and web servers instantaneously.",
    keywords: [
      "website technology detector",
      "tech stack fingerprinter online",
      "Wappalyzer alternative free",
      "detect CMS framework CDN WAF",
      "cek teknologi website",
    ],
    category: "Recon & OSINT",
    priority: 0.86,
    changeFrequency: "weekly",
  },
  "/scan/breach": {
    path: "/scan/breach",
    title: "Breach Peek — Free Passive OSINT Data Breach & Credential Exposure Checker",
    titleEn: "Free OSINT Data Breach Checker — Check Email & Domain Exposure in Public Breaches",
    description:
      "Periksa apakah alamat email atau domain organisasi Anda pernah muncul dalam insiden kebocoran data publik (data breach) secara 100% pasif, gratis, dan dilengkapi checklist mitigasi insiden.",
    descriptionEn:
      "Check if your email address or corporate domain appears in known public data breaches. 100% passive OSINT breach intelligence with incident remediation checklists.",
    keywords: [
      "data breach checker free",
      "check email breach OSINT",
      "domain credential leak scanner",
      "haveibeenpwned alternative",
      "cek kebocoran data email domain",
    ],
    category: "Recon & OSINT",
    priority: 0.88,
    changeFrequency: "weekly",
  },
  "/scan/osint": {
    path: "/scan/osint",
    title: "Multi-Source OSINT Recon Lookup — Domain, Email, Username & Digital Footprint Scanner",
    titleEn: "Passive OSINT Reconnaissance Tool — Domain, Email & Social Username Footprint Finder",
    description:
      "Reconnaissance Open-Source Intelligence (OSINT) pasif untuk domain, alamat email, nama, dan username lintas platform menggunakan sumber data publik resmi tanpa interaksi invasif.",
    descriptionEn:
      "Multi-source passive OSINT lookup for domains, emails, and usernames across public registries and social platforms with zero intrusive probing.",
    keywords: [
      "OSINT lookup tool online",
      "username footprint scanner",
      "domain OSINT reconnaissance",
      "passive digital footprint checker",
      "alat OSINT Indonesia",
    ],
    category: "Recon & OSINT",
    priority: 0.86,
    changeFrequency: "weekly",
  },
  "/scan/shield-status": {
    path: "/scan/shield-status",
    title: "Threat Lab & Shield Status Monitor — Real-Time Web Protection & Guard Telemetry",
    titleEn: "Threat Lab & Web Shield Status — Real-Time WAF, Latency & Security Guard Monitoring",
    description:
      "Pantau status proteksi aplikasi web, latensi jaringan, respons WAF/Shield, dan telemetri keamanan secara real-time di Threat Lab Sentinel-ID.",
    descriptionEn:
      "Monitor real-time web application shield status, WAF response telemetry, guard posture, and endpoint latency.",
    keywords: [
      "web shield status monitor",
      "WAF protection checker",
      "real-time security telemetry",
      "threat lab security monitor",
    ],
    category: "Security Scanner",
    priority: 0.84,
    changeFrequency: "weekly",
  },
  "/maintenance-log": {
    path: "/maintenance-log",
    title: "AI Maintenance & Server Log Security Analyzer — Anomaly, CVE & Intrusion Detector",
    titleEn: "AI Server Log & Maintenance Analyzer — Detect Security Anomalies & Attack Patterns",
    description:
      "Analisis log pemeliharaan server, Nginx/Apache access log, dan error trace untuk mengidentifikasi anomali keamanan, percobaan eksploitasi, serta rekomendasi mitigasi berbasis AI.",
    descriptionEn:
      "Analyze server maintenance and access logs to detect intrusion attempts, error anomalies, and actionable security remediation steps.",
    keywords: [
      "AI server log analyzer",
      "security log anomaly detector",
      "maintenance log security audit",
      "analisis log server otomatis",
    ],
    category: "Security Scanner",
    priority: 0.82,
    changeFrequency: "weekly",
  },
  "/history": {
    path: "/history",
    title: "Public Security Audit History & Telemetry Archive — Sentinel-ID",
    titleEn: "Security Scan History & Audit Telemetry Archive — Sentinel-ID",
    description:
      "Telusuri riwayat pemindaian keamanan pasif, skor postur keamanan domain, dan ringkasan temuan CWE/CVE pada platform Sentinel-ID.",
    descriptionEn:
      "Browse recent passive security scans, domain security posture scores, and CWE/CVE vulnerability summaries on Sentinel-ID.",
    keywords: [
      "website security scan history",
      "domain audit archive",
      "riwayat scan keamanan web",
    ],
    category: "Security Scanner",
    priority: 0.78,
    changeFrequency: "daily",
  },
  "/docs": {
    path: "/docs",
    title: "Technical Documentation & Passive Security Architecture — Sentinel-ID",
    titleEn: "Sentinel-ID Documentation — Passive Crawler, AES-256-GCM Vault & Scoring Architecture",
    description:
      "Dokumentasi teknis resmi Sentinel-ID: arsitektur crawler pasif GET-only, SSRF Guard, skema Redis, sistem penilaian risiko CWE/CVSS, dan Brankas Bukti AES-256-GCM.",
    descriptionEn:
      "Official technical documentation for Sentinel-ID: GET-only passive crawler architecture, SSRF protection, Redis schema, CWE scoring system, and AES-256-GCM encrypted evidence vault.",
    keywords: [
      "Sentinel-ID documentation",
      "passive security scanner architecture",
      "SSRF guard implementation",
      "dokumentasi audit keamanan web",
    ],
    category: "Documentation",
    priority: 0.85,
    changeFrequency: "weekly",
  },
  "/api-docs": {
    path: "/api-docs",
    title: "REST API & SSE Streaming Reference — Sentinel-ID Security & SEO Automation",
    titleEn: "Sentinel-ID API Reference — Automate Passive Security Scans & SEO Quality Control",
    description:
      "Referensi lengkap REST API & Server-Sent Events (SSE) Sentinel-ID untuk mengintegrasikan audit keamanan pasif dan QC SEO otomatis ke dalam pipeline CI/CD Anda.",
    descriptionEn:
      "Complete REST API and Server-Sent Events (SSE) reference for integrating Sentinel-ID passive security audits and automated SEO quality control into CI/CD workflows.",
    keywords: [
      "security scanner REST API",
      "automated SEO audit API",
      "CI/CD security scanning API",
      "Sentinel-ID API reference",
    ],
    category: "Documentation",
    priority: 0.85,
    changeFrequency: "weekly",
  },
};

/**
 * Helper to generate full Next.js Metadata for any route in the application
 * with bilingual title/description, canonical URL, multi-region hreflang alternates,
 * Open Graph (with multi-locale alternates), Twitter Card, and GoogleBot directives.
 */
export function buildPageMetadata(routeKey: string, overrides?: Partial<Metadata>): Metadata {
  const cfg = SEO_ROUTES_REGISTRY[routeKey] ?? SEO_ROUTES_REGISTRY["/"];
  const fullUrl = `${SITE_URL}${cfg.path}`;

  return {
    title: cfg.title,
    description: `${cfg.description} | ${cfg.descriptionEn}`,
    keywords: Array.from(new Set([...cfg.keywords, ...MASTER_GLOBAL_KEYWORDS.slice(0, 15)])),
    alternates: {
      canonical: fullUrl,
      languages: buildLanguageAlternates(cfg.path),
      types: {
        "application/rss+xml": `${SITE_URL}/feed.xml`,
      },
    },
    openGraph: {
      title: cfg.titleEn,
      description: cfg.descriptionEn,
      url: fullUrl,
      siteName: SITE_NAME,
      locale: "en_US",
      alternateLocale: ["id_ID", "en_GB", "en_SG", "en_AU", "ms_MY", "ja_JP", "de_DE"],
      type: "website",
      images: [
        {
          url: "/image/image.png",
          width: 1200,
          height: 630,
          alt: `${cfg.titleEn} — Sentinel-ID`,
        },
      ],
    },
    twitter: {
      card: "summary_large_image",
      title: cfg.titleEn,
      description: cfg.descriptionEn,
      images: ["/image/image.png"],
      creator: "@Kasyaf",
      site: "@SentinelID",
    },
    robots: {
      index: true,
      follow: true,
      nocache: false,
      googleBot: {
        index: true,
        follow: true,
        noimageindex: false,
        "max-video-preview": -1,
        "max-image-preview": "large",
        "max-snippet": -1,
      },
    },
    ...overrides,
  };
}

/**
 * Bilingual FAQ Items for Google Rich Snippets (FAQPage Schema) & Homepage Knowledge Hub
 */
export const GLOBAL_SEO_FAQS = [
  {
    qId: "Apakah Sentinel-ID 100% aman dan tidak merusak server produksi?",
    aId: "Ya. Sentinel-ID beroperasi secara 100% pasif menggunakan metode HTTP GET/HEAD-only tanpa injeksi payload, tanpa brute-force, dan dilengkapi SSRF Guard serta pembatas RequestBudget. Aman dijalankan pada server produksi kapan saja.",
    qEn: "Is Sentinel-ID 100% safe for production servers (zero-exploit)?",
    aEn: "Yes. Sentinel-ID is a strictly passive, non-intrusive website security auditor using read-only HTTP GET/HEAD requests with zero exploit payloads, strict SSRF protection, and rate-limited request budgets.",
  },
  {
    qId: "Bagaimana cara kerja Brankas Bukti Terenkripsi AES-256-GCM (Sentinel Vault)?",
    aId: "Ketika pemindai mendeteksi file sensitif seperti .env, .git/HEAD, wp-config.php.bak, atau kunci AWS, isi rahasia langsung di-redact dari publik dan dienkripsi menggunakan AES-256-GCM di Vault Admin. Hanya pemilik sah domain yang dapat mengklaim bukti tersebut melalui verifikasi DNS TXT atau file HTTP.",
    qEn: "How does the AES-256-GCM Encrypted Evidence Vault protect leaked secrets?",
    aEn: "When Sentinel-ID detects exposed .env files, .git repositories, database backups, or API keys, raw values are never shown publicly. Evidence is encrypted with AES-256-GCM and can only be unlocked once by the verified domain owner via DNS TXT or HTTP token verification.",
  },
  {
    qId: "Apa saja celah RCE & Shell Surface yang diperiksa secara pasif?",
    aId: "Mesin Deep Shell & OOB memeriksa 6 permukaan runtime utama secara pasif: wp2shell (WordPress config & REST exposure), php2shell (Laravel Ignition CVE-2021-3129, PHPUnit, phpinfo), node2shell (V8 Inspector, child_process/vm sinks), go2shell (Go pprof & expvar leaks), py2shell (Werkzeug console, Jupyter API, Celery), serta Node Out-of-Bounds memory & heapdump.",
    qEn: "Which RCE and runtime shell surfaces does Sentinel-ID detect?",
    aEn: "Sentinel-ID passively audits six runtime surfaces: wp2shell (WordPress config/debug leaks), php2shell (Laravel Ignition, PHPUnit, phpinfo), node2shell (V8 inspector, SSR AST sinks), go2shell (Go pprof/expvar), py2shell (Werkzeug debugger, Jupyter kernels), and Node.js Out-of-Bounds heap/memory exposures.",
  },
  {
    qId: "Bagaimana fitur SEO Master membantu website naik ke Rank #1 Google & muncul secara internasional?",
    aId: "Modul SEO Master memeriksa lebih dari 35 sinyal teknis Google: tag Hreflang multi-negara (id-ID, en-US, en-GB, x-default), struktur JSON-LD Schema.org, Meta Title & Description optimal, Open Graph, Twitter Card, rasio kata kunci, Core Web Vitals (LCP/CLS/TBT), serta Security-SEO Trust Signals (HTTPS/HSTS/CSP) yang menjadi faktor peringkat Google global.",
    qEn: "How does the SEO Master module help websites rank #1 on Google internationally?",
    aEn: "SEO Master audits 35+ Google ranking factors including international hreflang tags (en-US, en-GB, id-ID, x-default), Schema.org JSON-LD graphs, Core Web Vitals, keyword density, canonicalization, Open Graph, and HTTPS/HSTS security trust signals, plus generates ready-to-paste Rank #1 code.",
  },
];

/**
 * Generates the comprehensive Schema.org JSON-LD @graph for Google Rich Results
 * Includes: Organization, WebSite (with SearchAction), SoftwareApplication,
 * Service, ItemList (14 Security & SEO Tools), and FAQPage.
 */
export function buildMasterJsonLdGraph() {
  const toolRoutes = Object.values(SEO_ROUTES_REGISTRY).filter((r) => r.path !== "");

  return {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "Organization",
        "@id": `${SITE_URL}/#organization`,
        name: SITE_NAME,
        alternateName: ["Sentinel-ID Security Auditor", "Sentinel-ID Passive Web Scanner"],
        url: SITE_URL,
        logo: {
          "@type": "ImageObject",
          url: `${SITE_URL}/image/image.png`,
          width: 512,
          height: 512,
        },
        founder: {
          "@type": "Person",
          name: "Kasyaf",
          url: "https://kasyaf-cv.my.id",
        },
        sameAs: [
          "https://kasyaf-cv.my.id",
          "https://github.com/MeledakCik/audit-otomatis",
        ],
        areaServed: "Worldwide",
        knowsLanguage: ["id-ID", "en-US", "en-GB", "ms-MY", "ja-JP", "de-DE"],
        award: "Verified by Google Developer Bandung (GDG Bandung)",
      },
      {
        "@type": "WebSite",
        "@id": `${SITE_URL}/#website`,
        url: SITE_URL,
        name: SITE_BRAND,
        publisher: {
          "@id": `${SITE_URL}/#organization`,
        },
        inLanguage: ["id-ID", "en-US"],
        potentialAction: [
          {
            "@type": "SearchAction",
            target: {
              "@type": "EntryPoint",
              urlTemplate: `${SITE_URL}/scan/seo-master?domain={search_term_string}`,
            },
            "query-input": "required name=search_term_string",
          },
        ],
      },
      {
        "@type": ["SoftwareApplication", "WebApplication"],
        "@id": `${SITE_URL}/#software`,
        name: "Sentinel-ID Passive Website Security Auditor & SEO Master",
        applicationCategory: "SecurityApplication, DeveloperApplication, SEOApplication",
        operatingSystem: "All (Web-based Cloud Platform)",
        url: SITE_URL,
        offers: {
          "@type": "Offer",
          price: "0",
          priceCurrency: "USD",
          availability: "https://schema.org/InStock",
        },
        aggregateRating: {
          "@type": "AggregateRating",
          ratingValue: "4.9",
          ratingCount: "328",
          bestRating: "5",
          worstRating: "1",
        },
        featureList: [
          "100% Passive GET-Only Multi-Page Security Crawler",
          "AES-256-GCM Encrypted Sensitive File Evidence Vault (.env, .git, backups)",
          "Deep Passive RCE & Shell Surface Engine (wp2shell, php2shell, node2shell, go2shell, py2shell, Node OOB)",
          "SEO Master & International Rank #1 Hreflang / JSON-LD Schema Analyzer",
          "HTTP Security Headers Grader (CSP, HSTS, X-Frame-Options)",
          "JavaScript Secret Hunter & Supply Chain CVE Scanner",
          "Passive Subdomain Takeover Watch (crt.sh) & DNS-over-HTTPS Intelligence",
          "SSL/TLS Certificate & Cipher Suite Inspector",
          "Interactive Visual Attack Surface Node Graph",
          "Multi-Source OSINT & Public Data Breach Checker",
        ],
      },
      {
        "@type": "ItemList",
        "@id": `${SITE_URL}/#tools-list`,
        name: "Sentinel-ID Global Security & SEO Master Modules",
        itemListOrder: "https://schema.org/ItemListOrderAscending",
        numberOfItems: toolRoutes.length,
        itemListElement: toolRoutes.map((route, idx) => ({
          "@type": "ListItem",
          position: idx + 1,
          name: route.titleEn,
          description: route.descriptionEn,
          url: `${SITE_URL}${route.path}`,
        })),
      },
      {
        "@type": "FAQPage",
        "@id": `${SITE_URL}/#faq`,
        mainEntity: GLOBAL_SEO_FAQS.flatMap((item) => [
          {
            "@type": "Question",
            name: item.qEn,
            acceptedAnswer: {
              "@type": "Answer",
              text: item.aEn,
            },
          },
          {
            "@type": "Question",
            name: item.qId,
            acceptedAnswer: {
              "@type": "Answer",
              text: item.aId,
            },
          },
        ]),
      },
    ],
  };
}
