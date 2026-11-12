// Sumber tunggal data navigasi & katalog modul (dipakai sidebar + landing).
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
  { id: "overview", title: "Overview & Scan", route: "/dashboard", badge: "VAULT", badgeTone: "purple", category: "Core Audit & Scan", description: "Unified Deep Security Scanner (8 engine pasif sekaligus) & ringkasan postur domain.", iconName: "shield" },
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
