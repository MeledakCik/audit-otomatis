"use client";

import React, { useState, useMemo } from "react";
import {
  Shield, Search, TrendingUp, Lock, ClipboardCheck, Clock, Terminal,
  ShieldAlert, KeyRound, AlertTriangle, FileCode2, Award, Wrench,
  Network, Globe, Radio, Layers, Eye, UserCheck, ShieldCheck,
  BookOpen, Code2, Settings, ChevronRight, ChevronDown,
  PanelLeftClose, PanelLeftOpen, ExternalLink, X
} from "lucide-react";

export interface NavModuleItem {
  id: string;
  title: string;
  route: string;
  badge?: string;
  category: "Core Audit & Scan" | "Vulnerability & Code" | "Recon & Threat Intel" | "Resources & Admin";
  description: string;
  iconName: string;
}

export const SENTINEL_NAV_ITEMS: NavModuleItem[] = [
  { id: "overview", title: "Overview & Scan", route: "/", badge: "VAULT", category: "Core Audit & Scan", description: "Unified Deep Security Scanner", iconName: "shield" },
  { id: "seo-master", title: "SEO Master & Rank #1", route: "/scan/seo-master", badge: "GLOBAL", category: "Core Audit & Scan", description: "Audit 35+ sinyal Google SERP & 13 hreflang", iconName: "trending" },
  { id: "sentinel-vault", title: "Sentinel Vault & Klaim", route: "/scan/sentinel", badge: "AES", category: "Core Audit & Scan", description: "Brankas Bukti AES-256-GCM", iconName: "lock" },
  { id: "qc-otomatis", title: "QC Otomatis", route: "/qc", badge: "QC", category: "Core Audit & Scan", description: "Audit kualitas SEO & PageSpeed", iconName: "clipboard" },
  { id: "scan-history", title: "Scan History", route: "/history", category: "Core Audit & Scan", description: "Riwayat pemindaian domain", iconName: "clock" },
  { id: "request-inspector", title: "Request Inspector", route: "/requests", category: "Core Audit & Scan", description: "Log HTTP GET/HEAD request", iconName: "terminal" },
  { id: "header-armor", title: "Header Armor", route: "/scan/headers", badge: "HTTP", category: "Vulnerability & Code", description: "Analisis CSP, HSTS, XFO", iconName: "shield-alert" },
  { id: "secret-hunter", title: "Secret Hunter", route: "/scan/secrets", badge: "AST", category: "Vulnerability & Code", description: "Deteksi API key & token bocor", iconName: "key" },
  { id: "exposure-check", title: "Exposure Check", route: "/scan/exposure", category: "Vulnerability & Code", description: "Cek eksposur file sensitif & shell surface", iconName: "alert" },
  { id: "js-supply-chain", title: "JS Supply Chain", route: "/scan/js", badge: "CVE", category: "Vulnerability & Code", description: "Deteksi library usang & CVE", iconName: "file-code" },
  { id: "ssl-tls-checker", title: "SSL/TLS Checker", route: "/scan/ssl", badge: "TLS", category: "Vulnerability & Code", description: "Inspeksi sertifikat & TLS 1.3", iconName: "award" },
  { id: "maintenance-log-ai", title: "Maintenance Log AI", route: "/maintenance-log", badge: "AI", category: "Vulnerability & Code", description: "Log pemeliharaan berbasis AI", iconName: "wrench" },
  { id: "attack-surface-map", title: "Attack Surface Map", route: "/scan/map", badge: "GRAPH", category: "Recon & Threat Intel", description: "Visualisasi graf permukaan serangan", iconName: "network" },
  { id: "subdomain-watch", title: "Subdomain Watch", route: "/scan/subdomain", badge: "CT", category: "Recon & Threat Intel", description: "Enumerasi CT logs crt.sh", iconName: "globe" },
  { id: "dns-intelligence", title: "DNS Intelligence", route: "/scan/dns", badge: "DoH", category: "Recon & Threat Intel", description: "Audit DNS A/MX/TXT, SPF & DMARC", iconName: "radio" },
  { id: "tech-stack", title: "Tech Stack", route: "/scan/stack", category: "Recon & Threat Intel", description: "Identifikasi pasif framework & WAF", iconName: "layers" },
  { id: "breach-peek", title: "Breach Peek", route: "/scan/breach", badge: "OSINT", category: "Recon & Threat Intel", description: "Cek kebocoran data publik", iconName: "eye" },
  { id: "osint-lookup", title: "OSINT Lookup", route: "/scan/osint", badge: "RECON", category: "Recon & Threat Intel", description: "Reconnaissance username, email & domain", iconName: "user-check" },
  { id: "shield-status", title: "Shield Status", route: "/scan/shield-status", category: "Recon & Threat Intel", description: "Status ketahanan WAF/Cloudflare", iconName: "shield-check" },
  { id: "documentation", title: "Documentation", route: "/docs", category: "Resources & Admin", description: "Dokumentasi teknis Sentinel-ID", iconName: "book" },
  { id: "api-reference", title: "API Reference", route: "/api-docs", category: "Resources & Admin", description: "Referensi endpoint REST API", iconName: "code" },
  { id: "admin-console", title: "Admin Console", route: "/admin", badge: "ADMIN", category: "Resources & Admin", description: "Command Center Vault AES-256-GCM", iconName: "settings" }
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

export function AppSidebar({
  open = false,
  onClose
}: {
  open?: boolean;
  onClose?: () => void;
} = {}) {
  const [collapsed, setCollapsed] = useState(false);
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
      (i) => i.title.toLowerCase().includes(q) || i.route.toLowerCase().includes(q)
    );
  }, [searchQuery]);

  const categories: NavModuleItem["category"][] = [
    "Core Audit & Scan",
    "Vulnerability & Code",
    "Recon & Threat Intel",
    "Resources & Admin"
  ];

  const inner = (
    <aside
      className={`glass-panel flex flex-col h-full rounded-3xl transition-all duration-300 ${
        collapsed ? "w-[72px] p-2.5" : "w-64 p-3.5"
      }`}
    >
      {/* Hanya Search & Collapse — TIDAK mengulang Logo Sentinel-ID agar tidak ganda dengan AppShell */}
      <div className="flex items-center gap-2 pb-3 border-b border-[var(--border)]">
        {!collapsed && (
          <div className="glass-pill flex-1 flex items-center gap-2 px-3 py-2 rounded-xl">
            <Search className="w-3.5 h-3.5 text-pink-500 shrink-0" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Filter modul audit..."
              className="w-full bg-transparent text-xs focus:outline-none"
            />
          </div>
        )}
        <button
          type="button"
          onClick={() => setCollapsed(!collapsed)}
          className={`glass-pill p-2 rounded-xl hover:opacity-80 ${collapsed ? "mx-auto" : "shrink-0"}`}
          title={collapsed ? "Perluas Sidebar" : "Ciutkan Sidebar"}
        >
          {collapsed ? <PanelLeftOpen className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
        </button>
        {onClose && (
          <button type="button" onClick={onClose} className="lg:hidden glass-pill p-2 rounded-xl">
            <X className="w-4 h-4" />
          </button>
        )}
      </div>

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
                  className="w-full flex items-center justify-between px-2 py-1 text-[10px] font-mono uppercase tracking-wider text-[var(--muted)]"
                >
                  <span>{cat}</span>
                  {isOpen ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
                </button>
              )}
              {(isOpen || collapsed) && (
                <div className="space-y-1">
                  {items.map((item) => (
                    <a
                      key={item.id}
                      href={item.route}
                      className={`flex items-center justify-between gap-2 rounded-xl transition hover:bg-pink-500/10 ${
                        collapsed ? "p-2.5 justify-center" : "px-2.5 py-2"
                      }`}
                    >
                      <div className="flex items-center gap-2.5 min-w-0">
                        <ModuleIcon name={item.iconName} className="w-4 h-4 text-pink-500 shrink-0" />
                        {!collapsed && <span className="text-xs truncate">{item.title}</span>}
                      </div>
                      {!collapsed && item.badge && (
                        <span className="text-[10px] font-mono font-semibold px-1.5 py-0.5 rounded bg-pink-500/15 text-pink-500 shrink-0">
                          {item.badge}
                        </span>
                      )}
                    </a>
                  ))}
                </div>
              )}
            </div>
          );
        })}
      </nav>

      {!collapsed && (
        <div className="pt-2.5 border-t border-[var(--border)]">
          <div className="glass-pill rounded-2xl p-2.5 flex items-center justify-between">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="w-7 h-7 rounded-full bg-gradient-to-br from-pink-500 to-purple-600 flex items-center justify-center text-white text-xs font-bold shrink-0">
                K
              </div>
              <div className="min-w-0">
                <div className="text-[9px] font-mono uppercase text-[var(--muted)]">Lead Author</div>
                <div className="text-xs font-bold truncate">Kasyaf · v3.6</div>
              </div>
            </div>
            <ExternalLink className="w-3.5 h-3.5 text-[var(--muted)] shrink-0" />
          </div>
        </div>
      )}
    </aside>
  );

  return (
    <>
      <div className="hidden lg:block h-[calc(100vh-5.75rem)] sticky top-20 shrink-0">{inner}</div>
      {open && (
        <div className="fixed inset-0 z-50 lg:hidden flex">
          <div className="fixed inset-0 bg-black/50 backdrop-blur-sm" onClick={onClose} />
          <div className="relative z-10 h-full p-3">{inner}</div>
        </div>
      )}
    </>
  );
}
export default AppSidebar;
