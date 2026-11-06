"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import Image from "next/image";
import {
  LayoutGrid,
  ClipboardCheck,
  History,
  BookOpen,
  Code2,
  Terminal,
  Wrench,
  ShieldHalf,
  KeyRound,
  Map,
  Radar,
  Globe2,
  ExternalLink,
  UserCircle,
  TrafficConeIcon,
  Fingerprint,
  LucideIcon,
  ShieldCheck,
  FileJson,
  UserSearch,
  ShellIcon,
  Lock,
  Search,
  ShieldAlert,
  TrendingUp,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { VerifiedBadge } from "./verified-badge";

interface NavItem {
  label: string;
  icon: LucideIcon;
  href: string;
  badge?: string;
}

interface NavGroup {
  title: string;
  items: NavItem[];
}

const NAV_GROUPS: NavGroup[] = [
  {
    title: "Core Audit & Scan",
    items: [
      { label: "Overview & Scan", icon: LayoutGrid, href: "/", badge: "VAULT" },
      { label: "SEO Master & Rank #1", icon: TrendingUp, href: "/scan/seo-master", badge: "GLOBAL" },
      { label: "Sentinel Vault & Klaim", icon: Lock, href: "/scan/sentinel", badge: "AES" },
      { label: "QC Otomatis", icon: ClipboardCheck, href: "/qc" },
      { label: "Scan History", icon: History, href: "/history" },
      { label: "Request Inspector", icon: Terminal, href: "/requests" },
    ],
  },
  {
    title: "Vulnerability & Code",
    items: [
      { label: "Header Armor", icon: ShieldHalf, href: "/scan/headers" },
      { label: "Secret Hunter", icon: KeyRound, href: "/scan/secrets" },
      { label: "Exposure Check", icon: ExternalLink, href: "/scan/exposure" },
      { label: "JS Supply Chain", icon: FileJson, href: "/scan/js" },
      { label: "SSL/TLS Checker", icon: ShellIcon, href: "/scan/ssl" },
      { label: "Maintenance Log AI", icon: Wrench, href: "/maintenance-log" },
    ],
  },
  {
    title: "Recon & Threat Intel",
    items: [
      { label: "Attack Surface Map", icon: Map, href: "/scan/map" },
      { label: "Subdomain Watch", icon: Globe2, href: "/scan/subdomain" },
      { label: "DNS Intelligence", icon: TrafficConeIcon, href: "/scan/dns" },
      { label: "Tech Stack", icon: Fingerprint, href: "/scan/stack" },
      { label: "Breach Peek", icon: Radar, href: "/scan/breach" },
      { label: "OSINT Lookup", icon: UserSearch, href: "/scan/osint" },
      { label: "Shield Status", icon: ShieldCheck, href: "/scan/shield-status" },
    ],
  },
  {
    title: "Resources & Admin",
    items: [
      { label: "Documentation", icon: BookOpen, href: "/docs" },
      { label: "API Reference", icon: Code2, href: "/api-docs" },
      { label: "Admin Console", icon: ShieldAlert, href: "/admin", badge: "ADMIN" },
    ],
  },
];

export function AppSidebar() {
  const pathname = usePathname();
  const [filter, setFilter] = useState("");

  const q = filter.trim().toLowerCase();

  return (
    <div className="flex h-full w-64 max-w-full flex-col bg-[#0d0916] border-r border-white/[0.07] select-none">
      {/* Header Logo */}
      <div className="flex h-16 items-center gap-3 px-4 border-b border-white/[0.07] shrink-0">
        <div className="h-9 w-9 grid place-items-center rounded-xl bg-gradient-to-br from-purple-500 via-fuchsia-500 to-pink-500 text-black shadow-lg shadow-purple-500/25 shrink-0">
          <Image
            src="/image/image.png"
            alt="Sentinel-ID Passive Website Security Auditor & SEO Master Logo"
            width={22}
            height={22}
            className="object-contain"
          />
        </div>
        <div className="leading-tight min-w-0">
          <div className="flex items-center gap-1.5">
            <span className="text-sm font-extrabold tracking-wider text-white truncate">
              SENTINEL-ID
            </span>
            <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_8px_#34d399]" />
          </div>
          <div className="text-[10px] font-mono tracking-[0.22em] text-purple-300 uppercase">
            SECURITY &amp; SEO MASTER
          </div>
        </div>
      </div>

      {/* Quick Search Filter */}
      <div className="px-3 pt-3 pb-1 shrink-0">
        <div className="relative">
          <Search className="h-3.5 w-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
          <input
            type="text"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            placeholder="Filter modul audit..."
            aria-label="Filter modul navigasi"
            className="w-full h-8 rounded-lg border border-white/[0.08] bg-white/[0.03] pl-8 pr-2.5 text-xs font-mono text-white placeholder:text-slate-500 outline-none focus:border-purple-500/50"
          />
        </div>
      </div>

      {/* Categorized Navigation Items */}
      <nav
        aria-label="Navigasi utama"
        className="flex-1 px-3 py-3 space-y-5 overflow-y-auto thin-scroll"
      >
        {NAV_GROUPS.map((group) => {
          const filtered = q
            ? group.items.filter((i) => i.label.toLowerCase().includes(q))
            : group.items;
          if (filtered.length === 0) return null;

          return (
            <div key={group.title} className="space-y-1">
              <div className="px-2.5 pb-1 text-[10px] font-mono font-bold tracking-widest text-slate-400/80 uppercase">
                {group.title}
              </div>
              {filtered.map((item) => {
                const active =
                  item.href === "/"
                    ? pathname === "/"
                    : pathname === item.href || pathname?.startsWith(`${item.href}/`);
                const Icon = item.icon;

                return (
                  <Link
                    key={item.label}
                    href={item.href}
                    aria-current={active ? "page" : undefined}
                    className={cn(
                      "flex items-center justify-between gap-2 rounded-xl px-2.5 py-2 text-xs font-mono transition-all group focus-visible:outline-2 focus-visible:outline-accent",
                      active
                        ? "bg-gradient-to-r from-purple-500/20 to-pink-500/10 text-white border border-purple-500/35 shadow-sm"
                        : "text-slate-300/75 hover:text-white hover:bg-white/[0.04] border border-transparent"
                    )}
                  >
                    <span className="flex items-center gap-2.5 min-w-0">
                      <Icon
                        aria-hidden="true"
                        className={cn(
                          "h-4 w-4 shrink-0 transition-colors",
                          active
                            ? "text-purple-300"
                            : "text-slate-400 group-hover:text-purple-300"
                        )}
                      />
                      <span className="font-medium truncate">{item.label}</span>
                    </span>
                    {item.badge && (
                      <span
                        className={cn(
                          "rounded-md px-1.5 py-0.5 text-[9px] font-bold tracking-wider shrink-0",
                          item.badge === "ADMIN"
                            ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                            : item.badge === "GLOBAL"
                            ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/35"
                            : "bg-purple-500/20 text-purple-300 border border-purple-500/30"
                        )}
                      >
                        {item.badge}
                      </span>
                    )}
                  </Link>
                );
              })}
            </div>
          );
        })}
      </nav>

      {/* Google Developer Bandung Verified + Author Footer */}
      <div className="p-3 space-y-2 border-t border-white/[0.06] bg-black/25 shrink-0">
        <VerifiedBadge variant="sidebar" />

        <a
          href="https://kasyaf-cv.my.id"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-2.5 rounded-xl border border-white/[0.08] bg-white/[0.02] px-3 py-2 group hover:border-purple-500/40 hover:bg-white/[0.05] transition-all"
        >
          <div className="h-7 w-7 grid place-items-center rounded-full bg-purple-500/15 border border-purple-500/30 shrink-0">
            <UserCircle className="h-4 w-4 text-purple-300" />
          </div>
          <div className="flex-1 min-w-0 leading-tight">
            <div className="text-[10px] font-mono tracking-wider text-slate-400 uppercase">
              Lead Author
            </div>
            <div className="text-xs font-semibold text-white group-hover:text-purple-200 flex items-center gap-1 truncate">
              <span>Kasyaf</span>
              <ExternalLink aria-hidden="true" className="h-3 w-3 opacity-70 shrink-0" />
            </div>
          </div>
        </a>
      </div>
    </div>
  );
}
