"use client";

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
} from "lucide-react";
import { cn } from "@/lib/utils";

interface NavItem {
  label: string;
  icon: LucideIcon;
  href: string;
}

const MAIN: NavItem[] = [
  { label: "Overview", icon: LayoutGrid, href: "/" },
  { label: "QC Otomatis", icon: ClipboardCheck, href: "/qc" },
  { label: "Scan History", icon: History, href: "/history" },
  { label: "Request Inspector", icon: Terminal, href: "/requests" },
  { label: "Maintenance Log", icon: Wrench, href: "/maintenance-log" },
  { label: "Header Armor", icon: ShieldHalf, href: "/scan/headers" },
  { label: "Secret Hunter", icon: KeyRound, href: "/scan/secrets" },
  { label: "Attack Surface Map", icon: Map, href: "/scan/map" },
  { label: "Breach Peek", icon: Radar, href: "/scan/breach" },
  { label: "Subdomain Watch", icon: Globe2, href: "/scan/subdomain" },
  { label: "Tech Stack", icon: Fingerprint, href: "/scan/stack" },
  { label: "Shield Status", icon: ShieldCheck, href: "/scan/shield-status" },
  { label: "DNS Checker", icon: TrafficConeIcon, href: "/scan/dns" },
];


const RESOURCES: NavItem[] = [
  { label: "Documentation", icon: BookOpen, href: "/docs" },
  { label: "API Reference", icon: Code2, href: "/api-docs" },
];

export function AppSidebar() {
  const pathname = usePathname();

  const renderNavItems = (items: NavItem[]) => {
    return items.map((item) => {
      const active = pathname === item.href;
      const Icon = item.icon;

      return (
        <Link
          key={item.label}
          href={item.href}
          className={cn(
            "flex items-center gap-3 rounded-lg px-3 py-2.5 text-xs font-mono transition-all group",
            active
              ? "bg-[#2a1842] text-white shadow-[inset_0_1px_0_0_rgba(255,255,255,0.1)] border border-purple-500/20"
              : "text-white/50 hover:text-white hover:bg-white/[0.04]"
          )}
        >
          <Icon
            className={cn(
              "h-4 w-4 transition-colors",
              active ? "text-[#c084fc]" : "text-white/40 group-hover:text-white/70"
            )}
          />
          <span className="font-medium">{item.label}</span>
        </Link>
      );
    });
  };

  return (
    <aside className="flex h-full w-64 flex-col bg-[#0f0b16] border-r border-white/[0.06] select-none">
      {/* Header Logo */}
      <div className="flex h-16 items-center gap-3 px-5 border-b border-white/[0.06] shrink-0">
        <div className="h-8 w-8 grid place-items-center rounded-lg bg-gradient-to-br from-[#c084fc] to-[#9333ea] text-black shadow-lg shadow-purple-500/20">
          <Image
            src="/image/image.png"
            alt="Logo"
            width={20}
            height={20}
            className="object-contain"
          />
        </div>
        <div className="leading-tight">
          <div className="text-sm font-extrabold tracking-wider text-white">
            AUTO SECURITY
          </div>
          <div className="text-[10px] font-mono tracking-[0.25em] text-purple-400/70">
            AUDITOR
          </div>
        </div>
      </div>

      {/* Navigation Items */}
      <div className="flex-1 px-3 py-6 space-y-6 overflow-y-auto">
        <div className="space-y-1.5">
          <div className="px-3 pb-2 text-[10px] font-mono font-semibold tracking-wider text-white/30 uppercase">
            Main Menu
          </div>
          {renderNavItems(MAIN)}
        </div>

        <div className="space-y-1.5">
          <div className="px-3 pb-2 text-[10px] font-mono font-semibold tracking-wider text-white/30 uppercase">
            Resources
          </div>
          {renderNavItems(RESOURCES)}
        </div>
      </div>

      {/* Author Footer */}
      <div className="p-3 space-y-3">
        <a
          href="https://kasyaf-cv.my.id"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-3 rounded-xl border border-purple-500/20 bg-gradient-to-br from-[#1e1233] to-[#15101f] px-3 py-3 group hover:border-purple-500/40 hover:from-[#261845] hover:to-[#1a142e] transition-all"
        >
          <div className="h-8 w-8 grid place-items-center rounded-full bg-white/[0.06] border border-white/[0.08] group-hover:bg-purple-500/20 transition-colors">
            <UserCircle className="h-4 w-4 text-white/70 group-hover:text-purple-300" />
          </div>
          <div className="flex-1 leading-tight">
            <div className="text-[10px] font-mono tracking-wider text-white/40 uppercase">
              Created By
            </div>
            <div className="text-xs font-semibold text-white group-hover:text-purple-200 flex items-center gap-1">
              Kasyaf - Author
              <ExternalLink className="h-3 w-3 opacity-50 group-hover:opacity-100" />
            </div>
          </div>
        </a>
      </div>

      {/* System Status & Notes */}
      <div className="p-3 pt-0 mt-auto border-t border-white/[0.04] bg-black/20">
        <div className="mt-3 px-2 text-[11px] font-mono leading-relaxed text-slate-400 bg-white/[0.02] p-2.5 rounded-lg border border-white/[0.04]">
          <span className="text-purple-400 font-semibold block mb-0.5">
            Catatan:
          </span>
          Hanya untuk domain milik sendiri / izin tertulis.
        </div>
      </div>
    </aside>
  );
}
