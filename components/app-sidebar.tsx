"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutGrid,
  ClipboardCheck,
  History,
  BookOpen,
  Code2,
  ShieldCheck,
} from "lucide-react";
import { cn } from "@/lib/utils";

const MAIN = [
  { label: "Overview", icon: LayoutGrid, href: "/" },
  { label: "QC Otomatis", icon: ClipboardCheck, href: "/qc" },
  { label: "Scan History", icon: History, href: "/history" },
];

const RESOURCES = [
  { label: "Documentation", icon: BookOpen, href: "/docs" },
  { label: "API Reference", icon: Code2, href: "/api-docs" },
];

export function AppSidebar() {
  const pathname = usePathname();

  return (
    <aside className="flex h-full w-64 flex-col bg-[#0f0b16] border-r border-white/[0.06] select-none">
      <div className="flex h-16 items-center gap-3 px-5 border-b border-white/[0.06] shrink-0">
        <div className="h-8 w-8 grid place-items-center rounded-lg bg-gradient-to-br from-[#c084fc] to-[#9333ea] text-black shadow-lg shadow-purple-500/20">
          <ShieldCheck className="h-5 w-5 text-black" />
        </div>
        <div className="leading-tight">
          <div className="text-sm font-extrabold tracking-wider text-white">
            AUTO-SEC
          </div>
          <div className="text-[10px] font-mono tracking-[0.25em] text-purple-400/70">
            AUDITOR
          </div>
        </div>
      </div>

      <div className="flex-1 px-3 py-6 space-y-6 overflow-y-auto">
        <div className="space-y-1.5">
          <div className="px-3 pb-2 text-[11px] font-mono font-semibold tracking-wider text-white/30 uppercase">
            Main Menu
          </div>
          {MAIN.map((i) => {
            const active = pathname === i.href;
            return (
              <Link
                key={i.label}
                href={i.href}
                className={cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2.5 text-xs font-mono transition-all group",
                  active
                    ? "bg-[#2a1842] text-white shadow-[inset_0_1px_0_0_rgba(255,255,255,0.1)] border border-purple-500/20"
                    : "text-white/50 hover:text-white hover:bg-white/[0.04]",
                )}
              >
                <i.icon
                  className={cn(
                    "h-4 w-4 transition-colors",
                    active
                      ? "text-[#c084fc]"
                      : "text-white/40 group-hover:text-white/70",
                  )}
                />
                <span className="font-medium">{i.label}</span>
              </Link>
            );
          })}
        </div>

        <div className="space-y-1.5">
          <div className="px-3 pb-2 text-[11px] font-mono font-semibold tracking-wider text-white/30 uppercase">
            Resources
          </div>
          {RESOURCES.map((i) => {
            const active = pathname === i.href;
            return (
              <Link
                key={i.label}
                href={i.href}
                className={cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2.5 text-xs font-mono transition-all group",
                  active
                    ? "bg-[#2a1842] text-white shadow-[inset_0_1px_0_0_rgba(255,255,255,0.1)] border border-purple-500/20"
                    : "text-white/50 hover:text-white hover:bg-white/[0.04]",
                )}
              >
                <i.icon
                  className={cn(
                    "h-4 w-4 transition-colors",
                    active
                      ? "text-[#c084fc]"
                      : "text-white/40 group-hover:text-white/70",
                  )}
                />
                <span className="font-medium">{i.label}</span>
              </Link>
            );
          })}
        </div>
      </div>

      <div className="p-3 mt-auto border-t border-white/[0.04] bg-black/20">
        <div className="rounded-xl border border-white/[0.06] bg-white/[0.02] p-3 space-y-2.5">
          <div className="text-[10px] font-mono tracking-wider text-white/30 uppercase">
            System Status
          </div>
          <div className="flex items-center gap-2 text-xs text-white/70 font-medium">
            <span className="h-2 w-2 rounded-full bg-emerald-500 shadow-[0_0_8px_0_#22c55e] animate-pulse" />
            All systems operational
          </div>
          <div className="text-[11px] font-mono text-white/40 pt-1 border-t border-white/[0.04]">
            API: <span className="text-emerald-400">23ms</span> latency
          </div>
        </div>

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
