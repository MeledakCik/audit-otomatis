"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { Activity, Lock, KeyRound, LogOut, ArrowUpRight, ShieldAlert } from "lucide-react";
import { VerifiedBadge } from "@/components/verified-badge";
import { cn } from "@/lib/utils";

export function AdminNav() {
  const path = usePathname();
  const router = useRouter();

  const navItems = [
    {
      href: "/admin/activities",
      label: "Aktivitas & Data User",
      icon: Activity,
    },
    {
      href: "/admin/vault",
      label: "Encrypted Vault",
      icon: Lock,
    },
    {
      href: "/admin/requests",
      label: "Klaim Domain (ACC)",
      icon: KeyRound,
    },
  ];

  async function logout() {
    await fetch("/api/admin/logout", { method: "POST" });
    router.replace("/admin/login");
    router.refresh();
  }

  return (
    <header className="mb-8 space-y-4">
      {/* Top Command Bar */}
      <div className="flex flex-wrap items-center justify-between gap-4 rounded-2xl border border-purple-500/25 bg-gradient-to-r from-[#150f24] via-[#110c1d] to-[#0d0917] px-5 py-4 shadow-xl">
        <div className="flex items-center gap-3.5">
          <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-purple-600 to-pink-600 grid place-items-center text-white shadow-lg shadow-purple-600/25">
            <ShieldAlert className="h-5 w-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-base font-extrabold tracking-wide text-white">
                SENTINEL-ID ADMIN CONSOLE
              </span>
              <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 border border-emerald-500/30 px-2 py-0.5 text-[10px] font-mono text-emerald-300">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                TELEMETRY LIVE
              </span>
            </div>
            <p className="text-xs font-mono text-slate-400">
              Pusat Monitoring Aktivitas User · Brankas AES-256-GCM · Verifikasi Kepemilikan Domain
            </p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-2.5">
          <VerifiedBadge variant="admin" />
          <Link
            href="/"
            className="inline-flex items-center gap-1.5 rounded-xl border border-white/10 bg-white/[0.04] hover:bg-white/[0.08] px-3.5 py-1.5 text-xs font-mono text-slate-200 transition-colors"
          >
            <span>Lihat User Scanner</span>
            <ArrowUpRight className="h-3.5 w-3.5" />
          </Link>
          <button
            type="button"
            onClick={logout}
            className="inline-flex items-center gap-1.5 rounded-xl border border-red-500/30 bg-red-500/10 hover:bg-red-500/20 px-3.5 py-1.5 text-xs font-mono font-semibold text-red-300 transition-colors cursor-pointer"
          >
            <LogOut className="h-3.5 w-3.5" />
            <span>Logout</span>
          </button>
        </div>
      </div>

      {/* Navigation Tabs */}
      <nav aria-label="Menu Admin" className="flex flex-wrap items-center gap-2">
        {navItems.map((item) => {
          const active = path?.startsWith(item.href);
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "inline-flex items-center gap-2 rounded-xl px-4 py-2.5 text-xs font-mono font-bold transition-all",
                active
                  ? "bg-gradient-to-r from-purple-600 to-pink-600 text-white shadow-lg shadow-purple-600/25"
                  : "border border-white/10 bg-[#120d1d] text-slate-300 hover:text-white hover:border-purple-500/40"
              )}
            >
              <Icon className="h-4 w-4" />
              <span>{item.label}</span>
            </Link>
          );
        })}
      </nav>
    </header>
  );
}
