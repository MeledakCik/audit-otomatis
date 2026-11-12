"use client";

import React, { useCallback, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useTheme } from "next-themes";
import { AppSidebar } from "@/components/app-sidebar";
import { Sun, Moon, Shield, Menu, BadgeCheck } from "lucide-react";

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const { resolvedTheme, setTheme } = useTheme();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const closeSidebar = useCallback(() => setSidebarOpen(false), []);

  // Landing page punya navbar sendiri; tidak memakai shell aplikasi
  if (pathname === "/") return <>{children}</>;

  return (
    <div className="relative min-h-dvh overflow-x-clip">
      <header
        className="sticky top-0 z-40 px-3 sm:px-6"
        style={{ paddingTop: "calc(env(safe-area-inset-top, 0px) + 0.5rem)" }}
      >
        <div className="max-w-[1400px] mx-auto glass-panel rounded-2xl px-3 sm:px-4 py-2 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 sm:gap-3 min-w-0">
            <button
              type="button"
              onClick={() => setSidebarOpen(true)}
              className="lg:hidden p-2.5 rounded-xl border border-border hover:bg-foreground/5"
              aria-label="Buka menu"
              aria-expanded={sidebarOpen}
            >
              <Menu className="w-5 h-5" />
            </button>
            <Link href="/" className="flex items-center gap-2.5 min-w-0">
              <span className="w-9 h-9 rounded-xl bg-gradient-accent flex items-center justify-center text-white shrink-0">
                <Shield className="w-5 h-5" />
              </span>
              <span className="font-bold tracking-tight text-base truncate">Sentinel-ID</span>
            </Link>
          </div>

          <div className="flex items-center gap-2">
            <span className="hidden md:inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full text-xs border border-ok/30 bg-ok/10 text-ok font-medium">
              <BadgeCheck className="w-4 h-4" /> GDG Bandung Verified
            </span>
            <button
              type="button"
              onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
              className="px-3 py-2 rounded-xl border border-border text-xs font-medium flex items-center gap-2 hover:bg-foreground/5"
              aria-label="Ganti tema terang/gelap"
            >
              <Sun className="w-4 h-4 text-amber-400 hidden dark:block" />
              <Moon className="w-4 h-4 text-indigo-600 dark:hidden" />
              <span className="hidden sm:inline">Tema</span>
            </button>
          </div>
        </div>
      </header>

      <div className="max-w-[1400px] mx-auto px-3 sm:px-6 pt-4 sm:pt-6 pb-16 flex gap-6 items-start">
        <AppSidebar open={sidebarOpen} onClose={closeSidebar} />
        <main id="main" className="flex-1 min-w-0">{children}</main>
      </div>
    </div>
  );
}
