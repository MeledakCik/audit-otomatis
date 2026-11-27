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

  const isAdmin = pathname === "/admin" || pathname?.startsWith("/admin/");

  return (
    <div className="relative min-h-dvh overflow-x-clip">
      <header
        className="sticky top-0 z-40 border-b border-border bg-background/85 backdrop-blur supports-[backdrop-filter]:bg-background/70"
        style={{ paddingTop: "env(safe-area-inset-top, 0px)" }}
      >
        <div className="max-w-[1440px] mx-auto h-14 px-4 sm:px-6 lg:px-8 flex items-center justify-between gap-3">
          <div className="flex items-center gap-2 sm:gap-3 min-w-0">
            {!isAdmin && (
              <button
                type="button"
                onClick={() => setSidebarOpen(true)}
                className="lg:hidden -ml-1.5 p-2 rounded-lg text-muted hover:text-foreground hover:bg-foreground/5"
                aria-label="Buka menu"
                aria-expanded={sidebarOpen}
              >
                <Menu className="w-5 h-5" />
              </button>
            )}
            <Link href={isAdmin ? "/admin" : "/"} className="flex items-center gap-2.5 min-w-0">
              <span className="w-8 h-8 rounded-lg bg-accent flex items-center justify-center text-accent-fg shrink-0">
                <Shield className="w-4 h-4" />
              </span>
              <span className="font-semibold tracking-tight text-[15px] truncate">Sentinel-ID</span>
            </Link>
            {isAdmin && <span className="text-xs text-muted border-l border-border pl-3">Admin</span>}
          </div>

          <div className="flex items-center gap-2">
            {!isAdmin && (
              <span className="hidden md:inline-flex items-center gap-1.5 text-xs text-muted">
                <BadgeCheck className="w-4 h-4 text-ok" /> GDG Bandung Verified
              </span>
            )}
            <button
              type="button"
              onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
              className="p-2 rounded-lg text-muted hover:text-foreground hover:bg-foreground/5"
              aria-label="Ganti tema terang/gelap"
            >
              <Sun className="w-4 h-4 hidden dark:block" />
              <Moon className="w-4 h-4 dark:hidden" />
            </button>
          </div>
        </div>
      </header>

      <div className="max-w-[1440px] mx-auto px-4 sm:px-6 lg:px-8 pt-6 sm:pt-8 pb-20 flex gap-8 items-start">
        {!isAdmin && <AppSidebar open={sidebarOpen} onClose={closeSidebar} />}
        <main id="main" className="flex-1 min-w-0">{children}</main>
      </div>
    </div>
  );
}
