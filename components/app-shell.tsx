"use client";

import React, { useState } from "react";
import { useTheme } from "next-themes";
import { AppSidebar } from "@/components/app-sidebar";
import { Sun, Moon, Shield, Menu, Sparkles } from "lucide-react";

export function AppShell({ children }: { children: React.ReactNode }) {
  const { resolvedTheme, setTheme } = useTheme();
  const [sidebarOpen, setSidebarOpen] = useState(false);

  return (
    <div className="relative min-h-screen overflow-x-hidden">
      <header className="sticky top-3 z-40 px-4 sm:px-6">
        <div className="max-w-7xl mx-auto glass-panel rounded-2xl px-4 py-2.5 flex items-center justify-between gap-3">
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setSidebarOpen(!sidebarOpen)}
              className="lg:hidden p-2 rounded-xl border border-[var(--border)]"
              aria-label="Toggle Menu"
            >
              <Menu className="w-4 h-4" />
            </button>
            <div className="flex items-center gap-2.5">
              <div className="w-8 h-8 rounded-xl bg-gradient-to-br from-pink-500 to-purple-600 flex items-center justify-center text-white">
                <Shield className="w-4 h-4" />
              </div>
              <span className="font-bold tracking-tight text-sm sm:text-base">Sentinel-ID</span>
            </div>
          </div>

          <div className="flex items-center gap-2">
            <span className="hidden md:inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs border border-emerald-500/30 bg-emerald-500/10 text-emerald-500">
              <Sparkles className="w-3.5 h-3.5" /> GDG Bandung Verified
            </span>
            <button
              type="button"
              onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
              className="px-3 py-1.5 rounded-xl border border-[var(--border)] text-xs font-medium flex items-center gap-1.5"
            >
              {resolvedTheme === "dark" ? <Sun className="w-3.5 h-3.5 text-amber-400" /> : <Moon className="w-3.5 h-3.5 text-indigo-600" />}
              <span>{resolvedTheme === "dark" ? "Light Glass" : "Dark Glass"}</span>
            </button>
          </div>
        </div>
      </header>

      <div className="max-w-7xl mx-auto px-4 sm:px-6 pt-6 pb-16 flex gap-6">
        <AppSidebar open={sidebarOpen} onClose={() => setSidebarOpen(false)} />
        <main className="flex-1 min-w-0">{children}</main>
      </div>
    </div>
  );
}
