"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { usePathname } from "next/navigation";
import Link from "next/link";
import { X, Menu, ShieldAlert, Lock } from "lucide-react";
import { AppSidebar } from "./app-sidebar";
import { VerifiedBadge } from "./verified-badge";

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select, textarea, [tabindex]:not([tabindex="-1"])';

export function AppShell({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const pathname = usePathname();
  const triggerRef = useRef<HTMLButtonElement>(null);
  const drawerRef = useRef<HTMLDivElement>(null);

  const isAdminRoute = pathname?.startsWith("/admin");

  const close = useCallback(() => {
    setOpen(false);
    triggerRef.current?.focus();
  }, []);

  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  useEffect(() => {
    if (!open) return;
    const drawer = drawerRef.current;
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    drawer?.querySelector<HTMLElement>(FOCUSABLE)?.focus();

    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        close();
        return;
      }
      if (e.key !== "Tab" || !drawer) return;
      const items = Array.from(drawer.querySelectorAll<HTMLElement>(FOCUSABLE));
      if (items.length === 0) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [open, close]);

  // Dedicated full-screen Command Center layout for /admin/*
  if (isAdminRoute) {
    return (
      <div className="min-h-dvh w-full bg-[#08060e] text-slate-100 flex flex-col">
        <a href="#main-content" className="skip-link">
          Lewati ke konten utama
        </a>
        <main id="main-content" tabIndex={-1} className="flex-1 focus:outline-none">
          {children}
        </main>
      </div>
    );
  }

  return (
    <div className="flex h-dvh w-full overflow-hidden bg-[#090610] text-slate-100">
      <a href="#main-content" className="skip-link">
        Lewati ke konten utama
      </a>

      <aside className="hidden lg:flex w-64 shrink-0 flex-col border-r border-white/[0.07] bg-[#0d0916]">
        <AppSidebar />
      </aside>

      {open && (
        <div className="fixed inset-0 z-50 flex lg:hidden">
          <div
            ref={drawerRef}
            role="dialog"
            aria-modal="true"
            aria-label="Menu navigasi"
            className="relative flex w-64 max-w-[85vw] flex-col bg-[#0d0916] border-r border-white/[0.08] shadow-2xl"
          >
            <AppSidebar />
            <button
              type="button"
              onClick={close}
              aria-label="Tutup menu"
              className="absolute right-3 top-3 h-9 w-9 grid place-items-center rounded-full bg-white/10 text-white hover:bg-white/20 transition-colors"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
          <div
            className="flex-1 bg-black/65 backdrop-blur-xs"
            aria-hidden="true"
            onClick={close}
          />
        </div>
      )}

      <div className="flex flex-1 flex-col min-w-0 overflow-hidden">
        {/* Top bar for both mobile and desktop */}
        <header className="flex h-14 items-center justify-between gap-3 px-4 lg:px-6 border-b border-white/[0.07] bg-[#0d0916]/90 backdrop-blur-md shrink-0">
          <div className="flex items-center gap-3 min-w-0">
            <button
              ref={triggerRef}
              type="button"
              onClick={() => setOpen(true)}
              aria-label="Buka menu navigasi"
              aria-expanded={open}
              className="lg:hidden h-9 w-9 grid place-items-center rounded-xl border border-white/10 text-white/80 hover:text-white hover:bg-white/[0.06] transition-colors shrink-0"
            >
              <Menu className="h-5 w-5" aria-hidden="true" />
            </button>

            <div className="flex items-center gap-2 min-w-0">
              <span className="inline-flex h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_8px_#34d399] shrink-0" />
              <span className="font-mono text-xs font-bold tracking-wider text-white truncate">
                SENTINEL-ID PASSIVE AUDITOR
              </span>
              <span className="hidden xl:inline-flex items-center gap-1 rounded-md bg-white/[0.04] border border-white/[0.08] px-2 py-0.5 text-[10px] font-mono text-slate-400">
                <Lock className="h-2.5 w-2.5 text-purple-400" />
                GET-ONLY · ZERO-EXPLOIT
              </span>
            </div>
          </div>

          <div className="flex items-center gap-2.5 shrink-0">
            <VerifiedBadge variant="header" />
            <Link
              href="/admin"
              className="hidden sm:inline-flex items-center gap-1.5 rounded-full border border-purple-500/30 bg-purple-500/10 hover:bg-purple-500/20 px-3 py-1 text-xs font-mono font-semibold text-purple-200 transition-colors"
            >
              <ShieldAlert className="h-3.5 w-3.5 text-purple-400" />
              <span>Admin</span>
            </Link>
          </div>
        </header>

        <main
          id="main-content"
          tabIndex={-1}
          className="flex-1 overflow-y-auto bg-[#090610] focus:outline-none thin-scroll"
        >
          {children}
        </main>
      </div>
    </div>
  );
}
