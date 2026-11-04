"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { usePathname } from "next/navigation";
import { X, Menu } from "lucide-react";
import { AppSidebar } from "./app-sidebar";

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select, textarea, [tabindex]:not([tabindex="-1"])';

export function AppShell({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);
  const pathname = usePathname();
  const triggerRef = useRef<HTMLButtonElement>(null);
  const drawerRef = useRef<HTMLDivElement>(null);

  const close = useCallback(() => {
    setOpen(false);
    triggerRef.current?.focus();
  }, []);

  // Close the drawer after navigation.
  useEffect(() => {
    setOpen(false);
  }, [pathname]);

  // Esc to close, Tab focus trap, body scroll lock, initial focus.
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

  return (
    <div className="flex h-dvh w-full overflow-hidden bg-[#0a0710] text-slate-100">
      <a href="#main-content" className="skip-link">
        Lewati ke konten utama
      </a>

      <aside className="hidden lg:flex w-64 shrink-0 flex-col border-r border-white/[0.06] bg-[#0f0b16]">
        <AppSidebar />
      </aside>

      {open && (
        <div className="fixed inset-0 z-50 flex lg:hidden">
          <div
            ref={drawerRef}
            role="dialog"
            aria-modal="true"
            aria-label="Menu navigasi"
            className="relative flex w-64 max-w-[85vw] flex-col bg-[#0f0b16] border-r border-white/[0.06] shadow-2xl"
          >
            <AppSidebar />
            <button
              type="button"
              onClick={close}
              aria-label="Tutup menu"
              className="absolute right-3 top-3 h-10 w-10 grid place-items-center rounded-full bg-white/10 text-white hover:bg-white/20 transition-colors"
            >
              <X className="h-4 w-4" aria-hidden="true" />
            </button>
          </div>
          <div
            className="flex-1 bg-black/60"
            aria-hidden="true"
            onClick={close}
          />
        </div>
      )}

      <div className="flex flex-1 flex-col min-w-0 overflow-hidden">
        <header className="flex lg:hidden h-14 items-center px-4 border-b border-white/[0.06] bg-[#0f0b16] shrink-0">
          <button
            ref={triggerRef}
            type="button"
            onClick={() => setOpen(true)}
            aria-label="Buka menu navigasi"
            aria-expanded={open}
            className="h-10 w-10 grid place-items-center rounded-lg text-white/80 hover:text-white hover:bg-white/[0.06] transition-colors"
          >
            <Menu className="h-5 w-5" aria-hidden="true" />
          </button>
          <span className="ml-3 font-mono text-sm font-bold tracking-widest text-white">
            AUTO SECURITY AUDITOR
          </span>
        </header>
        <main
          id="main-content"
          tabIndex={-1}
          className="flex-1 overflow-y-auto bg-[#0a0710] focus:outline-none"
        >
          {children}
        </main>
      </div>
    </div>
  );
}
