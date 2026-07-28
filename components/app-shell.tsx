"use client";

import { useState } from "react";
import { X, Menu } from "lucide-react";
import { AppSidebar } from "./app-sidebar";

export function AppShell({ children }: { children: React.ReactNode }) {
  const [open, setOpen] = useState(false);

  return (
    <div className="flex h-dvh w-full overflow-hidden bg-[#0a0710] text-slate-100">
      <aside className="hidden lg:flex w-64 shrink-0 flex-col border-r border-white/[0.06] bg-[#0f0b16]">
        <AppSidebar />
      </aside>

      {open && (
        <div className="fixed inset-0 z-50 flex lg:hidden">
          <div className="relative flex w-64 flex-col bg-[#0f0b16] border-r border-white/[0.06] shadow-2xl">
            <AppSidebar />
            <button
              onClick={() => setOpen(false)}
              className="absolute right-3 top-3 h-8 w-8 grid place-items-center rounded-full bg-white/10 text-white hover:bg-white/20 transition-colors"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
          <div
            className="flex-1 bg-black/60 backdrop-blur-sm"
            onClick={() => setOpen(false)}
          />
        </div>
      )}

      <div className="flex flex-1 flex-col min-w-0 overflow-hidden">
        <header className="flex lg:hidden h-14 items-center px-4 border-b border-white/[0.06] bg-[#0f0b16] shrink-0">
          <button
            onClick={() => setOpen(true)}
            className="p-2 rounded-lg text-white/70 hover:text-white hover:bg-white/[0.06] transition-colors"
          >
            <Menu className="h-5 w-5" />
          </button>
          <span className="ml-3 font-mono text-sm font-bold tracking-widest text-white">
            AUTO-SEC AUDITOR
          </span>
        </header>
        <main className="flex-1 overflow-y-auto bg-[#0a0710]">{children}</main>
      </div>
    </div>
  );
}
