"use client";

import React, { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Shield, Search, TrendingUp, Lock, ClipboardCheck, Clock, Terminal,
  ShieldAlert, KeyRound, AlertTriangle, FileCode2, Award, Wrench,
  Network, Globe, Radio, Layers, Eye, UserCheck, ShieldCheck,
  BookOpen, Code2, Settings, ChevronRight, ChevronDown, AtSign,
  PanelLeftClose, PanelLeftOpen, X,
} from "lucide-react";
import { SENTINEL_NAV_ITEMS, type NavModuleItem } from "@/lib/nav-items";
import { AUTHOR } from "@/lib/author";

export { SENTINEL_NAV_ITEMS };
export type { NavModuleItem };

const ICONS: Record<string, React.ComponentType<{ className?: string }>> = {
  shield: Shield, trending: TrendingUp, lock: Lock, clipboard: ClipboardCheck,
  clock: Clock, terminal: Terminal, "shield-alert": ShieldAlert, key: KeyRound,
  alert: AlertTriangle, "file-code": FileCode2, award: Award, wrench: Wrench,
  network: Network, globe: Globe, radio: Radio, layers: Layers, eye: Eye,
  "user-check": UserCheck, "shield-check": ShieldCheck, book: BookOpen,
  code: Code2, settings: Settings,
};

export function ModuleIcon({ name, className = "w-4 h-4" }: { name: string; className?: string }) {
  const Icon = ICONS[name] ?? Shield;
  return <Icon className={className} />;
}

const CATEGORIES: NavModuleItem["category"][] = [
  "Core Audit & Scan",
  "Vulnerability & Code",
  "Recon & Threat Intel",
  "Resources & Admin",
];

function isActive(pathname: string, route: string) {
  if (route === "/") return pathname === "/";
  return pathname === route || pathname.startsWith(route + "/");
}

export function AppSidebar({
  open = false,
  onClose,
}: {
  open?: boolean;
  onClose?: () => void;
} = {}) {
  const pathname = usePathname() ?? "/";
  const [collapsed, setCollapsed] = useState(false);
  const [q, setQ] = useState("");
  const [openCats, setOpenCats] = useState<Record<string, boolean>>(
    Object.fromEntries(CATEGORIES.map((c) => [c, true]))
  );

  // Drawer mobile: tutup saat pindah halaman, Esc, dan kunci scroll body
  useEffect(() => { onClose?.(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [pathname]);
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose?.();
    document.addEventListener("keydown", onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.removeEventListener("keydown", onKey);
      document.body.style.overflow = prev;
    };
  }, [open, onClose]);

  const filtered = useMemo(() => {
    const s = q.trim().toLowerCase();
    if (!s) return SENTINEL_NAV_ITEMS;
    return SENTINEL_NAV_ITEMS.filter(
      (i) =>
        i.title.toLowerCase().includes(s) ||
        i.route.toLowerCase().includes(s) ||
        i.badge?.toLowerCase().includes(s)
    );
  }, [q]);

  function render(isDrawer: boolean) {
    const slim = collapsed && !isDrawer;
    return (
      <aside
        aria-label="Navigasi modul"
        className={`glass-panel flex flex-col h-full rounded-3xl transition-[width] duration-200 ${
          slim ? "w-[72px] p-2.5" : "w-64 max-w-[85vw] p-3.5"
        }`}
      >
        <div className="flex items-center gap-2 pb-3 border-b border-border">
          {!slim && (
            <label className="glass-pill flex-1 flex items-center gap-2 px-3 py-2 rounded-xl">
              <Search className="w-4 h-4 text-accent shrink-0" aria-hidden />
              <input
                type="search"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                placeholder="Cari modul…"
                aria-label="Cari modul"
                className="w-full bg-transparent text-sm focus:outline-none placeholder:text-muted-dim"
              />
            </label>
          )}
          {!isDrawer && (
            <button
              type="button"
              onClick={() => setCollapsed((v) => !v)}
              className={`glass-pill p-2 rounded-xl hover:bg-foreground/5 ${slim ? "mx-auto" : "shrink-0"}`}
              aria-label={slim ? "Perluas sidebar" : "Ciutkan sidebar"}
            >
              {slim ? <PanelLeftOpen className="w-4 h-4" /> : <PanelLeftClose className="w-4 h-4" />}
            </button>
          )}
          {isDrawer && (
            <button
              type="button"
              onClick={onClose}
              className="glass-pill p-2 rounded-xl shrink-0"
              aria-label="Tutup menu"
            >
              <X className="w-4 h-4" />
            </button>
          )}
        </div>

        <nav className="flex-1 overflow-y-auto thin-scroll py-3 space-y-3 pr-0.5">
          {CATEGORIES.map((cat) => {
            const items = filtered.filter((i) => i.category === cat);
            if (!items.length) return null;
            const expanded = openCats[cat] ?? true;
            return (
              <div key={cat} className="space-y-1">
                {!slim && (
                  <button
                    type="button"
                    onClick={() => setOpenCats((p) => ({ ...p, [cat]: !expanded }))}
                    aria-expanded={expanded}
                    className="w-full flex items-center justify-between px-2 py-1 text-xs font-mono uppercase tracking-wider text-muted-dim hover:text-foreground"
                  >
                    <span>{cat}</span>
                    {expanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                  </button>
                )}
                {(expanded || slim || q) && (
                  <ul className="space-y-1">
                    {items.map((item) => {
                      const active = isActive(pathname, item.route);
                      return (
                        <li key={item.id}>
                          <Link
                            href={item.route}
                            title={slim ? item.title : undefined}
                            aria-current={active ? "page" : undefined}
                            className={`flex items-center justify-between gap-2 rounded-xl border transition-colors ${
                              slim ? "p-2.5 justify-center" : "px-2.5 py-2"
                            } ${
                              active
                                ? "bg-accent/10 border-accent/40 text-foreground font-semibold"
                                : "border-transparent text-soft hover:bg-foreground/5 hover:text-foreground"
                            }`}
                          >
                            <span className="flex items-center gap-2.5 min-w-0">
                              <ModuleIcon
                                name={item.iconName}
                                className={`w-4 h-4 shrink-0 ${active ? "text-accent" : "text-muted"}`}
                              />
                              {!slim && <span className="text-sm truncate">{item.title}</span>}
                            </span>
                          </Link>
                        </li>
                      );
                    })}
                  </ul>
                )}
              </div>
            );
          })}
          {!filtered.length && !slim && (
            <p className="px-2 text-sm text-muted">Tidak ada modul yang cocok.</p>
          )}
        </nav>

        {!slim && (
          <div className="pt-2.5 border-t border-border">
            <div className="glass-pill rounded-2xl p-3 space-y-2.5 min-w-0">
              <div className="flex items-center gap-2.5 min-w-0">
                <div className="w-8 h-8 rounded-full bg-gradient-accent flex items-center justify-center text-white text-xs font-bold shrink-0">K</div>
                <div className="min-w-0">
                  <div className="text-xs text-muted-dim">Author</div>
                  <div className="text-sm font-bold truncate">{AUTHOR.name}</div>
                </div>
              </div>
              <div className="flex flex-col gap-1 text-sm">
                <a href={AUTHOR.websiteUrl} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 text-soft hover:text-accent truncate">
                  <Globe className="w-4 h-4 shrink-0" aria-hidden /> {AUTHOR.website}
                </a>
                <a href={AUTHOR.instagramUrl} target="_blank" rel="noopener noreferrer" className="flex items-center gap-2 text-soft hover:text-accent truncate">
                  <AtSign className="w-4 h-4 shrink-0" aria-hidden /> {AUTHOR.instagramHandle}
                </a>
              </div>
            </div>
          </div>
        )}
      </aside>
    );
  }

  return (
    <>
      <div className="hidden lg:block h-[calc(100dvh-6rem)] sticky top-20 shrink-0">{render(false)}</div>
      {open && (
        <div className="fixed inset-0 z-50 lg:hidden flex" role="dialog" aria-modal="true" aria-label="Menu navigasi">
          <div className="fixed inset-0 bg-black/55 animate-fade-in" onClick={onClose} />
          <div
            className="relative z-10 h-dvh p-3 animate-fade-in"
            style={{ paddingTop: "calc(env(safe-area-inset-top, 0px) + 0.75rem)", paddingBottom: "calc(env(safe-area-inset-bottom, 0px) + 0.75rem)" }}
          >
            {render(true)}
          </div>
        </div>
      )}
    </>
  );
}
export default AppSidebar;
