"use client";

import { useEffect, useId, useState } from "react";
import Link from "next/link";
import { useTheme } from "next-themes";
import { Shield, Sun, Moon, ArrowRight, Menu, X } from "lucide-react";

const LINKS = [
  { href: "#fitur", label: "Fitur" },
  { href: "#keamanan", label: "Keamanan" },
  { href: "#cara-kerja", label: "Cara Kerja" },
  { href: "#author", label: "Tentang" },
];

export function LandingNav() {
  const { resolvedTheme, setTheme } = useTheme();
  const [open, setOpen] = useState(false);
  const menuId = useId();

  // Tutup menu saat ESC ditekan
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [open]);

  // Kunci scroll saat menu mobile terbuka
  useEffect(() => {
    if (!open) return;
    const prev = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      document.body.style.overflow = prev;
    };
  }, [open]);

  return (
    <header
      className="fixed inset-x-0 top-0 z-50 px-3 sm:px-6"
      style={{ paddingTop: "calc(env(safe-area-inset-top, 0px) + 0.5rem)" }}
    >
      <nav
        aria-label="Navigasi utama"
        className="max-w-6xl mx-auto glass-panel rounded-2xl px-3 sm:px-4 py-2 flex items-center justify-between gap-3"
      >
        {/* Brand */}
        <Link
          href="/"
          className="flex items-center gap-2.5 min-w-0"
          onClick={() => setOpen(false)}
        >
          <span className="w-9 h-9 rounded-xl bg-gradient-accent flex items-center justify-center text-white shrink-0">
            <Shield className="w-5 h-5" aria-hidden />
          </span>
          <span className="font-bold tracking-tight text-base truncate">
            Sentinel-ID
          </span>
        </Link>

        {/* Desktop links */}
        <ul className="hidden md:flex items-center gap-1">
          {LINKS.map((l) => (
            <li key={l.href}>
              <a
                href={l.href}
                className="px-3 py-2 rounded-lg text-sm text-soft hover:text-foreground hover:bg-foreground/5 transition-colors"
              >
                {l.label}
              </a>
            </li>
          ))}
        </ul>

        {/* Actions */}
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
            className="p-2.5 rounded-xl border border-border hover:bg-foreground/5 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60"
            aria-label="Ganti tema terang/gelap"
          >
            <Sun className="w-4 h-4 text-amber-400 hidden dark:block" aria-hidden />
            <Moon className="w-4 h-4 text-indigo-600 dark:hidden" aria-hidden />
          </button>

          <Link
            href="/dashboard"
            className="hidden sm:inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold text-white bg-gradient-accent hover:brightness-110 transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60"
          >
            Masuk ke Dashboard <ArrowRight className="w-4 h-4" aria-hidden />
          </Link>

          {/* Mobile toggle */}
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="md:hidden p-2.5 rounded-xl border border-border hover:bg-foreground/5 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60"
            aria-label={open ? "Tutup menu" : "Buka menu"}
            aria-expanded={open}
            aria-controls={menuId}
          >
            {open ? (
              <X className="w-5 h-5" aria-hidden />
            ) : (
              <Menu className="w-5 h-5" aria-hidden />
            )}
          </button>
        </div>
      </nav>

      {/* Mobile menu panel */}
      <div
        id={menuId}
        className={`md:hidden max-w-6xl mx-auto mt-2 glass-panel rounded-2xl overflow-hidden transition-[max-height,opacity] duration-200 ease-out ${
          open ? "max-h-96 opacity-100" : "max-h-0 opacity-0"
        }`}
      >
        <ul className="p-2 flex flex-col">
          {LINKS.map((l) => (
            <li key={l.href}>
              <a
                href={l.href}
                onClick={() => setOpen(false)}
                className="block px-3 py-2.5 rounded-lg text-sm text-soft hover:text-foreground hover:bg-foreground/5 transition-colors"
              >
                {l.label}
              </a>
            </li>
          ))}
          <li className="mt-1 pt-2 border-t border-border/60">
            <Link
              href="/dashboard"
              onClick={() => setOpen(false)}
              className="inline-flex w-full items-center justify-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold text-white bg-gradient-accent hover:brightness-110 transition"
            >
              Masuk ke Dashboard <ArrowRight className="w-4 h-4" aria-hidden />
            </Link>
          </li>
        </ul>
      </div>
    </header>
  );
}