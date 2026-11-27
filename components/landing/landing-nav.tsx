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
      className="fixed inset-x-0 top-0 z-50 px-4 sm:px-6 lg:px-8 border-b border-border bg-background/85 backdrop-blur supports-[backdrop-filter]:bg-background/70"
      style={{ paddingTop: "env(safe-area-inset-top, 0px)" }}
    >
      <nav
        aria-label="Navigasi utama"
        className="max-w-6xl mx-auto h-14 flex items-center justify-between gap-3"
      >
        {/* Brand */}
        <Link
          href="/"
          className="flex items-center gap-2.5 min-w-0"
          onClick={() => setOpen(false)}
        >
          <span className="w-8 h-8 rounded-lg bg-accent flex items-center justify-center text-accent-fg shrink-0">
            <Shield className="w-4 h-4" aria-hidden />
          </span>
          <span className="font-semibold tracking-tight text-[15px] truncate">
            Sentinel-ID
          </span>
        </Link>

        {/* Desktop links */}
        <ul className="hidden md:flex items-center gap-1">
          {LINKS.map((l) => (
            <li key={l.href}>
              <a
                href={l.href}
                className="px-3 py-2 rounded-lg text-sm text-muted hover:text-foreground transition-colors"
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
            className="p-2 rounded-lg text-muted hover:text-foreground hover:bg-foreground/5 transition-colors"
            aria-label="Ganti tema terang/gelap"
          >
            <Sun className="w-4 h-4 hidden dark:block" aria-hidden />
            <Moon className="w-4 h-4 dark:hidden" aria-hidden />
          </button>

          <Link
            href="/dashboard"
            className="hidden sm:inline-flex items-center gap-1.5 h-9 px-3.5 rounded-lg text-sm font-medium bg-accent text-accent-fg hover:bg-accent-dim transition-colors"
          >
            Dashboard <ArrowRight className="w-4 h-4" aria-hidden />
          </Link>

          {/* Mobile toggle */}
          <button
            type="button"
            onClick={() => setOpen((v) => !v)}
            className="md:hidden p-2 rounded-lg text-muted hover:text-foreground hover:bg-foreground/5 transition-colors"
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
        className={`md:hidden border-t border-border overflow-hidden transition-[max-height,opacity] duration-200 ease-out ${
          open ? "max-h-96 opacity-100" : "max-h-0 opacity-0"
        }`}
      >
        <ul className="max-w-6xl mx-auto py-3 flex flex-col">
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
          <li className="mt-2 pt-3 border-t border-border">
            <Link
              href="/dashboard"
              onClick={() => setOpen(false)}
              className="inline-flex w-full items-center justify-center gap-2 h-10 rounded-lg text-sm font-medium bg-accent text-accent-fg hover:bg-accent-dim transition-colors"
            >
              Masuk ke Dashboard <ArrowRight className="w-4 h-4" aria-hidden />
            </Link>
          </li>
        </ul>
      </div>
    </header>
  );
}