"use client";

import Link from "next/link";
import { useTheme } from "next-themes";
import { Shield, Sun, Moon, ArrowRight } from "lucide-react";

const LINKS = [
  { href: "#fitur", label: "Fitur" },
  { href: "#cara-kerja", label: "Cara Kerja" },
];

export function LandingNav() {
  const { resolvedTheme, setTheme } = useTheme();

  return (
    <header
      className="fixed inset-x-0 top-0 z-50 px-3 sm:px-6"
      style={{ paddingTop: "calc(env(safe-area-inset-top, 0px) + 0.5rem)" }}
    >
      <nav
        aria-label="Navigasi utama"
        className="max-w-6xl mx-auto glass-panel rounded-2xl px-3 sm:px-4 py-2 flex items-center justify-between gap-3"
      >
        <Link href="/" className="flex items-center gap-2.5 min-w-0">
          <span className="w-9 h-9 rounded-xl bg-gradient-accent flex items-center justify-center text-white shrink-0">
            <Shield className="w-5 h-5" />
          </span>
          <span className="font-bold tracking-tight text-base truncate">Sentinel-ID</span>
        </Link>

        <ul className="hidden md:flex items-center gap-1">
          {LINKS.map((l) => (
            <li key={l.href}>
              <a href={l.href} className="px-3 py-2 rounded-lg text-sm text-soft hover:text-foreground hover:bg-foreground/5">
                {l.label}
              </a>
            </li>
          ))}
        </ul>

        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setTheme(resolvedTheme === "dark" ? "light" : "dark")}
            className="p-2.5 rounded-xl border border-border hover:bg-foreground/5"
            aria-label="Ganti tema terang/gelap"
          >
            <Sun className="w-4 h-4 text-amber-400 hidden dark:block" />
            <Moon className="w-4 h-4 text-indigo-600 dark:hidden" />
          </button>
          <Link
            href="/dashboard"
            className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-semibold text-white bg-gradient-accent hover:brightness-110 transition"
          >
            Masuk <ArrowRight className="w-4 h-4" />
          </Link>
        </div>
      </nav>
    </header>
  );
}
