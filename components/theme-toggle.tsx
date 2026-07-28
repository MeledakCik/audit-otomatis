"use client";

import { useEffect, useState } from "react";
import { useTheme } from "next-themes";
import { Moon, Sun } from "lucide-react";
import { cn } from "@/lib/utils";

/**
 * Toggle gelap/terang. Render awal (server + first client paint) selalu
 * anggap dark dulu (samain sama `defaultTheme="dark"` di ThemeProvider)
 * supaya nggak ada hydration mismatch — baru setelah mount, `resolvedTheme`
 * asli dari next-themes (localStorage) dipakai.
 */
export function ThemeToggle({ className }: { className?: string }) {
  const { resolvedTheme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);

  // Pattern standar dari next-themes buat menghindari hydration mismatch:
  // render pertama (server + client sebelum mount) selalu anggap "dark"
  // (samain sama defaultTheme), baru setelah mount pakai resolvedTheme
  // asli. Ini bukan derived-state anti-pattern yang biasa ditangkap rule
  // react-hooks/set-state-in-effect — di sini emang perlu nunggu satu
  // commit ekstra biar konsisten sama apa yang di-render server.
  // eslint-disable-next-line react-hooks/set-state-in-effect
  useEffect(() => setMounted(true), []);

  const isDark = mounted ? resolvedTheme === "dark" : true;

  return (
    <button
      type="button"
      aria-label={isDark ? "Ganti ke mode terang" : "Ganti ke mode gelap"}
      title={isDark ? "Mode terang" : "Mode gelap"}
      onClick={() => setTheme(isDark ? "light" : "dark")}
      className={cn(
        "relative inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-full border border-border-strong text-muted overflow-hidden bg-surface-raised",
        "hover:text-accent hover:border-accent/50 hover:shadow-[0_0_14px_-4px_var(--accent)] transition-all",
        "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/50",
        className
      )}
    >
      <Sun
        className={cn(
          "h-3.5 w-3.5 absolute transition-all duration-300 ease-out",
          isDark ? "opacity-0 -rotate-90 scale-50" : "opacity-100 rotate-0 scale-100"
        )}
      />
      <Moon
        className={cn(
          "h-3.5 w-3.5 absolute transition-all duration-300 ease-out",
          isDark ? "opacity-100 rotate-0 scale-100" : "opacity-0 rotate-90 scale-50"
        )}
      />
    </button>
  );
}
