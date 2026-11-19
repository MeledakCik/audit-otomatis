"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { Activity, ArrowUpRight, FlaskConical, KeyRound, Lock, LogOut } from "lucide-react";
import { cn } from "@/lib/utils";

const items = [
  { href: "/admin/test", label: "Uji Domain", icon: FlaskConical },
  { href: "/admin/activities", label: "Aktivitas", icon: Activity },
  { href: "/admin/vault", label: "Vault", icon: Lock },
  { href: "/admin/requests", label: "Klaim", icon: KeyRound },
];

export function AdminNav() {
  const path = usePathname();
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(false);

  async function logout() {
    setBusy(true);
    setError(false);
    try {
      const response = await fetch("/api/admin/logout", { method: "POST" });
      if (!response.ok && response.status !== 401) throw new Error();
      window.location.replace("/admin/login");
    } catch {
      setBusy(false);
      setError(true);
    }
  }

  return (
    <header className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-2 border-b border-border pb-3">
        <nav aria-label="Menu admin" className="grid w-full grid-cols-4 gap-1 sm:flex sm:w-auto sm:flex-wrap">
          {items.map(({ href, label, icon: Icon }) => (
            <Link
              key={href}
              href={href}
              aria-current={path === href ? "page" : undefined}
              className={cn(
                "inline-flex min-h-10 items-center justify-center gap-1.5 rounded-xl px-1 text-xs font-medium transition-colors sm:px-3 sm:text-sm",
                path === href ? "bg-accent/10 text-accent" : "text-muted hover:bg-foreground/5 hover:text-foreground"
              )}
            >
              <Icon aria-hidden className="hidden size-4 shrink-0 sm:block" />
              {label}
            </Link>
          ))}
        </nav>
        <div className="flex items-center gap-2 text-sm text-muted">
          <Link href="/dashboard" className="inline-flex min-h-10 items-center gap-1.5 rounded-xl px-2.5 hover:bg-foreground/5 hover:text-foreground">
            Dasbor pengguna <ArrowUpRight aria-hidden className="size-4" />
          </Link>
          <button
            type="button"
            onClick={logout}
            disabled={busy}
            className="inline-flex min-h-10 items-center gap-1.5 rounded-xl px-2.5 hover:bg-foreground/5 hover:text-foreground disabled:opacity-50"
          >
            <LogOut aria-hidden className="size-4" /> {busy ? "Keluar…" : "Keluar"}
          </button>
        </div>
      </div>
      {error && <p role="alert" className="text-sm text-danger">Gagal keluar. Coba lagi.</p>}
    </header>
  );
}
