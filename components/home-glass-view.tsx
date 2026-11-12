"use client";

import React, { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Search, ArrowRight, Loader2, AlertCircle } from "lucide-react";
import { SENTINEL_NAV_ITEMS } from "@/lib/nav-items";
import { ModuleIcon } from "@/components/app-sidebar";

const BADGE_TONE: Record<string, string> = {
  pink: "bg-accent/10 text-accent",
  emerald: "bg-ok/10 text-ok",
  purple: "bg-accent-2/10 text-accent-2",
  cyan: "bg-sev-low/10 text-sev-low",
  amber: "bg-warn/10 text-warn",
  rose: "bg-danger/10 text-danger",
};

const STATS = [
  { val: "50", label: "URL crawl" },
  { val: "100", label: "request maks" },
  { val: "8", label: "engine runtime" },
  { val: "AES-256", label: "brankas bukti" },
];

function Chip({ active, onClick, children }: { active: boolean; onClick: () => void; children: React.ReactNode }) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={active}
      className={`shrink-0 snap-start px-3.5 py-2 rounded-xl text-sm font-medium transition-colors ${
        active ? "bg-gradient-accent text-white" : "text-muted hover:text-foreground hover:bg-foreground/5"
      }`}
    >
      {children}
    </button>
  );
}

export function HomePage() {
  const router = useRouter();
  const [domain, setDomain] = useState("");
  const [consent, setConsent] = useState(false);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [category, setCategory] = useState("Semua");

  const categories = useMemo(
    () => ["Semua", ...Array.from(new Set(SENTINEL_NAV_ITEMS.map((m) => m.category)))],
    []
  );
  const modules = useMemo(
    () => (category === "Semua" ? SENTINEL_NAV_ITEMS : SENTINEL_NAV_ITEMS.filter((m) => m.category === category)),
    [category]
  );

  async function handleRunScan(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    if (!domain.trim()) return setError("Masukkan domain atau URL target.");
    if (!consent) return setError("Centang konfirmasi izin sebelum memulai.");
    setPending(true);
    try {
      const res = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: domain.trim(), permission: true }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok || !data.ok || !data.scanId) {
        setError(data.error ?? "Gagal memulai pemindaian. Coba lagi.");
        setPending(false);
        return;
      }
      const host = data.domain || domain.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
      router.push(`/scan/${data.scanId}?domain=${encodeURIComponent(host)}`);
    } catch {
      setError("Gagal terhubung ke server. Periksa koneksi Anda.");
      setPending(false);
    }
  }

  return (
    <div className="space-y-6 sm:space-y-8">
      {/* Scan */}
      <section className="glass-panel rounded-3xl p-5 sm:p-8 space-y-6">
        <div className="space-y-2">
          <h1 className="text-2xl sm:text-4xl font-extrabold tracking-tight text-balance">
            Audit domain Anda <span className="text-gradient-accent">secara pasif</span>
          </h1>
          <p className="text-base text-muted">GET-only · tanpa payload · tanpa login</p>
        </div>

        <form onSubmit={handleRunScan} className="space-y-3" noValidate>
          <div className="flex flex-col sm:flex-row gap-2.5">
            <label className="flex-1 flex items-center gap-2.5 px-3.5 rounded-xl bg-foreground/[0.04] border border-border focus-within:border-accent transition-colors">
              <Search className="w-4 h-4 text-accent shrink-0" aria-hidden />
              <span className="sr-only">Domain target</span>
              <input
                type="text"
                inputMode="url"
                autoCapitalize="none"
                autoCorrect="off"
                spellCheck={false}
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                placeholder="contoh: sentinel-id.net"
                className="w-full bg-transparent py-3.5 text-base font-mono focus:outline-none placeholder:text-muted-dim"
              />
            </label>
            <button
              type="submit"
              disabled={pending}
              className="px-6 py-3.5 rounded-xl font-semibold text-base text-white bg-gradient-accent hover:brightness-110 disabled:opacity-60 transition flex items-center justify-center gap-2"
            >
              {pending && <Loader2 className="w-4 h-4 animate-spin" />}
              {pending ? "Memulai…" : "Mulai audit"}
              {!pending && <ArrowRight className="w-4 h-4" />}
            </button>
          </div>

          <label className="flex items-start gap-2.5 text-sm text-soft cursor-pointer">
            <input
              type="checkbox"
              checked={consent}
              onChange={(e) => setConsent(e.target.checked)}
              className="mt-0.5 w-4 h-4 shrink-0 accent-[var(--accent)]"
            />
            <span>Saya pemilik domain ini atau punya izin tertulis.</span>
          </label>

          {error && (
            <p role="alert" className="flex items-start gap-2 text-sm text-danger">
              <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" /> {error}
            </p>
          )}
        </form>

        <dl className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {STATS.map((s) => (
            <div key={s.label} className="rounded-2xl bg-foreground/[0.04] px-4 py-3">
              <dd className="text-xl font-bold">{s.val}</dd>
              <dt className="text-xs text-muted">{s.label}</dt>
            </div>
          ))}
        </dl>
      </section>

      {/* Modul */}
      <section className="space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <h2 className="text-xl sm:text-2xl font-bold">{SENTINEL_NAV_ITEMS.length} modul</h2>
          <div className="flex gap-1.5 overflow-x-auto thin-scroll snap-x max-w-full">
            {categories.map((c) => (
              <Chip key={c} active={category === c} onClick={() => setCategory(c)}>{c}</Chip>
            ))}
          </div>
        </div>
        <ul className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-3.5">
          {modules.map((m) => (
            <li key={m.id}>
              <Link
                href={m.route}
                className="glass-panel h-full rounded-2xl p-4 flex flex-col gap-2 hover:border-accent/40 hover:-translate-y-0.5"
              >
                <span className="flex items-center justify-between gap-2">
                  <span className="flex items-center gap-2.5 min-w-0">
                    <ModuleIcon name={m.iconName} className="w-5 h-5 text-accent shrink-0" />
                    <span className="text-base font-semibold truncate">{m.title}</span>
                  </span>
                  {m.badge && (
                    <span className={`text-xs font-mono font-semibold px-1.5 py-0.5 rounded shrink-0 ${BADGE_TONE[m.badgeTone ?? "pink"]}`}>
                      {m.badge}
                    </span>
                  )}
                </span>
                <span className="text-sm text-muted line-clamp-2">{m.description}</span>
              </Link>
            </li>
          ))}
        </ul>
      </section>
    </div>
  );
}

export default HomePage;
