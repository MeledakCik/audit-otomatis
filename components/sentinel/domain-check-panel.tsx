"use client";

import { useState, type FormEvent } from "react";
import { useRouter } from "next/navigation";
import { ArrowRight, Loader2, Radar, ShieldCheck } from "lucide-react";

export function DomainCheckPanel() {
  const router = useRouter();
  const [domain, setDomain] = useState("");
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");

  async function startAudit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (running) return;

    const target = domain.trim();
    if (!target) return;
    setRunning(true);
    setError("");
    try {
      const response = await fetch("/api/admin/security-audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: target }),
        signal: AbortSignal.timeout(15000),
      });
      if (response.status === 401) return router.replace("/admin/login");
      const data = await response.json();
      if (!response.ok) {
        setError(data.error ?? "Audit tidak bisa dimulai.");
        return;
      }
      router.push(`/admin/audit/${data.scanId}`);
    } catch {
      setError("Server admin gagal merespons. Coba lagi.");
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="max-w-5xl space-y-5">
      <section className="glass-panel space-y-5 rounded-2xl p-5 sm:p-7">
        <div className="flex items-start gap-3">
          <div className="grid size-11 shrink-0 place-items-center rounded-xl bg-accent/10 text-accent">
            <Radar aria-hidden className="size-5" />
          </div>
          <div className="min-w-0">
            <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">Security audit</h1>
            <p className="mt-1 text-sm text-muted">Masukkan domain untuk memulai pemetaan, pemeriksaan kerentanan, lalu validasi bukti yang aman.</p>
          </div>
        </div>

        <div className="grid gap-3 sm:grid-cols-3">
          {[
            { title: "1. Pemetaan", detail: "Crawl halaman, endpoint, form, dan teknologi." },
            { title: "2. Pemeriksaan", detail: "Korelasi CVE, analisis XSS, indikasi RCE/webshell, upload, dan file sensitif." },
            { title: "3. Validasi bukti", detail: "Uji POST teks hanya tersedia jika form upload ditemukan." },
          ].map((step) => (
            <div key={step.title} className="rounded-xl border border-border bg-sunken p-3">
              <p className="text-sm font-semibold">{step.title}</p>
              <p className="mt-1 text-xs leading-relaxed text-muted">{step.detail}</p>
            </div>
          ))}
        </div>

        <form onSubmit={(event) => void startAudit(event)} className="space-y-2.5">
          <label htmlFor="security-audit-domain" className="text-sm font-medium">Domain atau URL target</label>
          <div className="flex flex-col gap-2 sm:flex-row">
            <input
              id="security-audit-domain"
              name="domain"
              type="text"
              inputMode="url"
              autoComplete="url"
              autoCapitalize="none"
              spellCheck={false}
              placeholder="contoh.com atau https://contoh.com"
              value={domain}
              onChange={(event) => setDomain(event.target.value)}
              disabled={running}
              required
              maxLength={2048}
              className="h-11 min-w-0 flex-1 rounded-xl border border-border bg-sunken px-3 text-sm text-foreground outline-none placeholder:text-muted focus:border-accent disabled:opacity-60"
            />
            <button
              type="submit"
              disabled={!domain.trim() || running}
              className="flex min-h-11 items-center justify-center gap-2 rounded-xl bg-gradient-accent px-5 text-sm font-semibold text-white hover:brightness-110 disabled:cursor-wait disabled:opacity-60"
            >
              {running ? <Loader2 aria-hidden className="size-4 motion-safe:animate-spin" /> : <ArrowRight aria-hidden className="size-4" />}
              {running ? "Menyiapkan audit…" : "Mulai audit"}
            </button>
          </div>
          {error && <p role="alert" className="text-sm text-danger">{error}</p>}
        </form>

        <p className="flex items-start gap-2 text-xs leading-relaxed text-muted">
          <ShieldCheck aria-hidden className="mt-0.5 size-4 shrink-0 text-ok" />
          Hanya target publik yang dapat diakses melalui HTTPS. Gunakan pada domain yang Anda berwenang uji. Pemeriksaan tidak mengeksekusi shell, webshell, RCE, atau payload destruktif; batas laju dan proteksi SSRF tetap aktif.
        </p>
      </section>
    </div>
  );
}
