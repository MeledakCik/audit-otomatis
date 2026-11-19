"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { ArrowRight, CheckCircle2, Globe, Loader2, RefreshCw } from "lucide-react";
import type { checkDomain } from "@/lib/sentinel/domain-check";

type DomainOption = { key: string; domain: string };
type DomainResult = Awaited<ReturnType<typeof checkDomain>>;

const expiryDate = new Intl.DateTimeFormat("id-ID", { dateStyle: "medium", timeZone: "Asia/Jakarta" });

export function DomainCheckPanel() {
  const [options, setOptions] = useState<DomainOption[]>([]);
  const [key, setKey] = useState("");
  const [revision, setRevision] = useState(0);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [listError, setListError] = useState("");
  const [testError, setTestError] = useState("");
  const [result, setResult] = useState<DomainResult | null>(null);

  useEffect(() => {
    const controller = new AbortController();

    async function load() {
      try {
        const response = await fetch("/api/admin/domain-check", { signal: controller.signal });
        if (response.status === 401) return window.location.replace("/admin/login");
        if (!response.ok) throw new Error();
        const { items }: { items: DomainOption[] } = await response.json();
        setOptions(items);
        setKey((current) => items.some((item) => item.key === current) ? current : "");
      } catch {
        if (!controller.signal.aborted) setListError("Daftar domain gagal dimuat.");
      } finally {
        if (!controller.signal.aborted) setLoading(false);
      }
    }

    void load();
    return () => controller.abort();
  }, [revision]);

  function refreshDomains() {
    setListError("");
    setLoading(true);
    setRevision((current) => current + 1);
  }

  async function run(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!key || busy || loading || listError) return;

    setBusy(true);
    setResult(null);
    setTestError("");
    try {
      const response = await fetch("/api/admin/domain-check", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key }),
        signal: AbortSignal.timeout(20000),
      });
      if (response.status === 401) return window.location.replace("/admin/login");
      const data = await response.json();
      if (!response.ok) {
        setTestError(data.error ?? "Uji domain gagal.");
        if (response.status === 409) refreshDomains();
        return;
      }
      setResult(data);
    } catch {
      setTestError("Server admin gagal merespons. Coba lagi.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="max-w-3xl space-y-4">
      <section className="glass-panel space-y-5 rounded-2xl p-5 sm:p-7">
        <div>
          <h1 className="text-2xl font-bold tracking-tight sm:text-3xl">Uji domain terverifikasi</h1>
          <p className="mt-2 text-sm text-muted">Periksa respons HTTPS, sertifikat TLS, dan header keamanan halaman utama.</p>
        </div>

        <form onSubmit={run} className="space-y-2">
          <label htmlFor="verified-domain" className="text-sm font-medium">Domain</label>
          <div className="flex flex-col gap-2 sm:flex-row">
            <div className="flex min-w-0 flex-1 items-center gap-2 rounded-xl border border-border bg-sunken px-3 focus-within:border-accent">
              <Globe aria-hidden className="size-4 shrink-0 text-accent" />
              <select
                id="verified-domain"
                value={key}
                disabled={loading || busy || !!listError || options.length === 0}
                onChange={(event) => {
                  setKey(event.target.value);
                  setResult(null);
                  setTestError("");
                }}
                className="h-11 w-full min-w-0 rounded-lg bg-sunken text-sm text-foreground disabled:text-muted"
                required
              >
                <option value="">{loading ? "Memuat domain…" : "Pilih domain"}</option>
                {options.map((item) => <option key={item.key} value={item.key}>{item.domain}</option>)}
              </select>
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                onClick={refreshDomains}
                disabled={loading || busy}
                aria-label="Muat ulang daftar domain"
                title="Muat ulang daftar domain"
                className="grid size-11 shrink-0 place-items-center rounded-xl border border-border text-muted hover:bg-foreground/5 disabled:opacity-50"
              >
                <RefreshCw aria-hidden className="size-4" />
              </button>
              <button
                type="submit"
                disabled={!key || loading || busy || !!listError}
                className="flex min-h-11 flex-1 items-center justify-center gap-2 rounded-xl bg-gradient-accent px-4 text-sm font-semibold text-white hover:brightness-110 disabled:opacity-50"
              >
                {busy ? <Loader2 aria-hidden className="size-4 motion-safe:animate-spin" /> : <ArrowRight aria-hidden className="size-4" />}
                {busy ? "Menguji…" : "Jalankan uji"}
              </button>
            </div>
          </div>
        </form>
        {!loading && !listError && options.length === 0 && (
          <p className="text-sm text-muted">
            Belum ada bukti kepemilikan yang masih berlaku. <Link href="/admin/requests" className="text-accent underline">Lihat klaim domain</Link>
          </p>
        )}
        {(listError || testError) && <p role="alert" className="text-sm text-danger">{listError || testError}</p>}
        {busy && <p role="status" className="sr-only">Permintaan HTTPS sedang berjalan.</p>}
      </section>

      {result && (
        <section aria-labelledby="domain-result" className="space-y-4 rounded-2xl border border-border bg-panel p-5 sm:p-7">
          <h2 id="domain-result" role="status" className="break-all text-lg font-semibold">Hasil uji {result.domain}</h2>
          <dl className="grid grid-cols-2 gap-3 sm:grid-cols-4">
            {[
              { label: "Status HTTP", value: `${result.statusCode} (${result.method})` },
              { label: "Waktu respons", value: `${result.responseTimeMs} ms` },
              { label: "Versi TLS", value: result.tlsVersion ?? "Tidak diketahui" },
              { label: "Sertifikat berakhir", value: result.certificateExpiresAt ? expiryDate.format(result.certificateExpiresAt) : "Tidak diketahui" },
            ].map(({ label, value }) => (
              <div key={label} className="rounded-xl border border-border bg-sunken p-3">
                <dt className="text-xs text-muted">{label}</dt>
                <dd className="mt-1 text-sm font-semibold tabular-nums">{value}</dd>
              </div>
            ))}
          </dl>
          {!result.pageAssessed && (
            <p className="rounded-xl border border-border bg-sunken p-3 text-sm text-muted">
              Halaman utama belum bisa dinilai dari respons ini. Header yang ditampilkan berasal dari respons HTTP {result.statusCode}.
            </p>
          )}
          {result.checks.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold">Header keamanan</h3>
              <ul className="mt-2 divide-y divide-border text-sm">
                {result.checks.map((check) => (
                  <li key={check.name} className="flex items-center justify-between gap-2 py-2">
                    <span className="min-w-0 wrap-break-word text-soft">{check.name}</span>
                    {check.pass
                      ? <span className="inline-flex shrink-0 items-center gap-1 text-xs text-ok"><CheckCircle2 aria-hidden className="size-3.5" /> {result.pageAssessed ? "Lolos" : "Teramati"}</span>
                      : <span className="shrink-0 text-xs text-warn">Perlu diperiksa</span>}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
