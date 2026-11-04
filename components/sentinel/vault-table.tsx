"use client";
import { useCallback, useEffect, useState } from "react";

interface Item { key: string; domain: string; id: string; ttl: number }
interface Ev { path: string; status: number; contentType: string; marker: string; snippet: string; domain: string }

const fmt = (s: number) => `${Math.floor(s / 3600)}j ${Math.floor((s % 3600) / 60)}m`;

export function VaultTable() {
  const [items, setItems] = useState<Item[] | null>(null);
  const [open, setOpen] = useState<{ key: string; ev: Ev } | null>(null);
  const [err, setErr] = useState("");

  const load = useCallback(async () => {
    const r = await fetch("/api/admin/vault");
    if (r.status === 401) { window.location.href = "/admin/login"; return; }
    setItems((await r.json()).items);
  }, []);
  useEffect(() => { load(); }, [load]);

  async function view(key: string) {
    setErr("");
    const r = await fetch("/api/admin/vault", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ key }) });
    const j = await r.json();
    if (!r.ok) return setErr(j.error ?? "Gagal");
    setOpen({ key, ev: j.evidence });
  }

  return (
    <section>
      <div className="mb-3 flex items-center justify-between">
        <h1 className="text-lg font-semibold">Vault ({items?.length ?? "…"})</h1>
        <button onClick={load} className="text-sm text-muted hover:text-foreground">Refresh</button>
      </div>
      {err && <p className="mb-2 text-sm text-sev-critical">{err}</p>}
      <div className="overflow-x-auto rounded-xl border border-border">
        <table className="w-full text-left text-sm">
          <thead className="text-muted"><tr><th className="p-3">Domain</th><th className="p-3">ID</th><th className="p-3">Sisa TTL</th><th className="p-3" /></tr></thead>
          <tbody>
            {items?.map((i) => (
              <tr key={i.key} className="border-t border-border">
                <td className="p-3">{i.domain}</td>
                <td className="p-3 font-mono text-xs">{i.id}</td>
                <td className="p-3">{fmt(i.ttl)}</td>
                <td className="p-3 text-right"><button onClick={() => view(i.key)} className="rounded-full border border-border-strong px-3 py-1 text-xs hover:border-accent">Decrypt &amp; View</button></td>
              </tr>
            ))}
            {items?.length === 0 && <tr><td colSpan={4} className="p-6 text-center text-muted">Vault kosong.</td></tr>}
          </tbody>
        </table>
      </div>

      {open && (
        <div role="dialog" aria-modal className="fixed inset-0 z-50 grid place-items-center bg-black/70 p-4" onClick={() => setOpen(null)}>
          <div className="max-h-[85vh] w-full max-w-2xl overflow-auto rounded-2xl border border-border bg-background p-5" onClick={(e) => e.stopPropagation()}>
            <div className="mb-3 flex justify-between"><h2 className="font-semibold">{open.ev.domain}{open.ev.path}</h2><button onClick={() => setOpen(null)}>✕</button></div>
            <p className="mb-2 text-xs text-muted">HTTP {open.ev.status} · {open.ev.contentType || "-"} · marker: {open.ev.marker}</p>
            <pre className="whitespace-pre-wrap break-all rounded-lg bg-surface p-3 font-mono text-xs">{open.ev.snippet}</pre>
          </div>
        </div>
      )}
    </section>
  );
}
