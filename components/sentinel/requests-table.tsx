"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { KeyRound, RefreshCw, CheckCircle2, XCircle, Clock, Search, AlertTriangle } from "lucide-react";
import { cn } from "@/lib/utils";

interface Item {
  key: string;
  ttl: number;
  domain: string;
  status: string;
  proof?: { method: string; verifiedAt: number };
  createdAt: number;
}

export function RequestsTable() {
  const [items, setItems] = useState<Item[] | null>(null);
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null);
  const [search, setSearch] = useState("");
  const [confirmModal, setConfirmModal] = useState<{
    key: string;
    domain: string;
    action: "ACC" | "REJECT";
  } | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    const r = await fetch("/api/admin/requests");
    if (r.status === 401) {
      window.location.href = "/admin/login";
      return;
    }
    setItems((await r.json()).items ?? []);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function executeDecision() {
    if (!confirmModal) return;
    setBusy(true);
    setMsg(null);
    try {
      const r = await fetch("/api/admin/requests", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key: confirmModal.key, action: confirmModal.action }),
      });
      const j = await r.json();
      setMsg({
        text: r.ok
          ? `Klaim domain ${confirmModal.domain} berhasil di-${confirmModal.action}!`
          : j.error ?? "Gagal memproses klaim",
        ok: r.ok,
      });
      setConfirmModal(null);
      await load();
    } finally {
      setBusy(false);
    }
  }

  const badgeStyle = (s: string) =>
    ({
      PENDING: "bg-amber-500/20 text-amber-300 border-amber-500/40",
      APPROVED: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
      VIEWED: "bg-sky-500/20 text-sky-300 border-sky-500/40",
      REJECTED: "bg-red-500/20 text-red-300 border-red-500/40",
      AWAITING_PROOF: "bg-purple-500/20 text-purple-300 border-purple-500/40",
    } as Record<string, string>)[s] ?? "bg-foreground/10 text-soft border-foreground/20";

  const filtered = useMemo(() => {
    if (!items) return [];
    const q = search.trim().toLowerCase();
    if (!q) return items;
    return items.filter(
      (i) => i.domain.toLowerCase().includes(q) || i.status.toLowerCase().includes(q)
    );
  }, [items, search]);

  return (
    <section className="space-y-4">
      <div className="rounded-2xl border border-border bg-panel p-5 flex flex-wrap items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="inline-flex items-center gap-1.5 rounded-full bg-amber-500/15 border border-amber-500/30 px-2.5 py-0.5 text-xs font-mono font-bold text-amber-300">
            <KeyRound className="h-3 w-3" />
            VERIFIKASI KEPEMILIKAN DOMAIN
          </div>
          <h1 className="text-lg font-extrabold text-foreground">
            Permintaan Klaim Domain ({items?.length ?? "…"})
          </h1>
          <p className="text-xs text-muted">
            Setujui (ACC) permintaan yang telah lulus verifikasi DNS TXT / HTTP File untuk menerbitkan token sekali-pakai (berlaku 10 menit).
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <div className="relative">
            <Search className="h-3.5 w-3.5 text-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Cari domain / status..."
              className="h-9 rounded-xl border border-border bg-sunken pl-9 pr-3 text-xs font-mono text-foreground placeholder:text-muted outline-none focus:border-purple-400"
            />
          </div>
          <button
            type="button"
            onClick={load}
            className="inline-flex items-center gap-1.5 rounded-xl border border-border bg-foreground/[0.04] hover:bg-foreground/[0.08] px-3.5 py-2 text-xs font-mono text-soft cursor-pointer"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            <span>Refresh</span>
          </button>
        </div>
      </div>

      {msg && (
        <div
          className={cn(
            "rounded-xl border px-4 py-3 text-xs font-mono",
            msg.ok
              ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-300"
              : "border-red-500/40 bg-red-500/10 text-red-300"
          )}
        >
          {msg.text}
        </div>
      )}

      <div className="overflow-x-auto rounded-2xl border border-border bg-panel shadow-xl">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-border bg-sunken font-mono uppercase text-xs text-muted">
            <tr>
              <th className="p-4">Domain</th>
              <th className="p-4">Status Klaim</th>
              <th className="p-4">Metode Bukti</th>
              <th className="p-4">Sisa TTL</th>
              <th className="p-4 text-right">Keputusan Admin</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.06]">
            {filtered.map((i) => (
              <tr key={i.key} className="hover:bg-foreground/[0.03] transition-colors">
                <td className="p-4 font-mono font-bold text-foreground">{i.domain}</td>
                <td className="p-4">
                  <span
                    className={cn(
                      "inline-flex items-center rounded-full border px-2.5 py-0.5 font-mono text-xs font-bold uppercase",
                      badgeStyle(i.status)
                    )}
                  >
                    {i.status}
                  </span>
                </td>
                <td className="p-4 font-mono">
                  {i.proof ? (
                    <span className="inline-flex items-center gap-1 text-emerald-400 font-semibold">
                      <CheckCircle2 className="h-3.5 w-3.5" />
                      {i.proof.method.toUpperCase()} TERVERIFIKASI
                    </span>
                  ) : (
                    <span className="text-muted">Menunggu bukti user</span>
                  )}
                </td>
                <td className="p-4 font-mono text-soft">
                  <span className="inline-flex items-center gap-1">
                    <Clock className="h-3.5 w-3.5 text-muted" />
                    {Math.floor(i.ttl / 3600)}j
                  </span>
                </td>
                <td className="p-4 text-right space-x-2">
                  {["PENDING", "APPROVED"].includes(i.status) && (
                    <>
                      <button
                        type="button"
                        onClick={() =>
                          setConfirmModal({ key: i.key, domain: i.domain, action: "ACC" })
                        }
                        className="inline-flex items-center gap-1 rounded-xl border border-emerald-500/40 bg-emerald-500/15 hover:bg-emerald-500/25 px-3 py-1.5 font-mono text-xs font-bold text-emerald-300 cursor-pointer"
                      >
                        <CheckCircle2 className="h-3.5 w-3.5" />
                        <span>{i.status === "APPROVED" ? "ACC Ulang" : "ACC"}</span>
                      </button>
                      <button
                        type="button"
                        onClick={() =>
                          setConfirmModal({ key: i.key, domain: i.domain, action: "REJECT" })
                        }
                        className="inline-flex items-center gap-1 rounded-xl border border-red-500/40 bg-red-500/15 hover:bg-red-500/25 px-3 py-1.5 font-mono text-xs font-bold text-red-300 cursor-pointer"
                      >
                        <XCircle className="h-3.5 w-3.5" />
                        <span>REJECT</span>
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={5} className="p-10 text-center font-mono text-muted">
                  Belum ada permintaan klaim kepemilikan domain.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {confirmModal && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 grid place-items-center bg-black/75 backdrop-blur-xs p-4"
          onClick={() => setConfirmModal(null)}
        >
          <div
            className="w-full max-w-md rounded-2xl border border-purple-500/35 bg-panel p-6 shadow-2xl space-y-4"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-center gap-2.5">
              <AlertTriangle
                className={cn(
                  "h-5 w-5",
                  confirmModal.action === "ACC" ? "text-emerald-400" : "text-red-400"
                )}
              />
              <h2 className="text-base font-extrabold text-foreground">
                Konfirmasi {confirmModal.action} Klaim Domain
              </h2>
            </div>
            <p className="text-xs text-soft leading-relaxed">
              {confirmModal.action === "ACC"
                ? `Anda akan menyetujui (ACC) klaim kepemilikan untuk domain "${confirmModal.domain}". User akan mendapatkan token sekali-pakai (berlaku 10 menit) untuk melihat evidence dari Vault.`
                : `Anda akan menolak (REJECT) klaim kepemilikan untuk domain "${confirmModal.domain}".`}
            </p>
            <div className="flex justify-end gap-2 pt-2">
              <button
                type="button"
                onClick={() => setConfirmModal(null)}
                className="rounded-xl border border-foreground/15 bg-foreground/5 px-4 py-2 text-xs font-semibold text-soft hover:bg-foreground/10"
              >
                Batal
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={executeDecision}
                className={cn(
                  "rounded-xl px-4 py-2 text-xs font-bold text-foreground cursor-pointer",
                  confirmModal.action === "ACC"
                    ? "bg-emerald-600 hover:bg-emerald-500"
                    : "bg-red-600 hover:bg-red-500"
                )}
              >
                {busy ? "Memproses…" : `Ya, ${confirmModal.action} Sekarang`}
              </button>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
