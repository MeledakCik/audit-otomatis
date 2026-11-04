"use client";
import { useCallback, useEffect, useState } from "react";

interface Item { key: string; ttl: number; domain: string; status: string; proof?: { method: string; verifiedAt: number }; createdAt: number }

export function RequestsTable() {
  const [items, setItems] = useState<Item[] | null>(null);
  const [msg, setMsg] = useState("");

  const load = useCallback(async () => {
    const r = await fetch("/api/admin/requests");
    if (r.status === 401) { window.location.href = "/admin/login"; return; }
    setItems((await r.json()).items);
  }, []);
  useEffect(() => { load(); }, [load]);

  async function decide(key: string, action: "ACC" | "REJECT") {
    if (!confirm(action === "ACC" ? "ACC: user akan bisa melihat evidence 1x (10 menit). Lanjut?" : "Tolak request ini?")) return;
    const r = await fetch("/api/admin/requests", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ key, action }) });
    const j = await r.json();
    setMsg(r.ok ? `${action} berhasil` : j.error ?? "Gagal");
    load();
  }

  const badge = (s: string) =>
    ({ PENDING: "text-yellow-400", APPROVED: "text-green-400", VIEWED: "text-muted", REJECTED: "text-sev-critical", AWAITING_PROOF: "text-muted" } as Record<string, string>)[s] ?? "";

  return (
    <section>
      <div className="mb-3 flex items-center justify-between">
        <h1 className="text-lg font-semibold">Auth Requests ({items?.length ?? "…"})</h1>
        <button onClick={load} className="text-sm text-muted hover:text-foreground">Refresh</button>
      </div>
      {msg && <p className="mb-2 text-sm">{msg}</p>}
      <div className="overflow-x-auto rounded-xl border border-border">
        <table className="w-full text-left text-sm">
          <thead className="text-muted"><tr><th className="p-3">Domain</th><th className="p-3">Status</th><th className="p-3">Bukti</th><th className="p-3">Sisa</th><th className="p-3" /></tr></thead>
          <tbody>
            {items?.map((i) => (
              <tr key={i.key} className="border-t border-border">
                <td className="p-3">{i.domain}</td>
                <td className={`p-3 font-mono text-xs ${badge(i.status)}`}>{i.status}</td>
                <td className="p-3 text-xs">{i.proof ? `${i.proof.method.toUpperCase()} ✓` : "—"}</td>
                <td className="p-3 text-xs">{Math.floor(i.ttl / 3600)}j</td>
                <td className="space-x-2 p-3 text-right">
                  {["PENDING", "APPROVED"].includes(i.status) && <>
                    <button onClick={() => decide(i.key, "ACC")} className="rounded-full border border-green-500/50 px-3 py-1 text-xs text-green-400 hover:bg-green-500/10">{i.status === "APPROVED" ? "ACC ulang" : "ACC"}</button>
                    <button onClick={() => decide(i.key, "REJECT")} className="rounded-full border border-sev-critical/40 px-3 py-1 text-xs text-sev-critical hover:bg-sev-critical/10">REJECT</button>
                  </>}
                </td>
              </tr>
            ))}
            {items?.length === 0 && <tr><td colSpan={5} className="p-6 text-center text-muted">Belum ada request.</td></tr>}
          </tbody>
        </table>
      </div>
    </section>
  );
}
