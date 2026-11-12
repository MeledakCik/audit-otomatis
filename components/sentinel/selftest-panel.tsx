"use client";

import { useState } from "react";
import { FlaskConical, CheckCircle2, XCircle, Loader2, ChevronDown } from "lucide-react";
import { cn } from "@/lib/utils";

interface SelfTestCase { name: string; pass: boolean; detail: string }
interface SelfTestResult { ranAt: number; pass: number; fail: number; cases: SelfTestCase[]; ok: boolean }

/**
 * Jalankan self-test mesin "Audit File Sensitif" sebelum admin memakainya untuk pelaporan
 * ke pihak domain. Self-test ini 100% lokal (fixture tetap, tanpa jaringan, tanpa menyentuh
 * domain apa pun) — hanya memverifikasi bahwa engine deteksi & redaksi masih berjalan benar.
 */
export function SelfTestPanel() {
  const [result, setResult] = useState<SelfTestResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [open, setOpen] = useState(false);

  async function run() {
    setBusy(true);
    setErr("");
    try {
      const res = await fetch("/api/admin/selftest", { method: "POST" });
      if (res.status === 401) { window.location.href = "/admin/login"; return; }
      const j = await res.json();
      if (!res.ok) { setErr(j.error ?? "Self-test gagal"); setResult(null); return; }
      setResult(j as SelfTestResult);
      setOpen(true);
    } catch {
      setErr("Tidak bisa menjalankan self-test (koneksi ke server admin gagal).");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="rounded-2xl border border-border bg-panel p-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <FlaskConical className="h-4 w-4 text-cyan-300" />
          <div>
            <p className="text-sm font-bold text-foreground">Self-Test Engine Audit File Sensitif</p>
            <p className="text-xs text-muted">
              Fixture lokal saja — tidak ada request ke domain mana pun. Jalankan sebelum memakai hasil untuk pelaporan.
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {result && (
            <button
              type="button"
              onClick={() => setOpen((o) => !o)}
              className="inline-flex items-center gap-1 rounded-lg bg-foreground/5 px-3 py-1.5 text-xs font-mono text-soft hover:text-foreground cursor-pointer"
            >
              {result.ok ? (
                <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              ) : (
                <XCircle className="h-3.5 w-3.5 text-red-400" />
              )}
              {result.pass}/{result.pass + result.fail} lolos
              <ChevronDown className={cn("h-3.5 w-3.5 transition-transform", open && "rotate-180")} />
            </button>
          )}
          <button
            type="button"
            onClick={run}
            disabled={busy}
            className="inline-flex items-center gap-1.5 rounded-lg bg-cyan-600 px-3 py-1.5 text-xs font-bold text-white hover:bg-cyan-500 disabled:opacity-50 cursor-pointer"
          >
            {busy ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <FlaskConical className="h-3.5 w-3.5" />}
            {busy ? "Menguji…" : "Jalankan Self-Test"}
          </button>
        </div>
      </div>

      {err && <p className="mt-2 text-xs text-red-400">{err}</p>}

      {result && open && (
        <ul className="mt-3 max-h-64 space-y-1 overflow-y-auto thin-scroll rounded-xl border border-border bg-sunken p-3 font-mono text-xs">
          {result.cases.map((c, i) => (
            <li key={i} className={cn("flex items-start gap-2", c.pass ? "text-emerald-300" : "text-red-300")}>
              {c.pass ? <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0" /> : <XCircle className="mt-0.5 h-3 w-3 shrink-0" />}
              <span>
                {c.name}
                {c.detail && <span className="text-muted"> — {c.detail}</span>}
              </span>
            </li>
          ))}
        </ul>
      )}

      {result && !result.ok && (
        <p className="mt-2 text-xs font-bold text-red-300">
          ⚠ Ada skenario yang gagal. Jangan pakai hasil audit untuk pelaporan sampai ini diperbaiki.
        </p>
      )}
    </div>
  );
}
