"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { ShieldAlert, Lock, User, Eye, EyeOff, ArrowLeft, CheckCircle2, AlertTriangle } from "lucide-react";
import { VerifiedBadge } from "@/components/verified-badge";

export function LoginForm() {
  const router = useRouter();
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const res = await fetch("/api/admin/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user, pass }),
      });
      if (res.ok) {
        router.replace("/admin/activities");
        router.refresh();
        return;
      }
      const j = await res.json().catch(() => ({}));
      setErr(j.error ?? "Login gagal");
      setPass("");
    } catch {
      setErr("Gagal menghubungi server autentikasi.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="min-h-dvh w-full flex flex-col justify-between p-4 sm:p-8 bg-[#08060e]">
      {/* Top Bar */}
      <div className="mx-auto w-full max-w-5xl flex items-center justify-between">
        <Link
          href="/"
          className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/[0.03] hover:bg-white/[0.08] px-3.5 py-2 text-xs font-mono text-slate-300 transition-colors"
        >
          <ArrowLeft className="h-3.5 w-3.5" />
          Kembali ke Beranda User
        </Link>
        <VerifiedBadge variant="admin" />
      </div>

      {/* Center Login Card */}
      <div className="mx-auto w-full max-w-md my-auto py-8">
        <div className="rounded-3xl border border-purple-500/30 bg-gradient-to-b from-[#171128] via-[#120d1f] to-[#0d0917] p-6 sm:p-8 shadow-2xl shadow-purple-950/40 space-y-6">
          <div className="flex flex-col items-center text-center space-y-2">
            <div className="h-14 w-14 rounded-2xl bg-gradient-to-br from-purple-600 to-pink-600 grid place-items-center text-white shadow-lg shadow-purple-600/30">
              <ShieldAlert className="h-7 w-7" />
            </div>
            <div className="inline-flex items-center gap-1.5 rounded-full bg-purple-500/15 border border-purple-500/30 px-3 py-0.5 text-[10px] font-mono font-bold uppercase tracking-widest text-purple-300">
              RESTRICTED ACCESS
            </div>
            <h1 className="text-2xl font-extrabold text-white tracking-tight">
              Admin Command Center
            </h1>
            <p className="text-xs text-slate-400 leading-relaxed">
              Pantau seluruh data &amp; aktivitas user secara real-time, kelola brankas bukti AES-256-GCM, dan verifikasi klaim domain.
            </p>
          </div>

          <form onSubmit={submit} className="space-y-4">
            <div className="space-y-1.5">
              <label htmlFor="admin-user" className="text-xs font-mono uppercase tracking-wider text-slate-300 font-semibold">
                Username Admin
              </label>
              <div className="relative">
                <User className="h-4 w-4 text-purple-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  id="admin-user"
                  className="w-full h-11 rounded-xl border border-white/15 bg-black/40 pl-10 pr-4 text-sm text-white placeholder:text-slate-500 outline-none focus:border-purple-400"
                  placeholder="Masukkan username admin"
                  autoComplete="username"
                  value={user}
                  onChange={(e) => setUser(e.target.value)}
                  required
                />
              </div>
            </div>

            <div className="space-y-1.5">
              <label htmlFor="admin-pass" className="text-xs font-mono uppercase tracking-wider text-slate-300 font-semibold">
                Password
              </label>
              <div className="relative">
                <Lock className="h-4 w-4 text-purple-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
                <input
                  id="admin-pass"
                  className="w-full h-11 rounded-xl border border-white/15 bg-black/40 pl-10 pr-10 text-sm text-white placeholder:text-slate-500 outline-none focus:border-purple-400"
                  placeholder="••••••••••••"
                  type={showPass ? "text" : "password"}
                  autoComplete="current-password"
                  value={pass}
                  onChange={(e) => setPass(e.target.value)}
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPass((s) => !s)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-white"
                  aria-label={showPass ? "Sembunyikan password" : "Tampilkan password"}
                >
                  {showPass ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {err && (
              <div
                role="alert"
                className="flex items-center gap-2 rounded-xl border border-red-500/40 bg-red-500/10 px-3.5 py-2.5 text-xs text-red-300"
              >
                <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
                <span>{err}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={busy}
              className="w-full h-11 rounded-xl bg-gradient-to-r from-purple-600 via-fuchsia-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 text-xs font-bold uppercase tracking-wider text-white shadow-lg shadow-purple-600/30 disabled:opacity-50 cursor-pointer"
            >
              {busy ? "Memverifikasi Sesi…" : "Masuk ke Admin Console →"}
            </button>
          </form>

          <div className="pt-3 border-t border-white/10 grid grid-cols-2 gap-2 text-[11px] font-mono text-slate-400">
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
              <span>Bcrypt Timing-Safe</span>
            </div>
            <div className="flex items-center gap-1.5">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
              <span>JWT HS256 + Redis</span>
            </div>
          </div>
        </div>
      </div>

      {/* Bottom Footer */}
      <div className="mx-auto w-full max-w-5xl text-center text-xs font-mono text-slate-500">
        Sentinel-ID Auto Security Auditor · Verified by Google Developer Bandung
      </div>
    </div>
  );
}
