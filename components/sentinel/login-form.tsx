"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { ArrowLeft, Eye, EyeOff, Lock } from "lucide-react";

const inputClass = "h-11 w-full rounded-xl border border-border bg-sunken px-3 text-sm text-foreground";

export function LoginForm() {
  const router = useRouter();
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [showPass, setShowPass] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const response = await fetch("/api/admin/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user, pass }),
      });
      if (response.ok) {
        router.replace("/admin/test");
        router.refresh();
        return;
      }
      const data = await response.json().catch(() => ({}));
      setError(data.error ?? "Gagal masuk.");
      setPass("");
    } catch {
      setError("Gagal menghubungi server autentikasi.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-md px-1 py-8 sm:py-14">
      <Link href="/dashboard" className="mb-4 inline-flex min-h-10 items-center gap-2 rounded-lg text-sm text-muted hover:text-foreground">
        <ArrowLeft aria-hidden className="size-4" /> Dasbor pengguna
      </Link>
      <section className="glass-panel space-y-5 rounded-2xl p-5 sm:p-7">
        <div className="flex items-center gap-3">
          <div className="grid size-10 place-items-center rounded-xl bg-accent/10 text-accent">
            <Lock aria-hidden className="size-5" />
          </div>
          <h1 className="text-2xl font-bold tracking-tight">Masuk sebagai admin</h1>
        </div>
        <form onSubmit={submit} className="space-y-4">
          <div className="space-y-1.5">
            <label htmlFor="admin-user" className="text-sm font-medium">Nama pengguna</label>
            <input id="admin-user" className={inputClass} autoComplete="username" value={user} onChange={(event) => setUser(event.target.value)} required />
          </div>
          <div className="space-y-1.5">
            <label htmlFor="admin-pass" className="text-sm font-medium">Kata sandi</label>
            <div className="relative">
              <input id="admin-pass" className={`${inputClass} pr-12`} type={showPass ? "text" : "password"} autoComplete="current-password" value={pass} onChange={(event) => setPass(event.target.value)} required />
              <button
                type="button"
                onClick={() => setShowPass(!showPass)}
                aria-label={showPass ? "Sembunyikan kata sandi" : "Tampilkan kata sandi"}
                className="absolute inset-y-0 right-0 grid w-11 place-items-center rounded-xl text-muted hover:text-foreground"
              >
                {showPass ? <EyeOff aria-hidden className="size-4" /> : <Eye aria-hidden className="size-4" />}
              </button>
            </div>
          </div>
          {error && <p role="alert" className="text-sm text-danger">{error}</p>}
          <button type="submit" disabled={busy} className="h-11 w-full rounded-xl bg-gradient-accent text-sm font-semibold text-white hover:brightness-110 disabled:opacity-60">
            {busy ? "Memverifikasi…" : "Masuk"}
          </button>
        </form>
      </section>
    </div>
  );
}
