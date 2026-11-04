"use client";
import { useState } from "react";
import { useRouter } from "next/navigation";

export function LoginForm() {
  const router = useRouter();
  const [user, setUser] = useState("");
  const [pass, setPass] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setErr("");
    const res = await fetch("/api/admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ user, pass }),
    });
    if (res.ok) { router.replace("/admin/vault"); router.refresh(); return; }
    const j = await res.json().catch(() => ({}));
    setErr(j.error ?? "Login gagal");
    setPass(""); setBusy(false);
  }

  const field = "w-full rounded-lg border border-border bg-surface px-3 py-2 text-sm outline-none focus:border-accent";
  return (
    <main className="mx-auto flex min-h-[70vh] w-full max-w-sm items-center p-4">
      <form onSubmit={submit} className="w-full space-y-4 rounded-2xl border border-border p-6">
        <h1 className="text-lg font-semibold">Admin Login</h1>
        <input className={field} placeholder="Username" autoComplete="username" value={user} onChange={(e) => setUser(e.target.value)} required />
        <input className={field} placeholder="Password" type="password" autoComplete="current-password" value={pass} onChange={(e) => setPass(e.target.value)} required />
        {err && <p role="alert" className="text-sm text-sev-critical">{err}</p>}
        <button disabled={busy} className="w-full rounded-full bg-accent px-4 py-2 text-sm font-semibold text-accent-fg disabled:opacity-50">
          {busy ? "…" : "Masuk"}
        </button>
      </form>
    </main>
  );
}
