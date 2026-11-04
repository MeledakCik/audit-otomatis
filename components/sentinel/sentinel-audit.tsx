"use client";
import { useEffect, useRef, useState } from "react";

interface Finding { domain: string; severity: "CRITICAL" | "HIGH"; finding: string; evidence_public: string; fix: string }
interface Pub { domain: string; scannedAt: number; findings: Finding[] }
interface Claim {
  status: string; domain?: string; challenge?: string; viewToken?: string;
  instructions?: { dns: { name: string; value: string }; file: { url: string; content: string } };
}
interface Evidence { path: string; status: number; marker: string; snippet: string }

const post = (url: string, body: unknown) =>
  fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });

export function SentinelAudit() {
  const [domain, setDomain] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");
  const [res, setRes] = useState<Pub | null>(null);
  const [claim, setClaim] = useState<Claim | null>(null);
  const [evidence, setEvidence] = useState<Evidence[] | null>(null);
  const poll = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => () => { if (poll.current) clearInterval(poll.current); }, []);

  async function audit(e: React.FormEvent) {
    e.preventDefault();
    setBusy(true); setErr(""); setRes(null); setClaim(null); setEvidence(null);
    const r = await post("/api/sentinel/audit", { domain });
    const j = await r.json();
    setBusy(false);
    if (!r.ok) return setErr(j.error ?? "Audit gagal");
    setRes(j);
    const c = await fetch(`/api/sentinel/claim?domain=${j.domain}`).then((x) => x.json());
    if (c.status !== "NONE") { setClaim(c); watch(j.domain); }
  }

  async function claimStart() {
    if (!res) return;
    const r = await post("/api/sentinel/claim", { domain: res.domain, action: "start" });
    setClaim(await r.json());
  }

  async function claimSubmit() {
    if (!res) return;
    setErr("");
    const r = await post("/api/sentinel/claim", { domain: res.domain, action: "submit" });
    const j = await r.json();
    if (!r.ok) return setErr(j.error ?? "Verifikasi gagal");
    setClaim(j); watch(res.domain);
  }

  function watch(d: string) {
    if (poll.current) clearInterval(poll.current);
    poll.current = setInterval(async () => {
      const c: Claim = await fetch(`/api/sentinel/claim?domain=${d}`).then((x) => x.json());
      setClaim(c);
      if (c.viewToken) {
        clearInterval(poll.current!);
        const v = await fetch(`/api/sentinel/view/${c.viewToken}`); // sekali pakai
        if (v.ok) setEvidence((await v.json()).evidence);
        else setErr("Token sudah dipakai / kedaluwarsa — minta admin ACC ulang.");
      } else if (["REJECTED", "VIEWED"].includes(c.status)) clearInterval(poll.current!);
    }, 5000);
  }

  const sev = (s: string) => (s === "CRITICAL" ? "text-sev-critical" : "text-orange-400");
  const field = "flex-1 rounded-lg border border-border bg-surface px-3 py-2 text-sm outline-none focus:border-accent";

  return (
    <main className="mx-auto w-full max-w-3xl space-y-6 p-4 md:p-8">
      <header>
        <h1 className="text-xl font-semibold">Passive Security Audit</h1>
        <p className="text-sm text-muted">GET-only, non-intrusif. Nilai rahasia tidak pernah ditampilkan.</p>
      </header>

      <form onSubmit={audit} className="flex gap-2">
        <input className={field} placeholder="example.com" value={domain} onChange={(e) => setDomain(e.target.value)} required />
        <button disabled={busy} className="rounded-full bg-accent px-5 text-sm font-semibold text-accent-fg disabled:opacity-50">{busy ? "Scanning…" : "Audit"}</button>
      </form>
      {err && <p role="alert" className="text-sm text-sev-critical">{err}</p>}

      {res && (
        <section className="space-y-3">
          <h2 className="font-semibold">{res.domain} — {res.findings.length} temuan</h2>
          {res.findings.length === 0 && <p className="text-sm text-muted">Tidak ada temuan pada pengecekan pasif ini.</p>}
          {res.findings.map((f, i) => (
            <article key={i} className="rounded-xl border border-border p-4">
              <p className={`text-xs font-bold ${sev(f.severity)}`}>{f.severity}</p>
              <p className="font-medium">{f.finding}</p>
              <p className="mt-1 text-sm text-muted">Evidence: {f.evidence_public}</p>
              <p className="text-sm">Fix: {f.fix}</p>
            </article>
          ))}

          {res.findings.some((f) => f.severity === "CRITICAL") && !claim && (
            <button onClick={claimStart} className="rounded-full border border-border-strong px-4 py-2 text-sm hover:border-accent">Saya Pemilik Domain</button>
          )}
        </section>
      )}

      {claim && claim.status !== "NONE" && (
        <section className="space-y-3 rounded-xl border border-border p-4">
          <p className="text-sm">Status klaim: <b>{claim.status}</b></p>

          {claim.status === "AWAITING_PROOF" && claim.instructions && (
            <>
              <p className="text-sm">Buktikan kepemilikan dengan salah satu:</p>
              <ol className="list-decimal space-y-2 pl-5 text-sm">
                <li>DNS TXT <code className="font-mono text-xs">{claim.instructions.dns.name}</code> = <code className="font-mono text-xs break-all">{claim.instructions.dns.value}</code></li>
                <li>File <code className="font-mono text-xs break-all">{claim.instructions.file.url}</code> berisi teks <code className="font-mono text-xs">{claim.instructions.file.content}</code></li>
              </ol>
              <button onClick={claimSubmit} className="rounded-full bg-accent px-4 py-2 text-sm font-semibold text-accent-fg">Verifikasi &amp; Kirim ke Admin</button>
            </>
          )}
          {claim.status === "PENDING" && <p className="text-sm text-muted">Bukti terverifikasi. Menunggu persetujuan admin (halaman ini auto-refresh)…</p>}
          {claim.status === "REJECTED" && <p className="text-sm text-sev-critical">Permintaan ditolak admin.</p>}
        </section>
      )}

      {evidence && (
        <section className="space-y-3 rounded-xl border border-sev-critical/40 p-4">
          <p className="text-sm font-semibold">Evidence mentah — hanya tampil sekali. Simpan sekarang lalu rotasi kredensial.</p>
          {evidence.map((e, i) => (
            <div key={i}>
              <p className="text-xs text-muted">{e.path} · HTTP {e.status} · {e.marker}</p>
              <pre className="whitespace-pre-wrap break-all rounded-lg bg-surface p-3 font-mono text-xs">{e.snippet}</pre>
            </div>
          ))}
        </section>
      )}
    </main>
  );
}
