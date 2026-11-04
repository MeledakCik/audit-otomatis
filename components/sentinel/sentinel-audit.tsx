"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  KeyRound,
  CheckCircle2,
  Clock,
  AlertTriangle,
  Copy,
  Check,
  RefreshCw,
  FileCode2,
  Server,
  Sparkles,
  Eye,
} from "lucide-react";
import { cn } from "@/lib/utils";

export interface SentinelFinding {
  domain: string;
  severity: "CRITICAL" | "HIGH";
  finding: string;
  evidence_public: string;
  fix: string;
}

export interface SentinelPub {
  domain: string;
  scannedAt: number;
  findings: SentinelFinding[];
}

export interface SentinelClaim {
  status: string;
  domain?: string;
  challenge?: string;
  viewToken?: string;
  viewTokenExp?: number;
  proof?: { method: string; verifiedAt: number };
  instructions?: {
    dns: { type?: string; name: string; value: string };
    file: { url: string; content: string };
  };
}

export interface SentinelEvidence {
  path: string;
  status: number;
  contentType?: string;
  marker: string;
  snippet: string;
}

const post = (url: string, body: unknown) =>
  fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

export function SentinelAudit({
  initialDomain = "",
  embedded = false,
  autoLoadPublic = false,
}: {
  initialDomain?: string;
  embedded?: boolean;
  autoLoadPublic?: boolean;
}) {
  const [domain, setDomain] = useState(initialDomain);
  const [busy, setBusy] = useState(false);
  const [claimBusy, setClaimBusy] = useState(false);
  const [err, setErr] = useState("");
  const [res, setRes] = useState<SentinelPub | null>(null);
  const [claim, setClaim] = useState<SentinelClaim | null>(null);
  const [evidence, setEvidence] = useState<SentinelEvidence[] | null>(null);
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const poll = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (initialDomain && initialDomain !== domain) {
      setDomain(initialDomain);
    }
  }, [initialDomain, domain]);

  useEffect(() => () => {
    if (poll.current) clearInterval(poll.current);
  }, []);

  const watch = useCallback((d: string) => {
    if (poll.current) clearInterval(poll.current);
    poll.current = setInterval(async () => {
      try {
        const c: SentinelClaim = await fetch(`/api/sentinel/claim?domain=${encodeURIComponent(d)}`).then((x) =>
          x.json()
        );
        setClaim(c);
        if (c.viewToken) {
          clearInterval(poll.current!);
          const v = await fetch(`/api/sentinel/view/${c.viewToken}`);
          if (v.ok) {
            const data = await v.json();
            setEvidence(data.evidence ?? []);
          } else {
            setErr("Token one-time sudah dipakai / kedaluwarsa — minta Admin ACC ulang.");
          }
        } else if (["REJECTED", "VIEWED"].includes(c.status)) {
          clearInterval(poll.current!);
        }
      } catch {
        // ignore network blip during poll
      }
    }, 5000);
  }, []);

  // Auto-load public Sentinel findings & claim status when initialDomain is provided (e.g. inside /scan/[id])
  useEffect(() => {
    if (!initialDomain || !autoLoadPublic) return;
    let cancelled = false;
    (async () => {
      try {
        const clean = initialDomain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
        const [pubRes, claimRes] = await Promise.all([
          fetch(`/api/sentinel/public/${encodeURIComponent(clean)}`),
          fetch(`/api/sentinel/claim?domain=${encodeURIComponent(clean)}`),
        ]);
        if (!cancelled && pubRes.ok) {
          const pubData = (await pubRes.json()) as SentinelPub;
          setRes(pubData);
        }
        if (!cancelled && claimRes.ok) {
          const claimData = (await claimRes.json()) as SentinelClaim;
          if (claimData.status && claimData.status !== "NONE") {
            setClaim(claimData);
            watch(clean);
          }
        }
      } catch {
        // ignore if no public record yet
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [initialDomain, autoLoadPublic, watch]);

  async function runAudit(targetDomain?: string) {
    const d = (targetDomain ?? domain).trim();
    if (!d) return;
    setBusy(true);
    setErr("");
    setEvidence(null);
    try {
      const r = await post("/api/sentinel/audit", { domain: d });
      const j = await r.json();
      setBusy(false);
      if (!r.ok) {
        setErr(j.error ?? "Audit gagal");
        return;
      }
      setRes(j);
      const c = await fetch(`/api/sentinel/claim?domain=${encodeURIComponent(j.domain)}`).then((x) => x.json());
      if (c.status && c.status !== "NONE") {
        setClaim(c);
        watch(j.domain);
      }
    } catch {
      setBusy(false);
      setErr("Gagal menghubungi server Sentinel Audit.");
    }
  }

  async function onSubmitForm(e: React.FormEvent) {
    e.preventDefault();
    await runAudit(domain);
  }

  async function claimStart() {
    const targetDom = res?.domain || domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!targetDom) return;
    setClaimBusy(true);
    setErr("");
    try {
      const r = await post("/api/sentinel/claim", { domain: targetDom, action: "start" });
      const j = await r.json();
      if (!r.ok) setErr(j.error ?? "Gagal memulai klaim domain");
      else setClaim(j);
    } finally {
      setClaimBusy(false);
    }
  }

  async function claimSubmit() {
    const targetDom = res?.domain || claim?.domain || domain.trim().toLowerCase();
    if (!targetDom) return;
    setClaimBusy(true);
    setErr("");
    try {
      const r = await post("/api/sentinel/claim", { domain: targetDom, action: "submit" });
      const j = await r.json();
      if (!r.ok) {
        setErr(j.error ?? "Verifikasi gagal");
      } else {
        setClaim(j);
        watch(targetDom);
      }
    } finally {
      setClaimBusy(false);
    }
  }

  function copyText(key: string, val: string) {
    try {
      navigator.clipboard.writeText(val);
      setCopiedField(key);
      setTimeout(() => setCopiedField(null), 2000);
    } catch {
      // ignore
    }
  }

  const critCount = res?.findings.filter((f) => f.severity === "CRITICAL").length ?? 0;
  const highCount = res?.findings.filter((f) => f.severity === "HIGH").length ?? 0;

  return (
    <div className={cn("w-full space-y-5", !embedded && "mx-auto max-w-4xl p-4 md:p-8")}>
      {/* Header Banner */}
      <div className="rounded-2xl border border-purple-500/25 bg-gradient-to-br from-[#171126] via-[#120d1e] to-[#0d0917] p-5 shadow-xl">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="space-y-1.5">
            <div className="inline-flex items-center gap-2 rounded-full bg-purple-500/15 border border-purple-500/30 px-3 py-0.5 text-[11px] font-mono font-semibold text-purple-300">
              <Lock className="h-3 w-3 text-purple-400" />
              SENTINEL VAULT AUDIT &amp; DOMAIN OWNERSHIP CLAIM
            </div>
            <h2 className="text-lg sm:text-xl font-extrabold text-white tracking-tight">
              Audit File Sensitif &amp; Brankas Bukti Terenkripsi (AES-256-GCM)
            </h2>
            <p className="text-xs text-slate-300/85 max-w-2xl leading-relaxed">
              Mendeteksi kebocoran kritis (<code className="text-purple-300">.env</code>,{" "}
              <code className="text-purple-300">.git/HEAD</code>, <code className="text-purple-300">backup.zip</code>,{" "}
              <code className="text-purple-300">wp-config.php.bak</code>, <code className="text-purple-300">AWS keys</code>) secara pasif. Nilai rahasia tidak pernah bocor ke publik dan disimpan terenkripsi di Vault Admin untuk diklaim pemilik sah domain.
            </p>
          </div>

          {initialDomain && (
            <button
              type="button"
              onClick={() => runAudit(initialDomain)}
              disabled={busy}
              className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 px-4 py-2.5 text-xs font-bold text-white shadow-lg shadow-purple-600/25 disabled:opacity-50 cursor-pointer shrink-0"
            >
              <RefreshCw className={cn("h-3.5 w-3.5", busy && "animate-spin")} />
              {busy ? "Memindai Vault…" : res ? "Scan Ulang Sentinel Vault" : "Jalankan Audit Vault Sekarang"}
            </button>
          )}
        </div>

        {/* Form Input (shown when not locked to initialDomain or when user wants to input domain) */}
        {!initialDomain && (
          <form onSubmit={onSubmitForm} className="mt-4 flex flex-col sm:flex-row gap-2.5">
            <div className="relative flex-1">
              <Server className="h-4 w-4 text-purple-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
              <input
                className="w-full h-11 rounded-xl border border-white/15 bg-black/40 pl-10 pr-4 text-sm text-white placeholder:text-slate-500 outline-none focus:border-purple-400"
                placeholder="Masukkan domain target (contoh: sentinel-id.net)"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                required
              />
            </div>
            <button
              type="submit"
              disabled={busy}
              className="h-11 rounded-xl bg-gradient-to-r from-purple-600 to-pink-600 hover:from-purple-500 hover:to-pink-500 px-6 text-xs font-bold uppercase tracking-wider text-white shadow-lg shadow-purple-600/25 disabled:opacity-50 cursor-pointer shrink-0"
            >
              {busy ? "Scanning Vault…" : "Audit & Simpan ke Vault →"}
            </button>
          </form>
        )}

        {err && (
          <div
            role="alert"
            className="mt-3 flex items-center gap-2 rounded-xl border border-red-500/40 bg-red-500/10 px-3.5 py-2.5 text-xs text-red-300"
          >
            <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
            <span>{err}</span>
          </div>
        )}
      </div>

      {/* Findings & Claim Section */}
      {res && (
        <div className="space-y-4 animate-fade-up">
          {/* Summary Bar */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="rounded-xl border border-white/10 bg-[#130e20] p-4 flex items-center justify-between">
              <div>
                <div className="text-[11px] font-mono uppercase tracking-wider text-slate-400">Domain Target</div>
                <div className="text-sm font-bold text-white mt-0.5 truncate">{res.domain}</div>
              </div>
              <ShieldCheck className="h-5 w-5 text-purple-400 shrink-0" />
            </div>

            <div className="rounded-xl border border-red-500/25 bg-red-500/[0.06] p-4 flex items-center justify-between">
              <div>
                <div className="text-[11px] font-mono uppercase tracking-wider text-red-300/80">
                  Critical (Terenkripsi di Vault)
                </div>
                <div className="text-xl font-extrabold text-red-400 mt-0.5 tabular-nums">{critCount}</div>
              </div>
              <Lock className="h-5 w-5 text-red-400 shrink-0" />
            </div>

            <div className="rounded-xl border border-amber-500/25 bg-amber-500/[0.06] p-4 flex items-center justify-between">
              <div>
                <div className="text-[11px] font-mono uppercase tracking-wider text-amber-300/80">
                  High Severity Posture
                </div>
                <div className="text-xl font-extrabold text-amber-400 mt-0.5 tabular-nums">{highCount}</div>
              </div>
              <ShieldAlert className="h-5 w-5 text-amber-400 shrink-0" />
            </div>
          </div>

          {/* Findings List */}
          {res.findings.length === 0 ? (
            <div className="rounded-2xl border border-emerald-500/25 bg-emerald-500/[0.06] p-5 flex items-center gap-3.5">
              <CheckCircle2 className="h-6 w-6 text-emerald-400 shrink-0" />
              <div>
                <div className="text-sm font-bold text-emerald-300">
                  Aman — Tidak Ditemukan Eksposur File Rahasia pada Audit Pasif Ini
                </div>
                <p className="text-xs text-slate-300/80 mt-0.5">
                  Tidak ada marker kredensial terbuka (<code className="font-mono">.env</code>,{" "}
                  <code className="font-mono">.git</code>, <code className="font-mono">backup.zip</code>) yang terdeteksi pada {res.domain}.
                </p>
              </div>
            </div>
          ) : (
            <div className="space-y-2.5">
              {res.findings.map((f, i) => {
                const isCrit = f.severity === "CRITICAL";
                return (
                  <article
                    key={i}
                    className={cn(
                      "rounded-xl border p-4 transition-all",
                      isCrit
                        ? "border-red-500/35 bg-gradient-to-r from-red-950/30 via-[#140e20] to-[#140e20]"
                        : "border-white/10 bg-[#130e20]"
                    )}
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span
                          className={cn(
                            "inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-[10px] font-mono font-bold uppercase tracking-wider",
                            isCrit
                              ? "bg-red-500/20 text-red-300 border border-red-500/40"
                              : "bg-amber-500/20 text-amber-300 border border-amber-500/40"
                          )}
                        >
                          {f.severity}
                        </span>
                        <h3 className="text-sm font-bold text-white">{f.finding}</h3>
                      </div>
                      {isCrit && (
                        <span className="inline-flex items-center gap-1 text-[11px] font-mono text-purple-300 bg-purple-500/15 border border-purple-500/30 px-2.5 py-0.5 rounded-full">
                          <Lock className="h-3 w-3" /> Tersimpan di Admin Vault (24j)
                        </span>
                      )}
                    </div>
                    <p className="mt-2 text-xs font-mono text-slate-300 bg-black/30 rounded-lg px-3 py-2 border border-white/[0.06]">
                      Evidence Publik: {f.evidence_public}
                    </p>
                    <p className="mt-2 text-xs text-slate-300">
                      <strong className="text-emerald-400">Rekomendasi Fix:</strong> {f.fix}
                    </p>
                  </article>
                );
              })}
            </div>
          )}

          {/* Domain Ownership Claim Call-To-Action */}
          <div className="rounded-2xl border border-purple-500/30 bg-[#140f23] p-5 space-y-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-sm font-bold text-white">
                  <KeyRound className="h-4 w-4 text-purple-400" />
                  <span>Verifikasi Kepemilikan Domain &amp; Akses Bukti Mentah (Vault)</span>
                </div>
                <p className="text-xs text-slate-400">
                  Pemilik sah domain <strong>{res.domain}</strong> dapat membuktikan kepemilikan via DNS TXT atau file HTTP untuk meminta persetujuan Admin membuka snippet bukti mentah (1x lihat).
                </p>
              </div>

              {(!claim || claim.status === "NONE") && (
                <button
                  type="button"
                  onClick={claimStart}
                  disabled={claimBusy}
                  className="inline-flex items-center gap-2 rounded-xl border border-purple-400/40 bg-purple-500/20 hover:bg-purple-500/30 px-4 py-2 text-xs font-bold text-purple-200 transition-all cursor-pointer shrink-0"
                >
                  <Sparkles className="h-3.5 w-3.5 text-purple-300" />
                  {claimBusy ? "Memproses…" : "Saya Pemilik Domain"}
                </button>
              )}
            </div>

            {/* Active Claim Flow */}
            {claim && claim.status !== "NONE" && (
              <div className="rounded-xl border border-white/10 bg-black/30 p-4 space-y-4">
                <div className="flex flex-wrap items-center justify-between gap-2 border-b border-white/10 pb-3">
                  <div className="flex items-center gap-2 text-xs font-mono">
                    <span className="text-slate-400">Status Klaim:</span>
                    <span
                      className={cn(
                        "rounded-full px-2.5 py-0.5 font-bold",
                        claim.status === "APPROVED" || claim.status === "VIEWED"
                          ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/30"
                          : claim.status === "PENDING"
                          ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                          : claim.status === "REJECTED"
                          ? "bg-red-500/20 text-red-300 border border-red-500/30"
                          : "bg-purple-500/20 text-purple-300 border border-purple-500/30"
                      )}
                    >
                      {claim.status}
                    </span>
                  </div>
                  <span className="text-[11px] font-mono text-slate-400">
                    Auto-polling status setiap 5 detik
                  </span>
                </div>

                {claim.status === "AWAITING_PROOF" && claim.instructions && (
                  <div className="space-y-3">
                    <p className="text-xs text-slate-300">
                      Pilih <strong>salah satu</strong> metode verifikasi di bawah ini, lalu klik tombol verifikasi:
                    </p>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {/* Method 1: DNS TXT */}
                      <div className="rounded-xl border border-white/10 bg-[#120d1d] p-3.5 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-purple-300">Opsi 1 — DNS TXT Record</span>
                          <button
                            type="button"
                            onClick={() => copyText("dns", claim.instructions!.dns.value)}
                            className="inline-flex items-center gap-1 text-[11px] font-mono text-purple-300 hover:text-white"
                          >
                            {copiedField === "dns" ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                            {copiedField === "dns" ? "Tersalin" : "Salin Value"}
                          </button>
                        </div>
                        <div className="text-[11px] font-mono text-slate-400">
                          Host/Name: <code className="text-white">{claim.instructions.dns.name}</code>
                        </div>
                        <div className="rounded-lg bg-black/50 p-2 font-mono text-[11px] text-emerald-300 break-all border border-white/5">
                          {claim.instructions.dns.value}
                        </div>
                      </div>

                      {/* Method 2: HTTP File */}
                      <div className="rounded-xl border border-white/10 bg-[#120d1d] p-3.5 space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-xs font-bold text-sky-300">Opsi 2 — Upload File TXT</span>
                          <button
                            type="button"
                            onClick={() => copyText("file", claim.instructions!.file.content)}
                            className="inline-flex items-center gap-1 text-[11px] font-mono text-sky-300 hover:text-white"
                          >
                            {copiedField === "file" ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                            {copiedField === "file" ? "Tersalin" : "Salin Isi"}
                          </button>
                        </div>
                        <div className="text-[11px] font-mono text-slate-400 break-all">
                          URL: <code className="text-white">{claim.instructions.file.url}</code>
                        </div>
                        <div className="rounded-lg bg-black/50 p-2 font-mono text-[11px] text-sky-300 break-all border border-white/5">
                          {claim.instructions.file.content}
                        </div>
                      </div>
                    </div>

                    <button
                      type="button"
                      onClick={claimSubmit}
                      disabled={claimBusy}
                      className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 px-5 py-2.5 text-xs font-bold text-white shadow-lg shadow-emerald-600/20 disabled:opacity-50 cursor-pointer"
                    >
                      <CheckCircle2 className="h-4 w-4" />
                      {claimBusy ? "Memverifikasi Bukti…" : "Verifikasi Bukti & Kirim ke Admin"}
                    </button>
                  </div>
                )}

                {claim.status === "PENDING" && (
                  <div className="flex items-center gap-3 text-xs text-amber-300 bg-amber-500/10 border border-amber-500/25 rounded-xl p-3.5">
                    <Clock className="h-4 w-4 shrink-0 animate-pulse" />
                    <div>
                      <strong>Bukti kepemilikan terverifikasi!</strong> Permintaan Anda telah masuk ke antrean Admin. Halaman ini otomatis memuat evidence begitu Admin melakukan <strong>ACC</strong>.
                    </div>
                  </div>
                )}

                {claim.status === "REJECTED" && (
                  <div className="flex items-center gap-3 text-xs text-red-300 bg-red-500/10 border border-red-500/25 rounded-xl p-3.5">
                    <AlertTriangle className="h-4 w-4 shrink-0" />
                    <span>Permintaan klaim kepemilikan domain ditolak oleh Admin.</span>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* One-Time Decrypted Evidence Display */}
      {evidence && (
        <section className="space-y-3 rounded-2xl border border-red-500/40 bg-gradient-to-b from-red-950/30 to-[#120d1e] p-5 animate-fade-up">
          <div className="flex items-center gap-2 text-red-300 font-bold text-sm">
            <Eye className="h-4 w-4 text-red-400" />
            <span>Evidence Mentah Terdekripsi (One-Time View — Hanya Tampil Sekali!)</span>
          </div>
          <p className="text-xs text-slate-300">
            Token akses sekali pakai telah dikonsumsi dan dihapus secara atomik (<code className="font-mono">GETDEL</code>) dari Redis. Segera salin informasi yang diperlukan dan rotasi kredensial Anda.
          </p>
          <div className="space-y-3 pt-1">
            {evidence.map((e, i) => (
              <div key={i} className="rounded-xl border border-white/10 bg-black/50 p-3.5 space-y-2">
                <div className="flex items-center justify-between text-xs font-mono text-purple-300">
                  <span>
                    <FileCode2 className="inline h-3.5 w-3.5 mr-1" />
                    {e.path} · HTTP {e.status} · Marker: <b>{e.marker}</b>
                  </span>
                  <button
                    type="button"
                    onClick={() => copyText(`ev_${i}`, e.snippet)}
                    className="inline-flex items-center gap-1 text-[11px] text-emerald-400 hover:text-emerald-300"
                  >
                    {copiedField === `ev_${i}` ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                    {copiedField === `ev_${i}` ? "Tersalin" : "Salin Snippet"}
                  </button>
                </div>
                <pre className="whitespace-pre-wrap break-all rounded-lg bg-[#090610] p-3 font-mono text-xs text-slate-200 border border-white/5 max-h-60 overflow-y-auto thin-scroll">
                  {e.snippet}
                </pre>
              </div>
            ))}
          </div>
        </section>
      )}
    </div>
  );
}
