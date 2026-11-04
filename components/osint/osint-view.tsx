"use client";

import { useState } from "react";
import {
  Search, Loader2, Globe, Mail, AtSign, User, ExternalLink, CheckCircle2, XCircle, HelpCircle, Hand,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import type { OsintLink, OsintResult, OsintType, PlatformStatus } from "@/lib/osint/types";

const MODES: { id: OsintType; label: string; icon: typeof Globe; placeholder: string }[] = [
  { id: "username", label: "Username", icon: AtSign, placeholder: "contoh: johndoe" },
  { id: "email", label: "Email", icon: Mail, placeholder: "contoh: nama@domain.com" },
  { id: "domain", label: "Domain", icon: Globe, placeholder: "contoh: example.com" },
  { id: "name", label: "Nama", icon: User, placeholder: "contoh: Budi Santoso" },
];

const STATUS: Record<PlatformStatus, { label: string; cls: string; icon: typeof Globe }> = {
  found: { label: "Ditemukan", cls: "text-emerald-400 border-emerald-500/30 bg-emerald-500/10", icon: CheckCircle2 },
  not_found: { label: "Tidak ada", cls: "text-slate-400 border-white/10 bg-white/[0.03]", icon: XCircle },
  unknown: { label: "Tidak pasti", cls: "text-amber-400 border-amber-500/30 bg-amber-500/10", icon: HelpCircle },
  manual: { label: "Cek manual", cls: "text-purple-300 border-purple-500/30 bg-purple-500/10", icon: Hand },
};

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-xl border border-white/[0.06] bg-[#120e1b] p-5 space-y-3">
      <div className="text-xs font-mono tracking-widest uppercase text-purple-300/80 font-semibold">{title}</div>
      {children}
    </div>
  );
}

function Mono({ items, empty = "—" }: { items: string[]; empty?: string }) {
  if (!items.length) return <div className="text-xs font-mono text-slate-500">{empty}</div>;
  return (
    <ul className="space-y-1 text-xs font-mono text-slate-300 break-all">
      {items.map((i) => (
        <li key={i}>{i}</li>
      ))}
    </ul>
  );
}

function Links({ links }: { links: OsintLink[] }) {
  const groups = Array.from(new Set(links.map((l) => l.group ?? "Lainnya")));
  return (
    <div className="space-y-3">
      {groups.map((g) => (
        <div key={g}>
          <div className="text-[10px] font-mono uppercase tracking-wider text-white/30 mb-1.5">{g}</div>
          <div className="flex flex-wrap gap-2">
            {links
              .filter((l) => (l.group ?? "Lainnya") === g)
              .map((l) => (
                <a
                  key={l.url}
                  href={l.url}
                  target={l.url.startsWith("/") ? undefined : "_blank"}
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.02] px-3 py-1 text-xs font-mono text-slate-300 hover:border-purple-500/40 hover:text-purple-200 transition-colors"
                >
                  {l.label}
                  <ExternalLink className="h-3 w-3 opacity-50" />
                </a>
              ))}
          </div>
        </div>
      ))}
    </div>
  );
}

function ResultView({ r }: { r: OsintResult }) {
  if (r.type === "username") {
    const found = r.platforms.filter((p) => p.status === "found").length;
    return (
      <Card title={`Username @${r.username} — ${found} ditemukan`}>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {r.platforms.map((p) => {
            const s = STATUS[p.status];
            const Icon = s.icon;
            return (
              <a
                key={p.platform}
                href={p.url}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center justify-between gap-3 rounded-lg border border-white/[0.06] bg-white/[0.02] px-3 py-2 hover:border-purple-500/30 transition-colors"
              >
                <div className="min-w-0">
                  <div className="text-sm text-white">{p.platform}</div>
                  {p.note && <div className="text-[10px] font-mono text-slate-500">{p.note}</div>}
                </div>
                <span className={cn("inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-mono shrink-0", s.cls)}>
                  <Icon className="h-3 w-3" /> {s.label}
                </span>
              </a>
            );
          })}
        </div>
        <p className="text-[11px] font-mono text-slate-500">
          &quot;Ditemukan&quot; hanya berarti halaman profil publik dengan username itu ada — belum tentu orang yang
          sama. Verifikasi manual sebelum menyimpulkan apa pun.
        </p>
      </Card>
    );
  }

  if (r.type === "email") {
    return (
      <div className="space-y-4">
        <Card title={`Email ${r.email}`}>
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs font-mono">
            <div>
              <div className="text-slate-500">Domain</div>
              <div className="text-slate-200">{r.domain}</div>
            </div>
            <div>
              <div className="text-slate-500">Bisa terima email (MX)</div>
              <div className={r.mx.length ? "text-emerald-400" : "text-red-400"}>{r.mx.length ? "Ya" : "Tidak ada MX"}</div>
            </div>
            <div>
              <div className="text-slate-500">Email sekali pakai</div>
              <div className={r.disposable ? "text-amber-400" : "text-slate-200"}>{r.disposable ? "Ya" : "Tidak"}</div>
            </div>
          </div>
          <div className="flex items-center gap-3 pt-1">
            {r.gravatar.exists ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img src={`${r.gravatar.url}?s=64&d=404`} alt="Gravatar" width={48} height={48} className="rounded-full border border-white/10" />
            ) : null}
            <div className="text-xs font-mono text-slate-300">
              Gravatar: {r.gravatar.exists ? "ada profil publik" : "tidak ada"}
            </div>
          </div>
          <Mono items={r.mx} empty="Tidak ada record MX" />
        </Card>
        <Card title="Sumber publik">
          <Links links={r.links} />
        </Card>
      </div>
    );
  }

  if (r.type === "domain") {
    return (
      <div className="space-y-4">
        <Card title={`Domain ${r.domain}`}>
          {r.rdap ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs font-mono">
              <div><div className="text-slate-500">Registrar</div><div className="text-slate-200">{r.rdap.registrar ?? "—"}</div></div>
              <div><div className="text-slate-500">Dibuat</div><div className="text-slate-200">{r.rdap.created?.slice(0, 10) ?? "—"}</div></div>
              <div><div className="text-slate-500">Kedaluwarsa</div><div className="text-slate-200">{r.rdap.expires?.slice(0, 10) ?? "—"}</div></div>
              <div><div className="text-slate-500">Status</div><div className="text-slate-200">{r.rdap.status?.join(", ") ?? "—"}</div></div>
            </div>
          ) : (
            <div className="text-xs font-mono text-slate-500">Data RDAP tidak tersedia untuk TLD ini.</div>
          )}
        </Card>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card title="A / AAAA"><Mono items={[...r.dns.a, ...r.dns.aaaa]} /></Card>
          <Card title="NS"><Mono items={r.dns.ns} /></Card>
          <Card title="MX"><Mono items={r.dns.mx} /></Card>
          <Card title="TXT"><Mono items={r.dns.txt} /></Card>
        </div>
        <Card title={`Subdomain dari Certificate Transparency (${r.subdomains.length})`}>
          <Mono items={r.subdomains} empty="Tidak ada data dari crt.sh" />
        </Card>
        <Card title="Sumber publik"><Links links={r.links} /></Card>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      <Card title={`Nama: ${r.name}`}>
        <p className="text-[11px] font-mono text-slate-500">
          Nama tidak punya sumber data tunggal. Tombol di bawah membuka pencarian publik di tab baru — tidak ada
          scraping dan hasilnya harus dinilai sendiri (nama sama ≠ orang sama).
        </p>
        <div className="text-[10px] font-mono uppercase tracking-wider text-white/30">Tebakan username</div>
        <Mono items={r.usernameGuesses} />
      </Card>
      <Card title="Pencarian publik"><Links links={r.links} /></Card>
    </div>
  );
}

export function OsintView() {
  const [mode, setMode] = useState<OsintType>("username");
  const [value, setValue] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<OsintResult | null>(null);
  const [agreed, setAgreed] = useState(false);

  const current = MODES.find((m) => m.id === mode)!;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (loading || !value.trim() || !agreed) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch(`/api/osint?type=${mode}&q=${encodeURIComponent(value.trim())}`);
      const json = (await res.json()) as { ok: boolean; error?: string; result?: OsintResult };
      if (!json.ok || !json.result) setError(json.error ?? "Gagal memproses.");
      else setResult(json.result);
    } catch {
      setError("Tidak bisa menghubungi layanan. Coba lagi.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="w-full min-h-full">
      <div className="mx-auto max-w-4xl px-6 lg:px-8 py-10 space-y-6">
        <div className="space-y-2">
          <div className="inline-flex items-center px-3 py-1 rounded-md bg-purple-500/10 border border-purple-500/20 text-xs font-mono tracking-[0.2em] uppercase text-purple-400">
            $ OSINT --PUBLIC
          </div>
          <h1 className="text-3xl font-extrabold text-white">OSINT Lookup</h1>
          <p className="text-sm text-slate-400">
            Cari jejak digital dari sumber data publik saja: username (Instagram, TikTok, Facebook, dll), email, domain,
            dan nama.
          </p>
        </div>

        <div className="rounded-2xl border border-white/10 bg-[#130f1d] p-5 space-y-4">
          <div className="flex flex-wrap rounded-xl border border-white/10 bg-black/20 p-1 gap-1">
            {MODES.map((m) => (
              <button
                key={m.id}
                type="button"
                onClick={() => { setMode(m.id); setResult(null); setError(null); }}
                className={cn(
                  "flex-1 inline-flex items-center justify-center gap-2 rounded-lg px-3 py-2 text-xs font-mono transition-colors",
                  mode === m.id ? "bg-[#2a1842] text-white border border-purple-500/20" : "text-white/50 hover:text-white"
                )}
              >
                <m.icon className="h-4 w-4" /> {m.label}
              </button>
            ))}
          </div>

          <form onSubmit={submit} className="space-y-3">
            <Input value={value} onChange={(e) => setValue(e.target.value)} placeholder={current.placeholder} disabled={loading} />
            <label className="flex items-start gap-2 text-[11px] font-mono text-slate-400 cursor-pointer">
              <input type="checkbox" checked={agreed} onChange={(e) => setAgreed(e.target.checked)} className="mt-0.5" />
              <span>
                Saya memakai ini secara sah (diri sendiri, izin tertulis, riset/jurnalistik/keamanan) dan tidak untuk
                menguntit, melecehkan, atau membuka data pribadi orang lain.
              </span>
            </label>
            <Button type="submit" disabled={loading || !value.trim() || !agreed} className="w-full">
              {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              {loading ? "Mencari..." : "Cari"}
            </Button>
          </form>
        </div>

        {error && (
          <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-xs font-mono text-red-300">{error}</div>
        )}
        {result && <ResultView r={result} />}

        <div className="text-[11px] font-mono text-slate-500 bg-white/[0.02] border border-white/[0.04] p-3 rounded-lg">
          Hanya data publik · tanpa login/bypass · maks 10 request/menit · hasil bukan bukti identitas.
        </div>
      </div>
    </div>
  );
}
