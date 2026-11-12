"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Lock,
  Search,
  RefreshCw,
  Eye,
  Copy,
  Check,
  X,
  ShieldAlert,
  Clock,
  FileJson,
  GitBranch,
  ExternalLink,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { GitIntelReport } from "@/lib/sentinel/git-intel";
import { dossierToMarkdown, type CveDossier } from "@/lib/sentinel/dossier";
import { sensitiveDossierToMarkdown } from "@/lib/sentinel/sensitive-dossier";
import type { SensitiveDossier } from "@/lib/sentinel/sensitive-types";
import { SelfTestPanel } from "./selftest-panel";

interface Item {
  key: string;
  domain: string;
  id: string;
  ttl: number;
}

interface Ev {
  path: string;
  status: number;
  contentType: string;
  marker: string;
  snippet: string;
  domain: string;
  gitIntel?: GitIntelReport;
  cveIntel?: CveDossier;
  sensitiveIntel?: SensitiveDossier;
}

const fmt = (s: number) => `${Math.floor(s / 3600)}j ${Math.floor((s % 3600) / 60)}m`;

export function VaultTable() {
  const [items, setItems] = useState<Item[] | null>(null);
  const [open, setOpen] = useState<{ key: string; ev: Ev } | null>(null);
  const [viewMode, setViewMode] = useState<"json" | "raw">("json");
  const [err, setErr] = useState("");
  const [search, setSearch] = useState("");
  const [copied, setCopied] = useState(false);

  const load = useCallback(async () => {
    const r = await fetch("/api/admin/vault");
    if (r.status === 401) {
      window.location.href = "/admin/login";
      return;
    }
    setItems((await r.json()).items ?? []);
  }, []);

  useEffect(() => {
    load();
  }, [load]);

  async function view(key: string) {
    setErr("");
    const r = await fetch("/api/admin/vault", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ key }),
    });
    const j = await r.json();
    if (!r.ok) return setErr(j.error ?? "Gagal mendekripsi entry");
    setOpen({ key, ev: j.evidence });
    setViewMode("json");
  }

  function copyContent(text: string) {
    try {
      navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // ignore
    }
  }

  const filtered = useMemo(() => {
    if (!items) return [];
    const q = search.trim().toLowerCase();
    if (!q) return items;
    return items.filter(
      (i) => i.domain.toLowerCase().includes(q) || i.id.toLowerCase().includes(q)
    );
  }, [items, search]);

  const formattedJsonString = useMemo(() => {
    if (!open) return "";
    if (open.ev.gitIntel) {
      return JSON.stringify(open.ev.gitIntel, null, 2);
    }
    if (open.ev.cveIntel) {
      return JSON.stringify(open.ev.cveIntel, null, 2);
    }
    if (open.ev.sensitiveIntel) {
      return JSON.stringify(open.ev.sensitiveIntel, null, 2);
    }
    try {
      const parsed = JSON.parse(open.ev.snippet);
      return JSON.stringify(
        {
          vaultKey: open.key,
          domain: open.ev.domain,
          path: open.ev.path,
          httpStatus: open.ev.status,
          marker: open.ev.marker,
          data: parsed,
        },
        null,
        2
      );
    } catch {
      return JSON.stringify(
        {
          vaultKey: open.key,
          domain: open.ev.domain,
          path: open.ev.path,
          httpStatus: open.ev.status,
          contentType: open.ev.contentType,
          marker: open.ev.marker,
          rawSnippet: open.ev.snippet,
        },
        null,
        2
      );
    }
  }, [open]);

  return (
    <section className="space-y-4">
      <SelfTestPanel />
      <div className="rounded-2xl border border-border bg-panel p-5 flex flex-wrap items-center justify-between gap-4">
        <div className="space-y-1">
          <div className="inline-flex items-center gap-1.5 rounded-full bg-pink-500/15 border border-pink-500/30 px-2.5 py-0.5 text-xs font-mono font-bold text-pink-300">
            <Lock className="h-3 w-3" />
            AES-256-GCM · AAD KEY-BOUND · JSON VAULT
          </div>
          <h1 className="text-lg font-extrabold text-foreground">
            Encrypted Evidence &amp; Git Intelligence Vault ({items?.length ?? "…"} item aktif)
          </h1>
          <p className="text-xs text-muted">
            Menyimpan bukti temuan CRITICAL (<code className="text-pink-300">/.git/config</code>,{" "}
            <code className="text-pink-300">/logs/HEAD</code>, <code className="text-pink-300">/.git/refs/heads/main</code>,{" "}
            <code className="text-pink-300">/.env</code>) beserta ekstraksi URL GitHub/GitLab dalam tampilan JSON terstruktur.
          </p>
        </div>

        <div className="flex items-center gap-2.5">
          <div className="relative">
            <Search className="h-3.5 w-3.5 text-muted absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Cari domain / ID..."
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

      {err && (
        <div className="rounded-xl border border-red-500/40 bg-red-500/10 p-3 text-xs text-red-300">
          {err}
        </div>
      )}

      <div className="overflow-x-auto rounded-2xl border border-border bg-panel shadow-xl">
        <table className="w-full text-left text-xs">
          <thead className="border-b border-border bg-sunken font-mono uppercase text-xs text-muted">
            <tr>
              <th className="p-4">Domain Target</th>
              <th className="p-4">Vault Entry ID</th>
              <th className="p-4">Enkripsi &amp; Format</th>
              <th className="p-4">Sisa Masa Aktif (TTL)</th>
              <th className="p-4 text-right">Inspeksi JSON</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-white/[0.06]">
            {filtered.map((i) => (
              <tr key={i.key} className="hover:bg-foreground/[0.03] transition-colors">
                <td className="p-4 font-mono font-bold text-foreground">{i.domain}</td>
                <td className="p-4 font-mono text-purple-300">{i.id}</td>
                <td className="p-4 font-mono">
                  <span className="inline-flex items-center gap-1 rounded-full bg-emerald-500/15 border border-emerald-500/30 px-2.5 py-0.5 text-xs text-emerald-300">
                    <FileJson className="h-3 w-3" />
                    AES-256-GCM · JSON
                  </span>
                </td>
                <td className="p-4 font-mono text-soft">
                  <span className="inline-flex items-center gap-1">
                    <Clock className="h-3.5 w-3.5 text-amber-400" />
                    {fmt(i.ttl)}
                  </span>
                </td>
                <td className="p-4 text-right">
                  <button
                    type="button"
                    onClick={() => view(i.key)}
                    className="inline-flex items-center gap-1.5 rounded-xl border border-purple-500/40 bg-purple-500/15 hover:bg-purple-500/25 px-3.5 py-1.5 font-mono text-xs font-semibold text-purple-200 transition-colors cursor-pointer"
                  >
                    <Eye className="h-3.5 w-3.5" />
                    <span>Decrypt &amp; View JSON</span>
                  </button>
                </td>
              </tr>
            ))}
            {filtered.length === 0 && (
              <tr>
                <td colSpan={5} className="p-10 text-center font-mono text-muted">
                  Vault saat ini kosong atau tidak ada domain yang cocok.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {open && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 grid place-items-center bg-black/75 backdrop-blur-xs p-4"
          onClick={() => setOpen(null)}
        >
          <div
            className="max-h-[88vh] w-full max-w-3xl overflow-auto rounded-2xl border border-purple-500/35 bg-panel p-6 shadow-2xl space-y-4 thin-scroll"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-3 border-b border-border pb-3">
              <div>
                <div className="inline-flex items-center gap-1.5 text-xs font-mono text-red-400 font-bold">
                  <ShieldAlert className="h-3.5 w-3.5" />
                  DECRYPTED VAULT EVIDENCE &amp; GIT REPO JSON (IN-MEMORY ONLY)
                </div>
                <h2 className="text-base font-extrabold text-foreground mt-0.5 break-all">
                  {open.ev.domain}
                  {open.ev.path}
                </h2>
              </div>
              <button
                type="button"
                onClick={() => setOpen(null)}
                className="h-8 w-8 grid place-items-center rounded-full bg-foreground/5 text-muted hover:text-foreground"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {open.ev.sensitiveIntel && (
              <div
                className={cn(
                  "rounded-xl border p-3.5",
                  open.ev.sensitiveIntel.summary.liveSecrets > 0
                    ? "border-red-500/40 bg-red-500/10"
                    : "border-amber-500/35 bg-amber-500/10"
                )}
              >
                <p
                  className={cn(
                    "text-xs font-mono font-bold",
                    open.ev.sensitiveIntel.summary.liveSecrets > 0 ? "text-red-300" : "text-amber-300"
                  )}
                >
                  ⚠ Audit File Sensitif: {open.ev.sensitiveIntel.summary.totalFiles} file ditemukan ·{" "}
                  {open.ev.sensitiveIntel.summary.criticalFiles} CRITICAL ·{" "}
                  {open.ev.sensitiveIntel.summary.liveSecrets} kredensial nyata (live) ·{" "}
                  {open.ev.sensitiveIntel.summary.placeholderSecrets} placeholder
                </p>
                {open.ev.sensitiveIntel.summary.awsAccountIds.length > 0 && (
                  <p className="mt-1 text-xs font-mono text-soft">
                    ID akun AWS (diturunkan offline): {open.ev.sensitiveIntel.summary.awsAccountIds.join(", ")}
                  </p>
                )}
                <ul className="mt-2 space-y-1 text-xs font-mono text-soft max-h-32 overflow-y-auto thin-scroll">
                  {open.ev.sensitiveIntel.entries.slice(0, 12).map((e) => (
                    <li key={e.path} className="flex flex-wrap items-center gap-x-2">
                      <span className={e.severity === "CRITICAL" ? "text-red-300 font-bold" : "text-amber-300 font-bold"}>
                        {e.severity}
                      </span>
                      <span className="text-foreground">{e.path}</span>
                      <span className="text-muted">
                        — {e.analysis.liveCount > 0 ? `${e.analysis.liveCount} nyata` : "tanpa kredensial nyata"}
                        {e.confidence === "existence-only" ? " · indikasi" : ""}
                      </span>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {open.ev.gitIntel?.primaryRepository?.webUrl && (
              <div className="rounded-xl border border-emerald-500/35 bg-emerald-500/10 p-3.5 flex flex-wrap items-center justify-between gap-2">
                <div className="text-xs font-mono">
                  <span className="text-emerald-300 font-bold block">
                    ✓ Repository {open.ev.gitIntel.primaryRepository.provider.toUpperCase()} Ditemukan:
                  </span>
                  <a
                    href={open.ev.gitIntel.primaryRepository.webUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-foreground underline font-bold break-all"
                  >
                    {open.ev.gitIntel.primaryRepository.webUrl}
                  </a>
                </div>
                <a
                  href={open.ev.gitIntel.primaryRepository.webUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-mono font-bold text-white"
                >
                  <GitBranch className="h-3.5 w-3.5" />
                  <span>Buka Repo</span>
                  <ExternalLink className="h-3.5 w-3.5" />
                </a>
              </div>
            )}

            <div className="flex flex-wrap items-center justify-between gap-2 text-xs font-mono text-soft bg-sunken rounded-xl p-3 border border-border">
              <div className="flex items-center gap-2">
                <button
                  type="button"
                  onClick={() => setViewMode("json")}
                  className={cn(
                    "rounded-lg px-3 py-1 font-bold cursor-pointer",
                    viewMode === "json"
                      ? "bg-purple-600 text-white"
                      : "bg-foreground/5 text-soft hover:text-foreground"
                  )}
                >
                  Tampilan JSON
                </button>
                <button
                  type="button"
                  onClick={() => setViewMode("raw")}
                  className={cn(
                    "rounded-lg px-3 py-1 font-bold cursor-pointer",
                    viewMode === "raw"
                      ? "bg-purple-600 text-white"
                      : "bg-foreground/5 text-soft hover:text-foreground"
                  )}
                >
                  Raw Evidence
                </button>
              </div>
              {open.ev.cveIntel && (
                <button
                  type="button"
                  onClick={() => {
                    const d = open.ev.cveIntel!;
                    const blob = new Blob([dossierToMarkdown(d)], { type: "text/markdown;charset=utf-8" });
                    const a = document.createElement("a");
                    a.href = URL.createObjectURL(blob);
                    a.download = `laporan-${d.domain}-${new Date(d.generatedAt).toISOString().slice(0, 10)}.md`;
                    a.click();
                    URL.revokeObjectURL(a.href);
                  }}
                  className="inline-flex items-center gap-1 rounded-lg bg-amber-500/20 px-3 py-1 font-bold text-amber-300 hover:bg-amber-500/30 cursor-pointer"
                >
                  <FileJson className="h-3.5 w-3.5" />
                  Export laporan (.md)
                </button>
              )}
              {open.ev.sensitiveIntel && (
                <button
                  type="button"
                  onClick={() => {
                    const d = open.ev.sensitiveIntel!;
                    const blob = new Blob([sensitiveDossierToMarkdown(d)], { type: "text/markdown;charset=utf-8" });
                    const a = document.createElement("a");
                    a.href = URL.createObjectURL(blob);
                    a.download = `laporan-file-sensitif-${d.domain}-${new Date(d.generatedAt).toISOString().slice(0, 10)}.md`;
                    a.click();
                    URL.revokeObjectURL(a.href);
                  }}
                  className="inline-flex items-center gap-1 rounded-lg bg-red-500/20 px-3 py-1 font-bold text-red-300 hover:bg-red-500/30 cursor-pointer"
                >
                  <FileJson className="h-3.5 w-3.5" />
                  Export laporan (.md)
                </button>
              )}
              <button
                type="button"
                onClick={() =>
                  copyContent(viewMode === "json" ? formattedJsonString : open.ev.snippet)
                }
                className="inline-flex items-center gap-1 text-emerald-400 hover:text-emerald-300 cursor-pointer"
              >
                {copied ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                {copied ? "Tersalin" : "Salin"}
              </button>
            </div>

            <pre className="whitespace-pre-wrap break-all rounded-xl bg-sunken border border-border p-4 font-mono text-xs text-emerald-300 max-h-96 overflow-y-auto thin-scroll">
              {viewMode === "json" ? formattedJsonString : open.ev.snippet}
            </pre>
          </div>
        </div>
      )}
    </section>
  );
}
