"use client";

import { useMemo, useState } from "react";
import { AlertTriangle, CheckCircle2, ExternalLink, Loader2, Radar, Send, ShieldCheck, XCircle } from "lucide-react";
import { RiskBadge } from "@/components/subdomain-watch/risk-badge";
import type { TakeoverRisk } from "@/lib/subdomain-watch/types";

type LiveRow = {
  host: string;
  statusCode: number | null;
  responseTimeMs: number | null;
  title: string | null;
  server: string | null;
  tlsVersion: string | null;
  csp: boolean;
  hsts: boolean;
  frameProtection: boolean;
  nosniff: boolean;
  fileForms: Array<{ endpoint: string; fields: string[] }>;
  cname: string | null;
  takeoverRisk: TakeoverRisk;
  takeoverReason: string | null;
  edgeChallenge: boolean;
  honeypotSignal: boolean;
  error?: "unreachable" | "non_public";
};

type AuditReport = {
  domain: string;
  source: string;
  totalFound: number;
  checked: number;
  truncated: boolean;
  rows: LiveRow[];
};

type PostResult = {
  method: "POST";
  url: string;
  statusCode: number;
  accepted: boolean;
  responseTimeMs: number;
  responseContentType: string;
  responsePreview: string;
  responseTruncated: boolean;
  bodyEchoed: boolean;
  honeypotSignal: boolean;
  edgeChallenge: boolean;
  classification: "honeypot_signal" | "edge_challenge" | "application_response" | "rejected_or_error";
  note: string;
};

const headerState = (pass: boolean, label: string) => (
  <span key={label} className={pass ? "text-ok" : "text-warn"}>{label} {pass ? "✓" : "·"}</span>
);

export function SubdomainLiveAudit({ domain }: { domain: string }) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [report, setReport] = useState<AuditReport | null>(null);
  const [curl, setCurl] = useState("");
  const [postBusy, setPostBusy] = useState(false);
  const [postError, setPostError] = useState("");
  const [postResult, setPostResult] = useState<PostResult | null>(null);

  const liveCount = useMemo(() => report?.rows.filter((row) => row.statusCode !== null).length ?? 0, [report]);

  async function runAudit() {
    if (!domain.trim() || busy) return;
    setBusy(true);
    setError("");
    setPostResult(null);
    try {
      const response = await fetch("/api/admin/subdomain-audit", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
        signal: AbortSignal.timeout(300000),
      });
      if (response.status === 401) return window.location.replace("/admin/login");
      const data = await response.json();
      if (!response.ok) {
        setError(data.error ?? "Audit subdomain gagal.");
        return;
      }
      setReport(data as AuditReport);
    } catch {
      setError("Audit melewati batas waktu atau server tidak merespons.");
    } finally {
      setBusy(false);
    }
  }

  async function replayPost() {
    if (!report || !curl.trim() || postBusy) return;
    setPostBusy(true);
    setPostError("");
    setPostResult(null);
    try {
      const response = await fetch("/api/admin/curl-post", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: report.domain, command: curl }),
        signal: AbortSignal.timeout(20000),
      });
      if (response.status === 401) return window.location.replace("/admin/login");
      const data = await response.json();
      if (!response.ok) {
        setPostError(data.error ?? "Replay POST ditolak.");
        return;
      }
      setPostResult(data as PostResult);
    } catch {
      setPostError("Server admin gagal merespons.");
    } finally {
      setPostBusy(false);
    }
  }

  return (
    <section className="rounded-2xl border border-border bg-panel p-4 sm:p-5 space-y-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="flex items-start gap-3">
          <div className="grid size-10 shrink-0 place-items-center rounded-xl border border-border bg-sunken text-accent">
            <Radar aria-hidden className="size-4" />
          </div>
          <div>
            <h2 className="font-semibold">Audit live semua subdomain</h2>
            <p className="mt-1 max-w-2xl text-xs leading-relaxed text-muted">Temukan hostname dari Certificate Transparency, lalu cek HTTPS publik, CNAME takeover, security headers, challenge edge, dan form upload pada halaman awal setiap host.</p>
          </div>
        </div>
        <button
          type="button"
          onClick={() => void runAudit()}
          disabled={!domain.trim() || busy}
          className="flex min-h-10 shrink-0 items-center justify-center gap-2 rounded-lg border border-accent/30 bg-accent/10 px-3 text-xs font-semibold text-accent hover:bg-accent/15 disabled:cursor-wait disabled:opacity-50"
        >
          {busy ? <Loader2 aria-hidden className="size-4 motion-safe:animate-spin" /> : <Radar aria-hidden className="size-4" />}
          {busy ? "Cek subdomain…" : "Cek semua subdomain"}
        </button>
      </div>

      <p className="flex items-start gap-2 text-xs leading-relaxed text-muted">
        <ShieldCheck aria-hidden className="mt-0.5 size-4 shrink-0 text-ok" />
        Hanya admin. Maksimal 100 nama dari CT plus domain induk; hostname privat/internal dilewati oleh SSRF guard. Hasil CT bukan jaminan bahwa seluruh DNS subdomain telah ditemukan.
      </p>

      {error && <p role="alert" className="rounded-lg border border-danger/30 bg-danger/5 p-3 text-sm text-danger">{error}</p>}

      {report && (
        <div className="space-y-4">
          <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted">
            <span>{report.domain}</span>
            <span>{report.totalFound} nama ditemukan dari {report.source}</span>
            <span>{liveCount}/{report.checked} merespons</span>
            {report.truncated && <span className="text-warn">Daftar CT terpotong pada batas sumber</span>}
          </div>

          <div className="overflow-x-auto rounded-xl border border-border">
            <table className="w-full min-w-[980px] text-left text-xs">
              <thead className="bg-sunken text-muted">
                <tr>
                  <th className="px-3 py-2.5 font-medium">Host</th>
                  <th className="px-3 py-2.5 font-medium">Live</th>
                  <th className="px-3 py-2.5 font-medium">CNAME / takeover</th>
                  <th className="px-3 py-2.5 font-medium">Headers</th>
                  <th className="px-3 py-2.5 font-medium">Bukti upload</th>
                  <th className="px-3 py-2.5 font-medium">Edge / trap</th>
                </tr>
              </thead>
              <tbody>
                {report.rows.map((row) => (
                  <tr key={row.host} className="border-t border-border align-top">
                    <td className="max-w-[280px] px-3 py-3">
                      <a href={`https://${row.host}`} target="_blank" rel="noreferrer" className="inline-flex max-w-full items-center gap-1 break-all font-mono text-accent hover:underline">
                        {row.host}<ExternalLink aria-hidden className="size-3 shrink-0" />
                      </a>
                      {row.title && <p className="mt-1 line-clamp-2 text-muted">{row.title}</p>}
                    </td>
                    <td className="px-3 py-3 font-mono">
                      {row.statusCode === null ? <span className="text-muted">{row.error === "non_public" ? "internal · skipped" : "unreachable"}</span> : (
                        <span className={row.statusCode >= 500 ? "text-danger" : row.statusCode >= 400 ? "text-warn" : "text-ok"}>
                          HTTP {row.statusCode} · {row.responseTimeMs} ms
                        </span>
                      )}
                      {row.server && <p className="mt-1 text-muted">{row.server}{row.tlsVersion ? ` · ${row.tlsVersion}` : ""}</p>}
                    </td>
                    <td className="max-w-[240px] px-3 py-3">
                      <RiskBadge risk={row.takeoverRisk} />
                      {row.cname && <p className="mt-1 break-all font-mono text-muted">{row.cname}</p>}
                      {row.takeoverReason && <p className="mt-1 text-muted">{row.takeoverReason}</p>}
                    </td>
                    <td className="px-3 py-3">
                      <div className="flex flex-wrap gap-x-2 gap-y-1">
                        {headerState(row.hsts, "HSTS")}
                        {headerState(row.csp, "CSP")}
                        {headerState(row.frameProtection, "Frame")}
                        {headerState(row.nosniff, "NoSniff")}
                      </div>
                    </td>
                    <td className="px-3 py-3 text-muted">
                      {row.fileForms.length ? row.fileForms.map((form) => (
                        <p key={form.endpoint} className="max-w-[340px] break-all">POST {form.endpoint} · field {form.fields.join(", ")}</p>
                      )) : "Tidak ditemukan di halaman awal"}
                    </td>
                    <td className="px-3 py-3 text-muted">
                      {row.edgeChallenge ? <span className="text-warn">Edge challenge</span> : "—"}
                      {row.honeypotSignal && <p className="text-warn">Signature honeypot</p>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          <details className="rounded-xl border border-border bg-sunken p-3 sm:p-4">
            <summary className="cursor-pointer text-sm font-semibold">Replay POST dari cURL</summary>
            <div className="mt-3 space-y-3">
              <p className="flex items-start gap-2 text-xs leading-relaxed text-muted">
                <AlertTriangle aria-hidden className="mt-0.5 size-4 shrink-0 text-warn" />
                Perintah tidak dijalankan lewat shell. Hanya `curl -X POST`, URL HTTPS pada domain ini/subdomainnya, Content-Type JSON/text/form, dan satu body teks hingga 8 KB yang diteruskan. Cookie/Authorization/Origin/Referer hanya diteruskan ke URL dalam scope, tidak dicatat atau dikembalikan. Upload file, redirect, dan opsi shell ditolak. POST dapat mengubah data target.
              </p>
              <label htmlFor="admin-curl-post" className="text-xs font-medium">Perintah cURL POST</label>
              <textarea
                id="admin-curl-post"
                value={curl}
                onChange={(event) => { setCurl(event.target.value); setPostResult(null); }}
                disabled={postBusy}
                rows={5}
                spellCheck={false}
                placeholder={`curl -X POST -H 'Content-Type: application/json' --data-raw '{"sentinel_probe":"manual-test"}' 'https://api.${report.domain}/endpoint'`}
                className="w-full rounded-lg border border-border bg-panel p-3 font-mono text-xs text-foreground outline-none placeholder:text-muted focus:border-accent disabled:opacity-60"
              />
              {postError && <p role="alert" className="text-sm text-danger">{postError}</p>}
              <button
                type="button"
                onClick={() => void replayPost()}
                disabled={!curl.trim() || postBusy}
                className="flex min-h-10 items-center justify-center gap-2 rounded-lg bg-gradient-accent px-4 text-sm font-semibold text-white hover:brightness-110 disabled:cursor-wait disabled:opacity-50"
              >
                {postBusy ? <Loader2 aria-hidden className="size-4 motion-safe:animate-spin" /> : <Send aria-hidden className="size-4" />}
                {postBusy ? "Mengirim POST…" : "Kirim POST live"}
              </button>
              {postResult && (
                <div role="status" className="rounded-lg border border-border bg-panel p-3 text-xs">
                  <p className="flex flex-wrap items-center gap-2 font-semibold">
                    {postResult.accepted ? <CheckCircle2 aria-hidden className="size-4 text-ok" /> : <XCircle aria-hidden className="size-4 text-warn" />}
                    HTTP {postResult.statusCode} · {postResult.classification.replace(/_/g, " ")} · {postResult.responseTimeMs} ms
                  </p>
                  <p className="mt-1 break-all text-muted">{postResult.url}</p>
                  {postResult.honeypotSignal && <p className="mt-1 text-warn">Ada signature honeypot eksplisit pada respons.</p>}
                  {postResult.edgeChallenge && <p className="mt-1 text-warn">Respons menunjukkan challenge/proteksi edge; ini belum membuktikan aplikasi menerima request.</p>}
                  {postResult.bodyEchoed && <p className="mt-1 text-muted">Body terkirim dipantulkan kembali. Ini bukti pemrosesan/refleksi, bukan bukti celah dengan sendirinya.</p>}
                  {postResult.responsePreview && <p className="mt-2 break-words text-muted">{postResult.responsePreview}</p>}
                  <p className="mt-2 text-muted">{postResult.note}</p>
                </div>
              )}
            </div>
          </details>
        </div>
      )}
    </section>
  );
}
