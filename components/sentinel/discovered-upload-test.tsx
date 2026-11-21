"use client";

import { useState } from "react";
import { CheckCircle2, FileUp, Loader2, XCircle } from "lucide-react";
import type { testFileUpload } from "@/lib/sentinel/domain-check";

type UploadResult = Awaited<ReturnType<typeof testFileUpload>> & {
  file: { name: string; originalName: string; size: number; sha256: string };
};

export function DiscoveredUploadTest({ scanId, endpoint, fieldName }: { scanId: string; endpoint: string; fieldName: string }) {
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<UploadResult | null>(null);

  async function run() {
    if (!file || busy) return;
    setBusy(true);
    setError("");
    setResult(null);
    try {
      const form = new FormData();
      form.set("scanId", scanId);
      form.set("endpoint", endpoint);
      form.set("file", file, file.name);
      const response = await fetch("/api/admin/upload-test", {
        method: "POST",
        body: form,
        signal: AbortSignal.timeout(20000),
      });
      if (response.status === 401) return window.location.replace("/admin/login");
      const data = await response.json();
      if (!response.ok) {
        setError(data.error ?? "Validasi upload gagal.");
        return;
      }
      setResult(data as UploadResult);
    } catch {
      setError("Server admin gagal merespons. Coba lagi.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <article className="rounded-xl border border-border bg-panel p-3 sm:p-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-end">
        <div className="min-w-0 flex-1 space-y-1.5">
          <p className="text-xs font-medium text-muted">{endpoint} · field <span className="font-mono">{fieldName}</span></p>
          <label htmlFor={`upload-sample-${scanId}-${fieldName}`} className="text-sm font-medium">Sampel .txt sendiri</label>
          <div className="flex min-h-11 items-center gap-2 rounded-lg border border-border bg-sunken px-3">
            <FileUp aria-hidden className="size-4 shrink-0 text-accent" />
            <input
              id={`upload-sample-${scanId}-${fieldName}`}
              type="file"
              accept=".txt,text/plain"
              disabled={busy}
              onChange={(event) => {
                setFile(event.target.files?.[0] ?? null);
                setResult(null);
              }}
              className="min-w-0 flex-1 py-2 text-xs text-muted file:mr-2 file:rounded-md file:border-0 file:bg-accent/10 file:px-2 file:py-1.5 file:text-xs file:font-medium file:text-accent"
            />
          </div>
          <p className="text-xs text-muted">Maksimum 32 KB. POST tanpa kredensial target; nama file diberi ID acak.</p>
        </div>
        <button
          type="button"
          onClick={() => void run()}
          disabled={!file || busy}
          className="flex min-h-11 shrink-0 items-center justify-center gap-2 rounded-lg bg-gradient-accent px-4 text-sm font-semibold text-white hover:brightness-110 disabled:opacity-50"
        >
          {busy ? <Loader2 aria-hidden className="size-4 motion-safe:animate-spin" /> : <FileUp aria-hidden className="size-4" />}
          {busy ? "Menguji…" : "Uji POST aman"}
        </button>
      </div>

      {error && <p role="alert" className="mt-3 text-sm text-danger">{error}</p>}
      {result && (
        <div role="status" className="mt-3 rounded-lg border border-border bg-sunken p-3 text-xs">
          <p className="flex items-center gap-2 font-semibold">
            {result.accepted ? <CheckCircle2 aria-hidden className="size-4 text-ok" /> : <XCircle aria-hidden className="size-4 text-danger" />}
            HTTP {result.statusCode} · {result.accepted ? "endpoint menerima POST" : "endpoint menolak POST"}
          </p>
          <p className="mt-1 break-all text-muted">Nama tujuan: {result.file.name} · SHA-256: {result.file.sha256}</p>
          {result.links.map((link) => (
            <p key={link.url} className="mt-1 break-all">
              <a className="text-accent underline" href={link.url} target="_blank" rel="noreferrer">{link.url}</a>
              {link.sameOrigin && result.publicRetrieval?.contentMatchesSample && <span className="ml-2 text-ok">isi cocok dan dapat dibaca tanpa login</span>}
            </p>
          ))}
        </div>
      )}
    </article>
  );
}
