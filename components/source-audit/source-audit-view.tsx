"use client";

import { useCallback, useMemo, useRef, useState } from "react";
import {
  FileArchive, UploadCloud, ShieldCheck, Download, ChevronDown, ExternalLink, Loader2, Search, X, Lock,
} from "lucide-react";
import type { Severity } from "@/lib/types";
import type { SourceAuditReport, SourceFinding } from "@/lib/source-audit/types";
import { maxVersion } from "@/lib/source-audit/semver";

const MAX_BYTES = 4 * 1024 * 1024;
const SEVERITIES: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"];
const SEV_LABEL: Record<Severity, string> = { CRITICAL: "Critical", HIGH: "High", MEDIUM: "Medium", LOW: "Low", INFO: "Info" };
const SEV_TEXT: Record<Severity, string> = {
  CRITICAL: "text-sev-critical", HIGH: "text-sev-high", MEDIUM: "text-sev-medium", LOW: "text-sev-low", INFO: "text-sev-info",
};
const SEV_DOT: Record<Severity, string> = {
  CRITICAL: "bg-sev-critical", HIGH: "bg-sev-high", MEDIUM: "bg-sev-medium", LOW: "bg-sev-low", INFO: "bg-sev-info",
};
const CONF_LABEL: Record<string, string> = {
  verified: "Terverifikasi", likely: "Kemungkinan besar", "pattern-only": "Perlu review manual", "version-based": "Berbasis versi",
};
const CATEGORY_LABEL: Record<string, string> = {
  secret: "Secret", "sensitive-file": "Berkas sensitif", injection: "Injection", xss: "XSS", crypto: "Kriptografi",
  auth: "Autentikasi", config: "Konfigurasi", deserialization: "Deserialisasi", ssrf: "SSRF", "path-traversal": "Path traversal",
  "supply-chain": "Supply chain", "ci-cd": "CI/CD", container: "Kontainer", "access-control": "Akses kontrol", dependency: "Dependensi",
};

type Phase = "idle" | "uploading" | "analyzing" | "done" | "error";

function fmtBytes(n: number) {
  return n > 1024 * 1024 ? `${(n / 1024 / 1024).toFixed(1)} MB` : `${Math.max(1, Math.round(n / 1024))} KB`;
}

function download(name: string, content: string, type: string) {
  const url = URL.createObjectURL(new Blob([content], { type }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

function toMarkdown(r: SourceAuditReport): string {
  const L: string[] = [
    `# Source Code Audit — ${r.fileName}`,
    ``,
    `- Skor: **${r.score}/100 (${r.grade})**`,
    `- Tanggal: ${new Date(r.createdAt).toLocaleString("id-ID")}`,
    `- Berkas dianalisis: ${r.stats.filesScanned} · Dependensi: ${r.dependencies.scanned}`,
    `- Framework: ${r.stats.frameworks.join(", ") || "-"}`,
    `- Ringkasan: ${SEVERITIES.map((s) => `${SEV_LABEL[s]} ${r.counts[s]}`).join(" · ")}`,
    ``,
    `## Temuan`,
  ];
  for (const f of r.findings) {
    L.push(``, `### [${f.severity}] ${f.title}`, `- Lokasi: \`${f.file}${f.line ? `:${f.line}` : ""}\``);
    if (f.cwe) L.push(`- Referensi: ${f.cwe}${f.owasp ? ` · ${f.owasp}` : ""}`);
    L.push(`- Keyakinan: ${CONF_LABEL[f.confidence] ?? f.confidence}`);
    if (f.snippet) L.push(`- Cuplikan: \`${f.snippet.replace(/`/g, "'")}\``);
    L.push(`- Dampak: ${f.impact}`, `- Perbaikan: ${f.fix}`);
  }
  if (r.dependencies.vulnerable.length) {
    L.push(``, `## Dependensi rentan`, ``, `| Paket | Versi | Ekosistem | Kerentanan | Perbaikan |`, `|---|---|---|---|---|`);
    for (const d of r.dependencies.vulnerable) {
      const fixed = maxVersion(d.vulns.map((v) => v.fixed)) ?? "-";
      L.push(`| ${d.name} | ${d.version} | ${d.ecosystem} | ${d.vulns.map((v) => v.aliases.find((a) => a.startsWith("CVE-")) ?? v.id).join(", ")} | ${fixed} |`);
    }
  }
  if (r.notes.length) L.push(``, `## Catatan`, ...r.notes.map((n) => `- ${n}`));
  L.push(``, `_Dihasilkan oleh Sentinel-ID Source Code Audit (analisis statis)._`);
  return L.join("\n");
}

function FindingRow({ f }: { f: SourceFinding }) {
  const [open, setOpen] = useState(false);
  return (
    <li className="border-b border-border last:border-0">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="w-full flex items-start gap-3 px-4 py-3 text-left hover:bg-foreground/[0.03]"
      >
        <span className={`mt-1.5 h-2 w-2 shrink-0 rounded-full ${SEV_DOT[f.severity]}`} aria-hidden />
        <span className="min-w-0 flex-1">
          <span className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
            <span className="text-sm font-medium text-foreground">{f.title}</span>
            <span className={`text-[11px] font-medium uppercase tracking-wide ${SEV_TEXT[f.severity]}`}>{SEV_LABEL[f.severity]}</span>
            {f.confidence === "pattern-only" && <span className="text-[11px] text-muted-dim">· perlu review</span>}
          </span>
          <span className="mt-0.5 block truncate font-mono text-xs text-muted">
            {f.file}
            {f.line ? `:${f.line}` : ""}
          </span>
        </span>
        <ChevronDown className={`mt-1 h-4 w-4 shrink-0 text-muted-dim transition-transform ${open ? "rotate-180" : ""}`} aria-hidden />
      </button>
      {open && (
        <div className="space-y-3 px-4 pb-4 pl-9 text-sm">
          {f.snippet && (
            <pre className="overflow-x-auto rounded-md border border-border bg-sunken px-3 py-2 font-mono text-xs text-soft whitespace-pre-wrap break-all">
              {f.snippet}
            </pre>
          )}
          <dl className="grid gap-2 sm:grid-cols-[120px_1fr]">
            <dt className="text-muted-dim">Dampak</dt>
            <dd className="text-soft">{f.impact}</dd>
            <dt className="text-muted-dim">Perbaikan</dt>
            <dd className="text-foreground">{f.fix}</dd>
            {f.cwe && (
              <>
                <dt className="text-muted-dim">Referensi</dt>
                <dd className="font-mono text-xs text-soft">
                  {f.cwe}
                  {f.owasp ? ` · ${f.owasp}` : ""}
                </dd>
              </>
            )}
            <dt className="text-muted-dim">Keyakinan</dt>
            <dd className="text-soft">{CONF_LABEL[f.confidence] ?? f.confidence}</dd>
          </dl>
        </div>
      )}
    </li>
  );
}

export function SourceAuditView() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [error, setError] = useState<string | null>(null);
  const [report, setReport] = useState<SourceAuditReport | null>(null);
  const [fileInfo, setFileInfo] = useState<{ name: string; size: number } | null>(null);
  const [drag, setDrag] = useState(false);
  const [sev, setSev] = useState<Severity | "ALL">("ALL");
  const [cat, setCat] = useState<string>("ALL");
  const [q, setQ] = useState("");
  const [hidePattern, setHidePattern] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const upload = useCallback(async (file: File) => {
    setError(null);
    setReport(null);
    if (!/\.zip$/i.test(file.name)) {
      setPhase("error");
      setError("Pilih berkas .zip.");
      return;
    }
    if (file.size > MAX_BYTES) {
      setPhase("error");
      setError(`Arsip ${fmtBytes(file.size)} melebihi batas 4 MB. Buang node_modules, .git, dan folder build lalu kompres ulang.`);
      return;
    }
    setFileInfo({ name: file.name, size: file.size });
    setPhase("uploading");
    const form = new FormData();
    form.append("file", file);
    try {
      const timer = setTimeout(() => setPhase((p) => (p === "uploading" ? "analyzing" : p)), 600);
      const res = await fetch("/api/source-audit", { method: "POST", body: form });
      clearTimeout(timer);
      const data = await res.json().catch(() => null);
      if (!res.ok || !data?.ok) {
        setPhase("error");
        setError(data?.error ?? `Gagal (HTTP ${res.status}).`);
        return;
      }
      setReport(data.report);
      setSev("ALL");
      setCat("ALL");
      setQ("");
      setPhase("done");
    } catch {
      setPhase("error");
      setError("Tidak bisa menghubungi server. Coba lagi.");
    }
  }, []);

  const filtered = useMemo(() => {
    if (!report) return [];
    const s = q.trim().toLowerCase();
    return report.findings.filter(
      (f) =>
        (sev === "ALL" || f.severity === sev) &&
        (cat === "ALL" || f.category === cat) &&
        (!hidePattern || f.confidence !== "pattern-only") &&
        (!s || f.title.toLowerCase().includes(s) || f.file.toLowerCase().includes(s) || (f.cwe ?? "").toLowerCase().includes(s))
    );
  }, [report, sev, cat, q, hidePattern]);

  const categories = useMemo(
    () => (report ? Array.from(new Set(report.findings.map((f) => f.category))) : []),
    [report]
  );

  const busy = phase === "uploading" || phase === "analyzing";

  return (
    <div className="mx-auto max-w-5xl space-y-8 p-4 sm:p-6 lg:p-8">
      <header className="space-y-2">
        <h1 className="text-2xl font-semibold tracking-tight text-foreground">Source Code Audit</h1>
        <p className="max-w-2xl text-sm leading-relaxed text-muted">
          Unggah kode sumber dalam ZIP untuk audit statis: secret yang ter-commit, berkas sensitif, pola kerentanan
          (OWASP Top 10) di JS/TS, PHP, Python, Go, Java/Kotlin, C#, konfigurasi Docker &amp; CI, serta dependensi
          rentan dari database OSV.
        </p>
      </header>

      {/* Dropzone */}
      <section aria-label="Unggah arsip">
        <label
          onDragOver={(e) => {
            e.preventDefault();
            setDrag(true);
          }}
          onDragLeave={() => setDrag(false)}
          onDrop={(e) => {
            e.preventDefault();
            setDrag(false);
            const f = e.dataTransfer.files?.[0];
            if (f && !busy) void upload(f);
          }}
          className={`flex cursor-pointer flex-col items-center justify-center gap-3 rounded-xl border border-dashed px-6 py-12 text-center transition-colors ${
            drag ? "border-accent bg-accent/5" : "border-border bg-panel hover:border-accent/50"
          } ${busy ? "pointer-events-none opacity-70" : ""}`}
        >
          <input
            ref={inputRef}
            type="file"
            accept=".zip,application/zip"
            className="sr-only"
            disabled={busy}
            onChange={(e) => {
              const f = e.target.files?.[0];
              if (f) void upload(f);
              e.target.value = "";
            }}
          />
          {busy ? (
            <Loader2 className="h-7 w-7 animate-spin text-accent" aria-hidden />
          ) : (
            <UploadCloud className="h-7 w-7 text-muted" aria-hidden />
          )}
          <div className="space-y-1">
            <p className="text-sm font-medium text-foreground">
              {phase === "uploading"
                ? "Mengunggah…"
                : phase === "analyzing"
                  ? "Menganalisis kode & dependensi…"
                  : "Seret ZIP ke sini atau klik untuk memilih"}
            </p>
            <p className="text-xs text-muted-dim">
              {fileInfo && busy ? `${fileInfo.name} · ${fmtBytes(fileInfo.size)}` : "Maks 4 MB · tanpa node_modules, .git, dan folder build"}
            </p>
          </div>
        </label>
        <p className="mt-3 flex items-start gap-2 text-xs text-muted-dim">
          <Lock className="mt-0.5 h-3.5 w-3.5 shrink-0" aria-hidden />
          Arsip diproses di memori lalu dibuang, tidak disimpan dan tidak dieksekusi. Yang dikirim keluar hanya nama &amp;
          versi paket ke OSV.dev. Secret di hasil selalu disamarkan.
        </p>
      </section>

      {error && (
        <div role="alert" className="flex items-start justify-between gap-3 rounded-lg border border-danger/30 bg-danger/5 px-4 py-3 text-sm text-danger">
          <span>{error}</span>
          <button type="button" onClick={() => setError(null)} aria-label="Tutup pesan" className="shrink-0">
            <X className="h-4 w-4" />
          </button>
        </div>
      )}

      {report && (
        <>
          {/* Ringkasan */}
          <section aria-label="Ringkasan" className="grid gap-px overflow-hidden rounded-xl border border-border bg-border sm:grid-cols-[200px_1fr]">
            <div className="flex flex-col justify-center gap-1 bg-panel p-6">
              <span className="text-xs text-muted-dim">Skor keamanan</span>
              <span className="flex items-baseline gap-2">
                <span className="text-4xl font-semibold tabular-nums text-foreground">{report.score}</span>
                <span className="text-sm text-muted">/100</span>
                <span className={`ml-1 text-lg font-semibold ${report.grade === "A" || report.grade === "B" ? "text-ok" : report.grade === "C" ? "text-warn" : "text-danger"}`}>
                  {report.grade}
                </span>
              </span>
              <span className="mt-1 flex items-center gap-1.5 truncate text-xs text-muted">
                <FileArchive className="h-3.5 w-3.5 shrink-0" aria-hidden /> {report.fileName}
              </span>
            </div>
            <div className="space-y-4 bg-panel p-6">
              <div className="flex flex-wrap gap-x-6 gap-y-3">
                {SEVERITIES.map((s) => (
                  <button
                    key={s}
                    type="button"
                    onClick={() => setSev(sev === s ? "ALL" : s)}
                    aria-pressed={sev === s}
                    className={`text-left ${sev !== "ALL" && sev !== s ? "opacity-40" : ""}`}
                  >
                    <span className={`block text-2xl font-semibold tabular-nums ${report.counts[s] ? SEV_TEXT[s] : "text-muted-dim"}`}>
                      {report.counts[s]}
                    </span>
                    <span className="text-xs text-muted">{SEV_LABEL[s]}</span>
                  </button>
                ))}
              </div>
              <p className="text-xs text-muted">
                {report.stats.filesScanned} berkas · {fmtBytes(report.stats.bytesScanned)} · {report.dependencies.scanned} dependensi ·{" "}
                {(report.durationMs / 1000).toFixed(1)} dtk
                {report.stats.frameworks.length ? ` · ${report.stats.frameworks.join(", ")}` : ""}
              </p>
              <div className="flex flex-wrap gap-2">
                <button
                  type="button"
                  onClick={() => download(`${report.fileName.replace(/\.zip$/i, "")}-audit.md`, toMarkdown(report), "text/markdown")}
                  className="inline-flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs text-soft hover:border-accent/50 hover:text-foreground"
                >
                  <Download className="h-3.5 w-3.5" aria-hidden /> Markdown
                </button>
                <button
                  type="button"
                  onClick={() => download(`${report.fileName.replace(/\.zip$/i, "")}-audit.json`, JSON.stringify(report, null, 2), "application/json")}
                  className="inline-flex items-center gap-1.5 rounded-md border border-border px-3 py-1.5 text-xs text-soft hover:border-accent/50 hover:text-foreground"
                >
                  <Download className="h-3.5 w-3.5" aria-hidden /> JSON
                </button>
                <button
                  type="button"
                  onClick={() => inputRef.current?.click()}
                  className="inline-flex items-center gap-1.5 rounded-md bg-accent px-3 py-1.5 text-xs font-medium text-accent-fg hover:opacity-90"
                >
                  <UploadCloud className="h-3.5 w-3.5" aria-hidden /> Audit ZIP lain
                </button>
              </div>
            </div>
          </section>

          {/* Temuan */}
          <section aria-labelledby="findings-h" className="space-y-3">
            <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
              <h2 id="findings-h" className="text-base font-semibold text-foreground">
                Temuan <span className="font-normal text-muted">({filtered.length}/{report.findings.length})</span>
              </h2>
              <div className="flex flex-wrap items-center gap-2">
                <label className="flex items-center gap-2 rounded-md border border-border bg-panel px-2.5 py-1.5">
                  <Search className="h-3.5 w-3.5 text-muted-dim" aria-hidden />
                  <input
                    value={q}
                    onChange={(e) => setQ(e.target.value)}
                    placeholder="Cari judul, berkas, CWE"
                    aria-label="Cari temuan"
                    className="w-44 bg-transparent text-xs focus:outline-none placeholder:text-muted-dim"
                  />
                </label>
                <select
                  value={cat}
                  onChange={(e) => setCat(e.target.value)}
                  aria-label="Filter kategori"
                  className="rounded-md border border-border bg-panel px-2.5 py-1.5 text-xs text-soft"
                >
                  <option value="ALL">Semua kategori</option>
                  {categories.map((c) => (
                    <option key={c} value={c}>
                      {CATEGORY_LABEL[c] ?? c}
                    </option>
                  ))}
                </select>
                <label className="flex items-center gap-1.5 text-xs text-muted">
                  <input type="checkbox" checked={hidePattern} onChange={(e) => setHidePattern(e.target.checked)} className="accent-[var(--accent)]" />
                  Sembunyikan &quot;perlu review&quot;
                </label>
              </div>
            </div>
            {report.findings.length === 0 ? (
              <div className="flex items-center gap-3 rounded-xl border border-border bg-panel px-4 py-6 text-sm text-soft">
                <ShieldCheck className="h-5 w-5 text-ok" aria-hidden /> Tidak ada temuan. Tetap lakukan review manual untuk logika bisnis &amp; otorisasi.
              </div>
            ) : (
              <ul className="overflow-hidden rounded-xl border border-border bg-panel">
                {filtered.map((f) => (
                  <FindingRow key={f.id} f={f} />
                ))}
                {!filtered.length && <li className="px-4 py-6 text-sm text-muted">Tidak ada temuan yang cocok dengan filter.</li>}
              </ul>
            )}
          </section>

          {/* Dependensi */}
          <section aria-labelledby="deps-h" className="space-y-3">
            <h2 id="deps-h" className="text-base font-semibold text-foreground">
              Dependensi rentan <span className="font-normal text-muted">({report.dependencies.vulnerable.length}/{report.dependencies.scanned})</span>
            </h2>
            {report.dependencies.error && <p className="text-xs text-warn">{report.dependencies.error}</p>}
            {report.dependencies.vulnerable.length > 0 ? (
              <div className="overflow-x-auto rounded-xl border border-border bg-panel">
                <table className="w-full text-left text-sm">
                  <thead className="border-b border-border text-xs text-muted-dim">
                    <tr>
                      <th className="px-4 py-2.5 font-medium">Paket</th>
                      <th className="px-4 py-2.5 font-medium">Kerentanan</th>
                      <th className="px-4 py-2.5 font-medium">Perbaiki ke</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.dependencies.vulnerable.map((d) => (
                      <tr key={`${d.ecosystem}:${d.name}@${d.version}`} className="border-b border-border last:border-0 align-top">
                        <td className="px-4 py-3">
                          <span className="font-mono text-xs text-foreground">{d.name}</span>
                          <span className="block text-xs text-muted-dim">
                            {d.version} · {d.ecosystem}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <ul className="space-y-1.5">
                            {d.vulns.slice(0, 5).map((v) => (
                              <li key={v.id} className="text-xs">
                                <a href={v.url} target="_blank" rel="noopener noreferrer" className={`inline-flex items-center gap-1 font-mono ${SEV_TEXT[v.severity]} hover:underline`}>
                                  {v.aliases.find((a) => a.startsWith("CVE-")) ?? v.id}
                                  <ExternalLink className="h-3 w-3" aria-hidden />
                                </a>
                                <span className="text-muted"> {v.summary}</span>
                              </li>
                            ))}
                            {d.vulns.length > 5 && <li className="text-xs text-muted-dim">+{d.vulns.length - 5} lainnya</li>}
                          </ul>
                        </td>
                        <td className="px-4 py-3 font-mono text-xs text-ok">
                          {maxVersion(d.vulns.map((v) => v.fixed)) ?? "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-sm text-muted">
                {report.dependencies.scanned
                  ? "Tidak ada dependensi dengan kerentanan diketahui di OSV."
                  : "Tidak ada lockfile yang dikenali (package-lock, yarn, pnpm, requirements, poetry, composer, go.sum, Gemfile.lock, Cargo.lock)."}
              </p>
            )}
          </section>

          {(report.notes.length > 0 || report.skipped.length > 0) && (
            <details className="rounded-xl border border-border bg-panel px-4 py-3 text-sm">
              <summary className="cursor-pointer text-muted">Catatan & berkas yang dilewati</summary>
              <ul className="mt-3 list-disc space-y-1 pl-5 text-xs text-muted">
                {report.notes.map((n) => (
                  <li key={n}>{n}</li>
                ))}
                {report.skipped.map((s) => (
                  <li key={s.path} className="font-mono">
                    {s.path}: {s.reason}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </>
      )}
    </div>
  );
}
