"use client";

import { useState } from "react";
import Link from "next/link";
import { LucideCloudCheck, Lock, AlertTriangle, CheckCircle2, Loader2, ShieldAlert, ArrowUpRight } from "lucide-react";
import { VerifiedBadge } from "@/components/verified-badge";

type Severity = "critical" | "medium" | "low" | "info";

interface Finding {
  type: string;
  severity: Severity;
  evidence: string;
  location: string;
  recommendation: string;
}

interface SensitivePathResult {
  checked: string;
  allowed: boolean;
  exposed: boolean;
  vaultStored?: boolean;
  statusCode?: number;
  contentType?: string;
  preview?: string;
  reason?: string;
  matchedPatterns?: string[];
}

interface ScanResult {
  url: string;
  finalUrl: string;
  redirected: boolean;
  headers: Record<string, string>;
  findings: Finding[];
  sensitivePathCheck: SensitivePathResult | null;
  summary?: {
    totalFindings: number;
    critical: number;
    medium: number;
    low: number;
    info: number;
    secure: boolean;
    hasExposedCredentials: boolean;
  };
  disclaimer: string;
  timestamp?: string;
}

const PRESET_PATHS = [
  { label: ".env", path: "/.env", tag: "Vault" },
  { label: ".git/HEAD", path: "/.git/HEAD", tag: "Vault" },
  { label: "backup.zip", path: "/backup.zip", tag: "Vault" },
  { label: "wp-config.php.bak", path: "/wp-config.php.bak", tag: "wp2shell" },
  { label: "AWS Keys", path: "/.aws/credentials", tag: "Vault" },
  { label: "WP Debug Log", path: "/wp-content/debug.log", tag: "wp2shell" },
  { label: "Ignition RCE", path: "/_ignition/health-check", tag: "php2shell" },
  { label: "Node V8 Debug", path: "/json/version", tag: "node2shell" },
  { label: "Go pprof", path: "/debug/pprof/", tag: "go2shell" },
  { label: "Werkzeug Console", path: "/console", tag: "py2shell" },
  { label: "Node Heapdump", path: "/heapdump", tag: "node out of bound" },
  { label: "WSO / Alfa Shell", path: "/wso.php", tag: "webshell" },
  { label: "b374k / Mini Shell", path: "/b374k.php", tag: "webshell" },
  { label: "TinyFileManager", path: "/tinyfilemanager.php", tag: "filemanager" },
  { label: "elFinder Connector", path: "/elfinder/php/connector.minimal.php", tag: "filemanager" },
];

const SEVERITY_STYLES: Record<
  Severity,
  { label: string; dot: string; text: string; ring: string; bg: string }
> = {
  critical: {
    label: "Critical",
    dot: "bg-danger",
    text: "text-danger",
    ring: "ring-danger/30",
    bg: "bg-danger/10",
  },
  medium: {
    label: "Medium",
    dot: "bg-warn",
    text: "text-warn",
    ring: "ring-warn/30",
    bg: "bg-warn/10",
  },
  low: {
    label: "Low",
    dot: "bg-ok",
    text: "text-ok",
    ring: "ring-ok/30",
    bg: "bg-ok/10",
  },
  info: {
    label: "Info",
    dot: "bg-muted",
    text: "text-muted",
    ring: "ring-[#7C89A6]/30",
    bg: "bg-muted/10",
  },
};

function normalizeToHttps(input: string): string | null {
  let raw = input.trim();
  if (!raw) return null;
  if (!/^https?:\/\//i.test(raw)) raw = "https://" + raw;
  try {
    const u = new URL(raw);
    u.protocol = "https:";
    return u.toString();
  } catch {
    return null;
  }
}

export default function ScanExposureClient() {
  const [urlInput, setUrlInput] = useState("");
  const [ownershipConfirmed, setOwnershipConfirmed] = useState(false);
  const [sensitivePath, setSensitivePath] = useState("");
  const [showSensitiveModal, setShowSensitiveModal] = useState(false);
  const [pendingSensitivePath, setPendingSensitivePath] = useState<string | null>(null);
  const [sensitiveOwnerAck, setSensitiveOwnerAck] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  async function runScan(withSensitivePath?: string) {
    const normalized = normalizeToHttps(urlInput);
    if (!normalized) {
      setError("Masukkan URL target yang valid (contoh: example.com)");
      return;
    }
    if (!ownershipConfirmed) {
      setError("Konfirmasi hak kepemilikan atau izin pemindaian terlebih dahulu.");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const res = await fetch("/api/exposure", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          url: normalized,
          sensitivePath: withSensitivePath,
          ownershipConfirmed: true,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? "Pemindaian gagal dilakukan.");
        return;
      }
      setResult(data as ScanResult);
    } catch {
      setError("Gagal menghubungi server scanner. Silakan coba lagi.");
    } finally {
      setLoading(false);
    }
  }

  function handleScanClick() {
    runScan();
  }

  function handleSensitiveCheckClick() {
    const normalized = normalizeToHttps(urlInput);
    if (!normalized) {
      setError("Masukkan URL domain utama terlebih dahulu.");
      return;
    }
    if (!sensitivePath.trim()) {
      setError("Masukkan jalur/path lengkap yang ingin diperiksa (contoh: /.env)");
      return;
    }
    setPendingSensitivePath(sensitivePath.trim());
    setSensitiveOwnerAck(false);
    setShowSensitiveModal(true);
  }

  function confirmSensitiveScan() {
    if (!pendingSensitivePath || !sensitiveOwnerAck) return;
    setShowSensitiveModal(false);
    runScan(pendingSensitivePath);
  }

  return (
    <div className="mx-auto max-w-4xl px-4 py-6 sm:px-6 sm:pb-24 space-y-6">
      {/* Header Section */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="flex items-start gap-3.5">
          <div className="h-10 w-10 grid place-items-center rounded-xl bg-gradient-to-br from-[#c084fc] to-[#9333ea] text-white shadow-lg shadow-purple-500/20 shrink-0 mt-0.5">
            <LucideCloudCheck className="h-5 w-5 text-foreground" strokeWidth={2.5} />
          </div>
          <div className="space-y-1">
            <h1 className="text-base sm:text-lg font-bold tracking-tight text-foreground flex items-center gap-2 flex-wrap">
              Audit File Sensitif &amp; Brankas Bukti Terenkripsi (AES-256-GCM)
              <Lock className="h-4 w-4 text-ok" />
            </h1>
            <p className="text-xs text-soft max-w-2xl leading-relaxed">
              Mendeteksi kebocoran kritis (<code className="text-purple-300">.env</code>,{" "}
              <code className="text-purple-300">.git/HEAD</code>, <code className="text-purple-300">backup.zip</code>,{" "}
              <code className="text-purple-300">wp-config.php.bak</code>, <code className="text-purple-300">AWS keys</code>
              ) serta permukaan <code className="text-pink-300">wp2shell</code>,{" "}
              <code className="text-pink-300">php2shell</code>, <code className="text-pink-300">node2shell</code>,{" "}
              <code className="text-pink-300">go2shell</code>, <code className="text-pink-300">py2shell</code>, dan{" "}
              <code className="text-pink-300">node out of bound</code> secara pasif. Nilai rahasia tidak pernah bocor ke publik dan disimpan terenkripsi di Vault Admin untuk diklaim pemilik sah domain.
            </p>
          </div>
        </div>
        <VerifiedBadge variant="vault" />
      </div>

      {/* Main Form Container */}
      <div className="rounded-2xl border border-line bg-panel p-4 sm:p-6 md:p-8 shadow-xl">
        {/* Target Domain Section Header */}
        <div className="flex items-center gap-3 mb-4">
          <span className="font-mono text-xs font-semibold uppercase tracking-widest text-ok">
            Target Domain
          </span>
          <span className="h-px flex-1 bg-line" />
        </div>

        {/* Input URL */}
        <div className="space-y-3">
          <div className="flex items-center gap-2 bg-sunken rounded-xl border border-muted px-3.5 py-3 focus-within:border-ok focus-within:ring-2 focus-within:ring-ok/30 transition-all">
            <span className="text-muted font-mono text-sm select-none">https://</span>
            <input
              type="text"
              placeholder="example.com"
              value={urlInput.replace(/^https?:\/\//, "")}
              onChange={(e) => setUrlInput(e.target.value)}
              className="flex-1 bg-transparent font-mono text-sm text-foreground placeholder:text-muted focus:outline-none min-w-0"
            />
          </div>

          <div className="flex items-start gap-2.5 rounded-lg border border-warn/20 bg-warn/5 px-3.5 py-2.5">
            <AlertTriangle className="h-4 w-4 text-warn shrink-0 mt-0.5" />
            <p className="text-xs text-soft leading-relaxed">
              Memeriksa penanda teknologi publik melalui permintaan GET standar yang 100% pasif. Nilai rahasia dari file sensitif tidak pernah ditampilkan di layar publik dan langsung dienkripsi AES-256-GCM ke Vault Admin.
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="mt-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <label className="flex items-start gap-3 text-sm text-soft cursor-pointer select-none">
            <input
              type="checkbox"
              checked={ownershipConfirmed}
              onChange={(e) => setOwnershipConfirmed(e.target.checked)}
              className="mt-0.5 h-4 w-4 rounded border-muted bg-sunken accent-[#3FA796] transition cursor-pointer"
            />
            <span className="text-xs sm:text-sm">Saya mengonfirmasi memiliki izin penuh atas domain ini.</span>
          </label>

          <button
            onClick={handleScanClick}
            disabled={loading}
            className="w-full sm:w-auto min-w-[140px] flex items-center justify-center gap-2 rounded-xl bg-ok px-6 py-2.5 font-mono text-xs font-bold uppercase tracking-wider text-[#0E1420] transition hover:bg-ok active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50 cursor-pointer"
          >
            {loading ? (
              <>
                <Loader2 className="h-4 w-4 animate-spin" />
                <span>Memindai...</span>
              </>
            ) : (
              "Mulai Pemindaian"
            )}
          </button>
        </div>

        {/* Sensitive Path & Deep Shell Surface Checker */}
        <div className="mt-6 pt-6 border-t border-line/80 space-y-3">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <span className="text-xs font-mono font-bold text-warn">
              Uji Path File Sensitif / Deep Shell Surface (Otomatis Enkripsi AES-256-GCM ke Vault):
            </span>
            <Link
              href="/scan/sentinel"
              className="inline-flex items-center gap-1 text-xs font-mono text-purple-300 hover:text-purple-200"
            >
              <span>Audit Semua Path Sekaligus di Sentinel Vault</span>
              <ArrowUpRight className="h-3.5 w-3.5" />
            </Link>
          </div>

          {/* Preset Quick Buttons */}
          <div className="flex flex-wrap gap-1.5">
            {PRESET_PATHS.map((p) => (
              <button
                key={p.path}
                type="button"
                onClick={() => setSensitivePath(p.path)}
                className="inline-flex items-center gap-1.5 rounded-lg border border-line bg-sunken hover:border-ok/60 px-2.5 py-1 text-xs font-mono text-soft transition cursor-pointer"
              >
                <span className="text-ok font-bold">[{p.tag}]</span>
                <span>{p.path}</span>
              </button>
            ))}
          </div>

          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
            <input
              type="text"
              placeholder="Cek path spesifik (cth: /.env, /.git/HEAD, /backup.zip, /wp-config.php.bak, /json/version)"
              value={sensitivePath}
              onChange={(e) => setSensitivePath(e.target.value)}
              className="flex-1 rounded-xl border border-muted bg-sunken px-3.5 py-2.5 font-mono text-xs text-foreground placeholder:text-muted focus:border-warn focus:outline-none focus:ring-2 focus:ring-warn/30 transition"
            />
            <button
              onClick={handleSensitiveCheckClick}
              disabled={loading}
              className="w-full sm:w-auto rounded-xl border border-warn/50 bg-warn/5 px-5 py-2.5 font-mono text-xs font-semibold text-warn transition hover:bg-warn/15 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50 whitespace-nowrap cursor-pointer"
            >
              Uji &amp; Amankan ke Vault
            </button>
          </div>
        </div>

        {/* Error State */}
        {error && (
          <div className="mt-4 rounded-xl border border-danger/40 bg-danger/10 px-4 py-3 flex items-center gap-2.5">
            <ShieldAlert className="h-4 w-4 text-danger shrink-0" />
            <p className="text-xs sm:text-sm font-medium text-danger">{error}</p>
          </div>
        )}
      </div>

      {/* Results Section */}
      {result && (
        <div className="mt-8 space-y-6 animate-in fade-in-50 duration-300">
          {/* Summary Card */}
          {result.summary && (
            <div className="rounded-2xl border border-line bg-panel p-4 sm:p-6 shadow-xl">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <p className="font-mono text-xs font-semibold uppercase tracking-widest text-muted">
                    Ringkasan Hasil
                  </p>
                  <p className="mt-1 text-sm font-semibold text-foreground flex items-center gap-2">
                    {result.summary.secure ? (
                      <>
                        <CheckCircle2 className="h-4 w-4 text-ok" />
                        <span>Aman - Tidak ditemukan isu kritis</span>
                      </>
                    ) : (
                      <>
                        <AlertTriangle className="h-4 w-4 text-warn" />
                        <span>Ditemukan {result.summary.totalFindings} potensi kerentanan</span>
                      </>
                    )}
                  </p>
                </div>

                {/* Severity Counters */}
                <div className="flex flex-wrap items-center gap-3 sm:gap-4 border-t sm:border-t-0 border-line pt-3 sm:pt-0">
                  {result.summary.critical > 0 && (
                    <span className="flex items-center gap-1.5 bg-danger/10 border border-danger/20 px-2.5 py-1 rounded-md">
                      <span className="h-2 w-2 rounded-full bg-danger" />
                      <span className="text-xs font-mono font-medium text-danger">
                        {result.summary.critical} Critical (Vault AES-256-GCM)
                      </span>
                    </span>
                  )}
                  {result.summary.medium > 0 && (
                    <span className="flex items-center gap-1.5 bg-warn/10 border border-warn/20 px-2.5 py-1 rounded-md">
                      <span className="h-2 w-2 rounded-full bg-warn" />
                      <span className="text-xs font-mono font-medium text-warn">
                        {result.summary.medium} Medium
                      </span>
                    </span>
                  )}
                  {result.summary.low > 0 && (
                    <span className="flex items-center gap-1.5 bg-ok/10 border border-ok/20 px-2.5 py-1 rounded-md">
                      <span className="h-2 w-2 rounded-full bg-ok" />
                      <span className="text-xs font-mono font-medium text-ok">
                        {result.summary.low} Low
                      </span>
                    </span>
                  )}
                  {result.summary.info > 0 && (
                    <span className="flex items-center gap-1.5 bg-muted/10 border border-muted/20 px-2.5 py-1 rounded-md">
                      <span className="h-2 w-2 rounded-full bg-muted" />
                      <span className="text-xs font-mono font-medium text-muted">
                        {result.summary.info} Info
                      </span>
                    </span>
                  )}
                </div>
              </div>

              {result.timestamp && (
                <p className="mt-3 text-xs font-mono text-muted">
                  Waktu Pemindaian: {new Date(result.timestamp).toLocaleString("id-ID")}
                </p>
              )}
            </div>
          )}

          {/* Target Info */}
          <div className="rounded-2xl border border-line bg-panel p-4 sm:p-6 shadow-xl">
            <div className="flex items-center gap-3 mb-3">
              <span className="font-mono text-xs font-semibold uppercase tracking-widest text-ok">
                Target Pemindaian
              </span>
              <span className="h-px flex-1 bg-line" />
            </div>
            <p className="break-all font-mono text-xs sm:text-sm text-foreground">
              {result.url}
              {result.redirected && (
                <span className="block sm:inline mt-1 sm:mt-0 sm:ml-2 text-xs text-muted">
                  ↳ dialihkan ke <span className="underline decoration-[#7C89A6]/40">{result.finalUrl}</span>
                </span>
              )}
            </p>
          </div>

          {/* Headers */}
          <div className="rounded-2xl border border-line bg-panel p-4 sm:p-6 shadow-xl">
            <div className="flex items-center gap-3 mb-4">
              <span className="font-mono text-xs font-semibold uppercase tracking-widest text-ok">
                Header Respons
              </span>
              <span className="h-px flex-1 bg-line" />
            </div>
            <div className="grid gap-2 font-mono text-xs">
              {Object.entries(result.headers)
                .filter(([key]) =>
                  [
                    "server",
                    "x-powered-by",
                    "content-type",
                    "strict-transport-security",
                    "content-security-policy",
                    "x-frame-options",
                  ].includes(key)
                )
                .map(([key, value]) => (
                  <div
                    key={key}
                    className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 sm:gap-4 border-b border-line/60 py-2 last:border-0"
                  >
                    <span className="text-muted font-medium">{key}</span>
                    <span className="text-soft break-all sm:text-right font-mono text-xs sm:text-xs">
                      {value || "—"}
                    </span>
                  </div>
                ))}
            </div>
          </div>

          {/* Findings */}
          <div className="rounded-2xl border border-line bg-panel p-4 sm:p-6 shadow-xl">
            <div className="flex items-center justify-between gap-3 mb-4">
              <div className="flex items-center gap-3 flex-1">
                <span className="font-mono text-xs font-semibold uppercase tracking-widest text-ok">
                  Temuan Auditing
                </span>
                <span className="h-px flex-1 bg-line" />
              </div>
              <span className="font-mono text-xs text-muted bg-sunken px-2 py-1 rounded border border-line">
                {result.findings.length} Ditemukan
              </span>
            </div>

            {result.findings.length === 0 ? (
              <div className="rounded-xl border border-ok/30 bg-ok/5 p-6 text-center">
                <p className="text-sm font-semibold text-ok">
                  ✨ Tidak Ditemukan Pola Eksposur
                </p>
                <p className="mt-1 text-xs text-muted">
                  Halaman utama tampak bersih dari konfigurasi terbuka yang umum.
                </p>
              </div>
            ) : (
              <div className="space-y-3">
                {result.findings.map((f, i) => {
                  const s = SEVERITY_STYLES[f.severity];
                  return (
                    <div
                      key={i}
                      className={`rounded-xl border border-line p-4 ${s.bg} ring-1 ${s.ring} space-y-2`}
                    >
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`h-2 w-2 rounded-full ${s.dot} shrink-0`} />
                        <span className={`font-mono text-xs font-bold uppercase ${s.text}`}>
                          {s.label}
                        </span>
                        <span className="text-[#232B3D]">•</span>
                        <span className="font-mono text-xs text-muted truncate">{f.type}</span>
                      </div>

                      <p className="break-all text-xs sm:text-sm font-medium text-foreground">
                        {f.evidence}
                      </p>

                      <p className="text-xs font-mono text-muted break-all">
                        Lokasi: {f.location}
                      </p>

                      <div className="mt-2 pt-2 border-t border-foreground/5">
                        <p className="text-xs text-ok leading-relaxed">
                          💡 <span className="font-semibold">Saran:</span> {f.recommendation}
                        </p>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>

          {/* Sensitive Path Result */}
          {result.sensitivePathCheck && (
            <div className="rounded-2xl border border-line bg-panel p-4 sm:p-6 shadow-xl">
              <div className="flex items-center gap-3 mb-4">
                <span className="font-mono text-xs font-semibold uppercase tracking-widest text-warn">
                  Hasil Pemeriksaan Path &amp; Status Brankas AES-256-GCM
                </span>
                <span className="h-px flex-1 bg-line" />
              </div>

              <div className="space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2 bg-sunken rounded-xl px-3.5 py-2.5 border border-muted">
                  <span className="text-xs font-medium text-muted">Target Path:</span>
                  <span className="font-mono text-xs text-foreground break-all">
                    {result.sensitivePathCheck.checked}
                  </span>
                </div>

                {result.sensitivePathCheck.reason && (
                  <div className="rounded-xl border border-warn/30 bg-warn/10 px-3.5 py-2.5">
                    <p className="text-xs sm:text-sm text-warn">
                      {result.sensitivePathCheck.reason}
                    </p>
                  </div>
                )}

                {result.sensitivePathCheck.allowed && (
                  <div className="grid grid-cols-2 gap-3">
                    <div className="rounded-xl border border-line bg-sunken p-3">
                      <p className="text-xs text-muted">Status Code</p>
                      <p className="font-mono text-sm font-semibold text-foreground mt-0.5">
                        {result.sensitivePathCheck.statusCode}
                      </p>
                    </div>
                    <div className="rounded-xl border border-line bg-sunken p-3">
                      <p className="text-xs text-muted">Status Eksposur &amp; Vault</p>
                      <p
                        className={`font-mono text-sm font-bold mt-0.5 ${
                          result.sensitivePathCheck.exposed ? "text-danger" : "text-ok"
                        }`}
                      >
                        {result.sensitivePathCheck.exposed
                          ? "⚠️ TEREKSPOS (Dienkripsi ke Vault Admin)"
                          : "✅ AMAN"}
                      </p>
                    </div>
                  </div>
                )}

                {result.sensitivePathCheck.matchedPatterns &&
                  result.sensitivePathCheck.matchedPatterns.length > 0 && (
                    <div className="rounded-xl border border-danger/30 bg-danger/5 p-3.5 space-y-2">
                      <p className="text-xs text-danger font-semibold">
                        Penanda Kritis Terdeteksi ({result.sensitivePathCheck.matchedPatterns.length}):
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {result.sensitivePathCheck.matchedPatterns.map((pattern, idx) => (
                          <span
                            key={idx}
                            className="px-2 py-1 bg-sunken rounded-md border border-line text-xs font-mono text-soft"
                          >
                            {pattern}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                {result.sensitivePathCheck.preview && (
                  <div className="rounded-xl border border-purple-500/35 bg-sunken p-3.5 space-y-2">
                    <p className="text-xs font-mono font-bold text-purple-300 flex items-center gap-1.5">
                      <Lock className="h-3.5 w-3.5 text-pink-400" />
                      Proteksi Nilai Rahasia (AES-256-GCM Vault Admin):
                    </p>
                    <pre className="font-mono text-xs text-soft whitespace-pre-wrap break-all bg-sunken p-2.5 rounded-lg">
                      {result.sensitivePathCheck.preview}
                    </pre>
                    <Link
                      href="/scan/sentinel"
                      className="inline-flex items-center gap-1.5 text-xs font-mono font-bold text-emerald-400 hover:text-emerald-300"
                    >
                      <span>Klaim Kepemilikan Domain untuk Membuka Bukti Mentah →</span>
                    </Link>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Disclaimer */}
          <div className="rounded-2xl border border-line/60 bg-panel/50 p-4">
            <p className="text-center text-xs text-muted leading-relaxed">
              {result.disclaimer}
            </p>
          </div>
        </div>
      )}

      {/* Sensitive Path Confirmation Modal */}
      {showSensitiveModal && pendingSensitivePath && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 px-4 backdrop-blur-sm animate-in fade-in-50">
          <div className="w-full max-w-md max-h-[90vh] overflow-y-auto rounded-2xl border border-danger/40 bg-panel p-5 sm:p-6 shadow-2xl space-y-4">
            <div className="flex items-center gap-2.5 text-danger">
              <AlertTriangle className="h-5 w-5 shrink-0" />
              <h3 className="font-mono text-sm font-bold uppercase tracking-wide">
                Konfirmasi Uji Path Sensitif &amp; Enkripsi Vault
              </h3>
            </div>

            <p className="text-xs sm:text-sm text-soft leading-relaxed">
              Sistem akan mengirimkan satu permintaan pembacaan pasif (GET-only) ke path berikut:
            </p>

            <div className="rounded-xl bg-sunken border border-muted p-3">
              <code className="font-mono text-xs text-foreground break-all">
                {pendingSensitivePath}
              </code>
            </div>

            <div className="space-y-2 bg-sunken/50 p-3 rounded-xl border border-line">
              <div className="flex items-start gap-2 text-xs text-muted">
                <span className="text-ok font-bold">✓</span>
                <span>100% pasif GET-only tanpa payload eksploitasi</span>
              </div>
              <div className="flex items-start gap-2 text-xs text-muted">
                <span className="text-ok font-bold">✓</span>
                <span>Nilai rahasia tidak pernah bocor ke layar publik</span>
              </div>
              <div className="flex items-start gap-2 text-xs text-muted">
                <span className="text-ok font-bold">✓</span>
                <span>Bukti kritis dienkripsi AES-256-GCM di Vault Admin untuk diklaim pemilik sah domain</span>
              </div>
            </div>

            <label className="flex items-start gap-3 text-xs text-soft cursor-pointer select-none">
              <input
                type="checkbox"
                checked={sensitiveOwnerAck}
                onChange={(e) => setSensitiveOwnerAck(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-muted bg-sunken accent-[#E15252] cursor-pointer"
              />
              <span>
                Saya menyatakan secara sah bahwa saya adalah pemilik domain ini atau memiliki izin tertulis untuk pengujian.
              </span>
            </label>

            <div className="flex flex-col-reverse sm:flex-row gap-2.5 pt-2">
              <button
                onClick={() => setShowSensitiveModal(false)}
                className="w-full sm:flex-1 rounded-xl border border-muted px-4 py-2.5 text-xs font-semibold text-soft hover:bg-[#1A2233] transition cursor-pointer"
              >
                Batal
              </button>
              <button
                onClick={confirmSensitiveScan}
                disabled={!sensitiveOwnerAck}
                className="w-full sm:flex-1 rounded-xl bg-danger px-4 py-2.5 text-xs font-semibold text-white transition hover:bg-[#EC6E6E] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-40 cursor-pointer"
              >
                Setuju &amp; Periksa
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}