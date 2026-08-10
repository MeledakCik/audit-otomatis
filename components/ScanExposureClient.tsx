"use client";

import { useState } from "react";
import { LucideCloudCheck, Lock, AlertTriangle, CheckCircle2, Loader2, ShieldAlert } from "lucide-react";

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

const SEVERITY_STYLES: Record<
  Severity,
  { label: string; dot: string; text: string; ring: string; bg: string }
> = {
  critical: {
    label: "Critical",
    dot: "bg-[#E15252]",
    text: "text-[#E15252]",
    ring: "ring-[#E15252]/30",
    bg: "bg-[#E15252]/10",
  },
  medium: {
    label: "Medium",
    dot: "bg-[#F2A93C]",
    text: "text-[#F2A93C]",
    ring: "ring-[#F2A93C]/30",
    bg: "bg-[#F2A93C]/10",
  },
  low: {
    label: "Low",
    dot: "bg-[#3FA796]",
    text: "text-[#3FA796]",
    ring: "ring-[#3FA796]/30",
    bg: "bg-[#3FA796]/10",
  },
  info: {
    label: "Info",
    dot: "bg-[#7C89A6]",
    text: "text-[#7C89A6]",
    ring: "ring-[#7C89A6]/30",
    bg: "bg-[#7C89A6]/10",
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
    <div className="mx-auto max-w-4xl px-4 py-6 sm:px-6 sm:pb-24">
      {/* Header Section */}
      <div className="flex items-start gap-3.5 mb-6">
        <div className="h-10 w-10 grid place-items-center rounded-xl bg-gradient-to-br from-[#c084fc] to-[#9333ea] text-white shadow-lg shadow-purple-500/20 shrink-0 mt-0.5">
          <LucideCloudCheck className="h-5 w-5 text-white" strokeWidth={2.5} />
        </div>
        <div className="space-y-1">
          <h1 className="text-base sm:text-lg font-bold tracking-tight text-foreground flex items-center gap-2 flex-wrap">
            Cloud Exposure & Misconfig Inspector
            <Lock className="h-4 w-4 text-[#3FA796]" />
          </h1>
          <p className="text-xs font-mono text-[#7C89A6] leading-relaxed">
            Audit inventaris aset publik & konfigurasi cloud untuk kebutuhan edukasi (tanpa eksploitasi/CVE database).
          </p>
        </div>
      </div>

      {/* Main Form Container */}
      <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4 sm:p-6 md:p-8 shadow-xl">
        {/* Target Domain Section Header */}
        <div className="flex items-center gap-3 mb-4">
          <span className="font-mono text-xs font-semibold uppercase tracking-widest text-[#3FA796]">
            Target Domain
          </span>
          <span className="h-px flex-1 bg-[#232B3D]" />
        </div>

        {/* Input URL */}
        <div className="space-y-3">
          <div className="flex items-center gap-2 bg-[#0E1420] rounded-xl border border-[#2A3348] px-3.5 py-3 focus-within:border-[#3FA796] focus-within:ring-2 focus-within:ring-[#3FA796]/30 transition-all">
            <span className="text-[#4C5A78] font-mono text-sm select-none">https://</span>
            <input
              type="text"
              placeholder="example.com"
              value={urlInput.replace(/^https?:\/\//, "")}
              onChange={(e) => setUrlInput(e.target.value)}
              className="flex-1 bg-transparent font-mono text-sm text-[#EAF0FA] placeholder:text-[#4C5A78] focus:outline-none min-w-0"
            />
          </div>

          <div className="flex items-start gap-2.5 rounded-lg border border-[#F2A93C]/20 bg-[#F2A93C]/5 px-3.5 py-2.5">
            <AlertTriangle className="h-4 w-4 text-[#F2A93C] shrink-0 mt-0.5" />
            <p className="text-xs text-[#C9D2E3] leading-relaxed">
              Memeriksa penanda teknologi publik melalui satu permintaan GET standar ke domain utama. Tidak melakukan bruteforce maupun pemindaian kerentanan agresif.
            </p>
          </div>
        </div>

        {/* Action Controls */}
        <div className="mt-6 flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <label className="flex items-start gap-3 text-sm text-[#C9D2E3] cursor-pointer select-none">
            <input
              type="checkbox"
              checked={ownershipConfirmed}
              onChange={(e) => setOwnershipConfirmed(e.target.checked)}
              className="mt-0.5 h-4 w-4 rounded border-[#2A3348] bg-[#0E1420] accent-[#3FA796] transition cursor-pointer"
            />
            <span className="text-xs sm:text-sm">Saya mengonfirmasi memiliki izin penuh atas domain ini.</span>
          </label>

          <button
            onClick={handleScanClick}
            disabled={loading}
            className="w-full sm:w-auto min-w-[140px] flex items-center justify-center gap-2 rounded-xl bg-[#3FA796] px-6 py-2.5 font-mono text-xs font-bold uppercase tracking-wider text-[#0E1420] transition hover:bg-[#57C4B2] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50"
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

        {/* Sensitive Path Checker Optional */}
        <div className="mt-6 pt-6 border-t border-[#232B3D]/80">
          <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
            <input
              type="text"
              placeholder="Cek path spesifik (cth: /.env atau /wp-config.php)"
              value={sensitivePath}
              onChange={(e) => setSensitivePath(e.target.value)}
              className="flex-1 rounded-xl border border-[#2A3348] bg-[#0E1420] px-3.5 py-2.5 font-mono text-xs text-[#EAF0FA] placeholder:text-[#4C5A78] focus:border-[#F2A93C] focus:outline-none focus:ring-2 focus:ring-[#F2A93C]/30 transition"
            />
            <button
              onClick={handleSensitiveCheckClick}
              disabled={loading}
              className="w-full sm:w-auto rounded-xl border border-[#F2A93C]/50 bg-[#F2A93C]/5 px-5 py-2.5 font-mono text-xs font-semibold text-[#F2A93C] transition hover:bg-[#F2A93C]/15 active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-50 whitespace-nowrap"
            >
              Uji Path
            </button>
          </div>
          <p className="mt-2 text-[11px] text-[#7C89A6]">
            Opsional: Uji eksposur file sensitif tertentu langsung pada server target.
          </p>
        </div>

        {/* Error State */}
        {error && (
          <div className="mt-4 rounded-xl border border-[#E15252]/40 bg-[#E15252]/10 px-4 py-3 flex items-center gap-2.5">
            <ShieldAlert className="h-4 w-4 text-[#E15252] shrink-0" />
            <p className="text-xs sm:text-sm font-medium text-[#E15252]">{error}</p>
          </div>
        )}
      </div>

      {/* Results Section */}
      {result && (
        <div className="mt-8 space-y-6 animate-in fade-in-50 duration-300">
          {/* Summary Card */}
          {result.summary && (
            <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4 sm:p-6 shadow-xl">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
                <div>
                  <p className="font-mono text-xs font-semibold uppercase tracking-widest text-[#7C89A6]">
                    Ringkasan Hasil
                  </p>
                  <p className="mt-1 text-sm font-semibold text-[#EAF0FA] flex items-center gap-2">
                    {result.summary.secure ? (
                      <>
                        <CheckCircle2 className="h-4 w-4 text-[#3FA796]" />
                        <span>Aman - Tidak ditemukan isu kritis</span>
                      </>
                    ) : (
                      <>
                        <AlertTriangle className="h-4 w-4 text-[#F2A93C]" />
                        <span>Ditemukan {result.summary.totalFindings} potensi kerentanan</span>
                      </>
                    )}
                  </p>
                </div>

                {/* Severity Counters */}
                <div className="flex flex-wrap items-center gap-3 sm:gap-4 border-t sm:border-t-0 border-[#232B3D] pt-3 sm:pt-0">
                  {result.summary.critical > 0 && (
                    <span className="flex items-center gap-1.5 bg-[#E15252]/10 border border-[#E15252]/20 px-2.5 py-1 rounded-md">
                      <span className="h-2 w-2 rounded-full bg-[#E15252]" />
                      <span className="text-xs font-mono font-medium text-[#E15252]">
                        {result.summary.critical} Critical
                      </span>
                    </span>
                  )}
                  {result.summary.medium > 0 && (
                    <span className="flex items-center gap-1.5 bg-[#F2A93C]/10 border border-[#F2A93C]/20 px-2.5 py-1 rounded-md">
                      <span className="h-2 w-2 rounded-full bg-[#F2A93C]" />
                      <span className="text-xs font-mono font-medium text-[#F2A93C]">
                        {result.summary.medium} Medium
                      </span>
                    </span>
                  )}
                  {result.summary.low > 0 && (
                    <span className="flex items-center gap-1.5 bg-[#3FA796]/10 border border-[#3FA796]/20 px-2.5 py-1 rounded-md">
                      <span className="h-2 w-2 rounded-full bg-[#3FA796]" />
                      <span className="text-xs font-mono font-medium text-[#3FA796]">
                        {result.summary.low} Low
                      </span>
                    </span>
                  )}
                  {result.summary.info > 0 && (
                    <span className="flex items-center gap-1.5 bg-[#7C89A6]/10 border border-[#7C89A6]/20 px-2.5 py-1 rounded-md">
                      <span className="h-2 w-2 rounded-full bg-[#7C89A6]" />
                      <span className="text-xs font-mono font-medium text-[#7C89A6]">
                        {result.summary.info} Info
                      </span>
                    </span>
                  )}
                </div>
              </div>

              {result.timestamp && (
                <p className="mt-3 text-[11px] font-mono text-[#4C5A78]">
                  Waktu Pemindaian: {new Date(result.timestamp).toLocaleString("id-ID")}
                </p>
              )}
            </div>
          )}

          {/* Target Info */}
          <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4 sm:p-6 shadow-xl">
            <div className="flex items-center gap-3 mb-3">
              <span className="font-mono text-xs font-semibold uppercase tracking-widest text-[#3FA796]">
                Target Pemindaian
              </span>
              <span className="h-px flex-1 bg-[#232B3D]" />
            </div>
            <p className="break-all font-mono text-xs sm:text-sm text-[#EAF0FA]">
              {result.url}
              {result.redirected && (
                <span className="block sm:inline mt-1 sm:mt-0 sm:ml-2 text-xs text-[#7C89A6]">
                  ↳ dialihkan ke <span className="underline decoration-[#7C89A6]/40">{result.finalUrl}</span>
                </span>
              )}
            </p>
          </div>

          {/* Headers */}
          <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4 sm:p-6 shadow-xl">
            <div className="flex items-center gap-3 mb-4">
              <span className="font-mono text-xs font-semibold uppercase tracking-widest text-[#3FA796]">
                Header Respons
              </span>
              <span className="h-px flex-1 bg-[#232B3D]" />
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
                  ].includes(key),
                )
                .map(([key, value]) => (
                  <div
                    key={key}
                    className="flex flex-col sm:flex-row sm:items-center justify-between gap-1 sm:gap-4 border-b border-[#232B3D]/60 py-2 last:border-0"
                  >
                    <span className="text-[#7C89A6] font-medium">{key}</span>
                    <span className="text-[#C9D2E3] break-all sm:text-right font-mono text-[11px] sm:text-xs">
                      {value || "—"}
                    </span>
                  </div>
                ))}
            </div>
          </div>

          {/* Findings */}
          <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4 sm:p-6 shadow-xl">
            <div className="flex items-center justify-between gap-3 mb-4">
              <div className="flex items-center gap-3 flex-1">
                <span className="font-mono text-xs font-semibold uppercase tracking-widest text-[#3FA796]">
                  Temuan Auditing
                </span>
                <span className="h-px flex-1 bg-[#232B3D]" />
              </div>
              <span className="font-mono text-xs text-[#7C89A6] bg-[#0E1420] px-2 py-1 rounded border border-[#232B3D]">
                {result.findings.length} Ditemukan
              </span>
            </div>

            {result.findings.length === 0 ? (
              <div className="rounded-xl border border-[#3FA796]/30 bg-[#3FA796]/5 p-6 text-center">
                <p className="text-sm font-semibold text-[#3FA796]">
                  ✨ Tidak Ditemukan Pola Eksposur
                </p>
                <p className="mt-1 text-xs text-[#7C89A6]">
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
                      className={`rounded-xl border border-[#232B3D] p-4 ${s.bg} ring-1 ${s.ring} space-y-2`}
                    >
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className={`h-2 w-2 rounded-full ${s.dot} shrink-0`} />
                        <span className={`font-mono text-xs font-bold uppercase ${s.text}`}>
                          {s.label}
                        </span>
                        <span className="text-[#232B3D]">•</span>
                        <span className="font-mono text-xs text-[#7C89A6] truncate">{f.type}</span>
                      </div>

                      <p className="break-all text-xs sm:text-sm font-medium text-[#EAF0FA]">
                        {f.evidence}
                      </p>

                      <p className="text-[11px] font-mono text-[#7C89A6] break-all">
                        Lokasi: {f.location}
                      </p>

                      <div className="mt-2 pt-2 border-t border-white/5">
                        <p className="text-xs text-[#8FE3D3] leading-relaxed">
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
            <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4 sm:p-6 shadow-xl">
              <div className="flex items-center gap-3 mb-4">
                <span className="font-mono text-xs font-semibold uppercase tracking-widest text-[#F2A93C]">
                  Hasil Pemeriksaan Path
                </span>
                <span className="h-px flex-1 bg-[#232B3D]" />
              </div>

              <div className="space-y-3">
                <div className="flex flex-col sm:flex-row sm:items-center gap-1 sm:gap-2 bg-[#0E1420] rounded-xl px-3.5 py-2.5 border border-[#2A3348]">
                  <span className="text-xs font-medium text-[#7C89A6]">Target Path:</span>
                  <span className="font-mono text-xs text-[#EAF0FA] break-all">
                    {result.sensitivePathCheck.checked}
                  </span>
                </div>

                {result.sensitivePathCheck.reason && (
                  <div className="rounded-xl border border-[#F2A93C]/30 bg-[#F2A93C]/10 px-3.5 py-2.5">
                    <p className="text-xs sm:text-sm text-[#F2A93C]">
                      {result.sensitivePathCheck.reason}
                    </p>
                  </div>
                )}

                {result.sensitivePathCheck.allowed && (
                  <div className="grid grid-cols-2 gap-3">
                    <div className="rounded-xl border border-[#232B3D] bg-[#0E1420] p-3">
                      <p className="text-[11px] text-[#7C89A6]">Status Code</p>
                      <p className="font-mono text-sm font-semibold text-[#EAF0FA] mt-0.5">
                        {result.sensitivePathCheck.statusCode}
                      </p>
                    </div>
                    <div className="rounded-xl border border-[#232B3D] bg-[#0E1420] p-3">
                      <p className="text-[11px] text-[#7C89A6]">Status Terbuka</p>
                      <p
                        className={`font-mono text-sm font-bold mt-0.5 ${
                          result.sensitivePathCheck.exposed ? "text-[#E15252]" : "text-[#3FA796]"
                        }`}
                      >
                        {result.sensitivePathCheck.exposed ? "⚠️ TEREKSPOS" : "✅ AMAN"}
                      </p>
                    </div>
                  </div>
                )}

                {result.sensitivePathCheck.matchedPatterns &&
                  result.sensitivePathCheck.matchedPatterns.length > 0 && (
                    <div className="rounded-xl border border-[#E15252]/30 bg-[#E15252]/5 p-3.5 space-y-2">
                      <p className="text-xs text-[#E15252] font-semibold">
                        Pola Cocok ({result.sensitivePathCheck.matchedPatterns.length}):
                      </p>
                      <div className="flex flex-wrap gap-1.5">
                        {result.sensitivePathCheck.matchedPatterns.map((pattern, idx) => (
                          <span
                            key={idx}
                            className="px-2 py-1 bg-[#0E1420] rounded-md border border-[#232B3D] text-[11px] font-mono text-[#C9D2E3]"
                          >
                            {pattern}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                {result.sensitivePathCheck.preview && (
                  <div className="rounded-xl border border-[#E15252]/30 bg-[#0E1420] p-3.5 space-y-1.5">
                    <p className="text-[11px] font-medium text-[#7C89A6]">
                      Pratinjau Respons (200 Karakter Pertama):
                    </p>
                    <pre className="font-mono text-xs text-[#C9D2E3] whitespace-pre-wrap break-all bg-black/30 p-2.5 rounded-lg">
                      {result.sensitivePathCheck.preview}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Disclaimer */}
          <div className="rounded-2xl border border-[#232B3D]/60 bg-[#141B2A]/50 p-4">
            <p className="text-center text-[11px] text-[#7C89A6] leading-relaxed">
              {result.disclaimer}
            </p>
          </div>
        </div>
      )}

      {/* Sensitive Path Confirmation Modal */}
      {showSensitiveModal && pendingSensitivePath && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 px-4 backdrop-blur-sm animate-in fade-in-50">
          <div className="w-full max-w-md max-h-[90vh] overflow-y-auto rounded-2xl border border-[#E15252]/40 bg-[#141B2A] p-5 sm:p-6 shadow-2xl space-y-4">
            <div className="flex items-center gap-2.5 text-[#E15252]">
              <AlertTriangle className="h-5 w-5 shrink-0" />
              <h3 className="font-mono text-sm font-bold uppercase tracking-wide">
                Konfirmasi Uji Path Sensitif
              </h3>
            </div>

            <p className="text-xs sm:text-sm text-[#C9D2E3] leading-relaxed">
              Sistem akan mengirimkan satu permintaan pembacaan (read-only) ke alamat berikut:
            </p>

            <div className="rounded-xl bg-[#0E1420] border border-[#2A3348] p-3">
              <code className="font-mono text-xs text-[#EAF0FA] break-all">
                {pendingSensitivePath}
              </code>
            </div>

            <div className="space-y-2 bg-[#0E1420]/50 p-3 rounded-xl border border-[#232B3D]">
              <div className="flex items-start gap-2 text-xs text-[#7C89A6]">
                <span className="text-[#3FA796] font-bold">✓</span>
                <span>Hanya memeriksa path spesifik yang Anda masukkan</span>
              </div>
              <div className="flex items-start gap-2 text-xs text-[#7C89A6]">
                <span className="text-[#3FA796] font-bold">✓</span>
                <span>Tidak ada isi file yang disimpan secara permanen</span>
              </div>
              <div className="flex items-start gap-2 text-xs text-[#7C89A6]">
                <span className="text-[#3FA796] font-bold">✓</span>
                <span>Hanya menampilkan pratinjau jika terdeteksi pola kredensial</span>
              </div>
            </div>

            <label className="flex items-start gap-3 text-xs text-[#C9D2E3] cursor-pointer select-none">
              <input
                type="checkbox"
                checked={sensitiveOwnerAck}
                onChange={(e) => setSensitiveOwnerAck(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-[#2A3348] bg-[#0E1420] accent-[#E15252] cursor-pointer"
              />
              <span>
                Saya menyatakan secara sah bahwa saya adalah pemilik domain ini atau memiliki izin tertulis untuk pengujian.
              </span>
            </label>

            <div className="flex flex-col-reverse sm:flex-row gap-2.5 pt-2">
              <button
                onClick={() => setShowSensitiveModal(false)}
                className="w-full sm:flex-1 rounded-xl border border-[#2A3348] px-4 py-2.5 text-xs font-semibold text-[#C9D2E3] hover:bg-[#1A2233] transition"
              >
                Batal
              </button>
              <button
                onClick={confirmSensitiveScan}
                disabled={!sensitiveOwnerAck}
                className="w-full sm:flex-1 rounded-xl bg-[#E15252] px-4 py-2.5 text-xs font-semibold text-white transition hover:bg-[#EC6E6E] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-40"
              >
                Setuju & Periksa
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}