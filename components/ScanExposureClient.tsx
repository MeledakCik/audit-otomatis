"use client";

import { useState } from "react";

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
  const [pendingSensitivePath, setPendingSensitivePath] = useState<
    string | null
  >(null);
  const [sensitiveOwnerAck, setSensitiveOwnerAck] = useState(false);

  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);

  async function runScan(withSensitivePath?: string) {
    const normalized = normalizeToHttps(urlInput);
    if (!normalized) {
      setError("Enter a valid URL, e.g. https://example.com");
      return;
    }
    if (!ownershipConfirmed) {
      setError("Confirm you own or have permission to scan this target first.");
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
        setError(data.error ?? "Scan failed.");
        return;
      }
      setResult(data as ScanResult);
    } catch {
      setError("Couldn't reach the scanner. Try again.");
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
      setError("Enter a valid homepage URL first.");
      return;
    }
    if (!sensitivePath.trim()) {
      setError(
        "Enter the full path you want to check, e.g. https://example.com/.env",
      );
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
    <div className="mx-auto max-w-4xl px-6 pb-24">
      {/* ---- Hero Section ---- */}
      <div className="mb-10">
        <div className="flex items-center gap-3 mb-3">
          <span className="font-mono text-xs uppercase tracking-[0.25em] text-[#3FA796]">
            Sentinel-ID / Passive Recon
          </span>
        </div>
        <h1 className="text-3xl font-semibold leading-tight tracking-tight text-[#EAF0FA] sm:text-4xl">
          Tech Stack Fingerprint
        </h1>
        <p className="mt-2 text-[#A9B4CC]">
          Passive homepage fingerprint – headers + HTML markers only. Educational
          asset inventory, no CVE lookup.
        </p>
      </div>

      {/* ---- Main Card ---- */}
      <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-8">
        {/* Target Domain Section */}
        <div className="flex items-center gap-3 mb-2">
          <span className="font-mono text-xs uppercase tracking-widest text-[#3FA796]">
            Target Domain
          </span>
          <span className="h-px flex-1 bg-[#232B3D]" />
        </div>

        <div className="mt-4">
          <div className="flex items-center gap-3 bg-[#0E1420] rounded-lg border border-[#2A3348] px-4 py-3 focus-within:border-[#3FA796] focus-within:ring-2 focus-within:ring-[#3FA796]/40 transition-all">
            <span className="text-[#4C5A78] font-mono text-sm">https://</span>
            <input
              type="text"
              placeholder="sentinel-id.net"
              value={urlInput.replace(/^https?:\/\//, "")}
              onChange={(e) => setUrlInput(e.target.value)}
              className="flex-1 bg-transparent font-mono text-[#EAF0FA] placeholder:text-[#4C5A78] focus:outline-none"
            />
          </div>

          <div className="mt-3 flex items-start gap-2 rounded-lg border border-[#F2A93C]/20 bg-[#F2A93C]/5 px-3 py-2">
            <span className="text-[#F2A93C] text-sm">⚠️</span>
            <p className="text-xs text-[#C9D2E3]">
              For educational asset inventory purposes. Detects public tech
              markers only, from one plain GET request to the homepage (headers +
              HTML). No CVE lookup, no vulnerability database, no bruteforce.
            </p>
          </div>
        </div>

        <div className="mt-6 flex flex-wrap items-center gap-4">
          <label className="flex items-start gap-3 text-sm text-[#C9D2E3]">
            <input
              type="checkbox"
              checked={ownershipConfirmed}
              onChange={(e) => setOwnershipConfirmed(e.target.checked)}
              className="mt-0.5 h-4 w-4 rounded border-[#2A3348] bg-[#0E1420] accent-[#3FA796]"
            />
            <span>I own or have permission</span>
          </label>

          <button
            onClick={handleScanClick}
            disabled={loading}
            className="ml-auto rounded-md bg-[#3FA796] px-8 py-2.5 font-mono text-sm font-semibold uppercase tracking-wide text-[#0E1420] transition hover:bg-[#57C4B2] disabled:cursor-not-allowed disabled:opacity-50"
          >
            {loading ? "Scanning…" : "Fingerprint"}
          </button>
        </div>

        {/* ---- Optional sensitive path checker ---- */}
        <div className="mt-6 pt-6 border-t border-[#232B3D]">
          <div className="flex flex-wrap items-center gap-3">
            <input
              type="text"
              placeholder="Check specific path (e.g., /wp-config.php)"
              value={sensitivePath}
              onChange={(e) => setSensitivePath(e.target.value)}
              className="flex-1 min-w-[200px] rounded-md border border-[#2A3348] bg-[#0E1420] px-4 py-2 font-mono text-sm text-[#EAF0FA] placeholder:text-[#4C5A78] focus:border-[#F2A93C] focus:outline-none focus:ring-2 focus:ring-[#F2A93C]/40"
            />
            <button
              onClick={handleSensitiveCheckClick}
              disabled={loading}
              className="rounded-md border border-[#F2A93C]/50 bg-transparent px-4 py-2 font-mono text-sm font-semibold text-[#F2A93C] transition hover:bg-[#F2A93C]/10 disabled:cursor-not-allowed disabled:opacity-50 whitespace-nowrap"
            >
              Check Path
            </button>
          </div>
          <p className="mt-1.5 text-xs text-[#7C89A6]">
            Optional: check a specific path for exposed credentials (requires
            ownership confirmation)
          </p>
        </div>

        {error && (
          <div className="mt-4 rounded-lg border border-[#E15252]/40 bg-[#E15252]/10 px-4 py-3">
            <p className="text-sm text-[#E15252]">{error}</p>
          </div>
        )}
      </div>

      {/* ---- Results ---- */}
      {result && (
        <div className="mt-8 space-y-6">
          {/* Summary Card */}
          {result.summary && (
            <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-6">
              <div className="flex items-center justify-between flex-wrap gap-4">
                <div>
                  <p className="font-mono text-xs uppercase tracking-widest text-[#7C89A6]">
                    Scan Summary
                  </p>
                  <p className="mt-1 text-sm text-[#C9D2E3]">
                    {result.summary.secure
                      ? "✅ No security issues detected"
                      : `⚠️ Found ${result.summary.totalFindings} issue(s)`}
                  </p>
                </div>
                <div className="flex gap-4 flex-wrap">
                  {result.summary.critical > 0 && (
                    <span className="flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-full bg-[#E15252]" />
                      <span className="text-xs font-mono text-[#E15252]">
                        {result.summary.critical} Critical
                      </span>
                    </span>
                  )}
                  {result.summary.medium > 0 && (
                    <span className="flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-full bg-[#F2A93C]" />
                      <span className="text-xs font-mono text-[#F2A93C]">
                        {result.summary.medium} Medium
                      </span>
                    </span>
                  )}
                  {result.summary.low > 0 && (
                    <span className="flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-full bg-[#3FA796]" />
                      <span className="text-xs font-mono text-[#3FA796]">
                        {result.summary.low} Low
                      </span>
                    </span>
                  )}
                  {result.summary.info > 0 && (
                    <span className="flex items-center gap-1.5">
                      <span className="h-2 w-2 rounded-full bg-[#7C89A6]" />
                      <span className="text-xs font-mono text-[#7C89A6]">
                        {result.summary.info} Info
                      </span>
                    </span>
                  )}
                </div>
              </div>
              {result.timestamp && (
                <p className="mt-2 text-xs text-[#4C5A78]">
                  Scanned: {new Date(result.timestamp).toLocaleString()}
                </p>
              )}
            </div>
          )}

          {/* Target info */}
          <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-6">
            <div className="flex items-center gap-3">
              <span className="font-mono text-xs uppercase tracking-widest text-[#3FA796]">
                Target
              </span>
              <span className="h-px flex-1 bg-[#232B3D]" />
            </div>
            <p className="mt-3 break-all font-mono text-sm text-[#EAF0FA]">
              {result.url}
              {result.redirected && (
                <span className="ml-2 text-xs text-[#7C89A6]">
                  → redirected to {result.finalUrl}
                </span>
              )}
            </p>
          </div>

          {/* Headers */}
          <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-6">
            <div className="flex items-center gap-3 mb-4">
              <span className="font-mono text-xs uppercase tracking-widest text-[#3FA796]">
                Response Headers
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
                    className="flex flex-wrap justify-between gap-2 border-b border-[#232B3D] py-2"
                  >
                    <span className="text-[#7C89A6]">{key}</span>
                    <span className="text-[#C9D2E3] break-all text-right">
                      {value || "—"}
                    </span>
                  </div>
                ))}
            </div>
          </div>

          {/* Findings */}
          <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-6">
            <div className="flex items-center gap-3 mb-4">
              <span className="font-mono text-xs uppercase tracking-widest text-[#3FA796]">
                Findings
              </span>
              <span className="h-px flex-1 bg-[#232B3D]" />
              <span className="text-xs text-[#7C89A6]">
                {result.findings.length} found
              </span>
            </div>

            {result.findings.length === 0 ? (
              <div className="rounded-lg border border-[#3FA796]/30 bg-[#3FA796]/5 px-4 py-6 text-center">
                <p className="text-sm text-[#3FA796]">
                  ✨ No exposure patterns found
                </p>
                <p className="mt-1 text-xs text-[#7C89A6]">
                  Your homepage appears clean from common exposure patterns
                </p>
              </div>
            ) : (
              <ul className="space-y-4">
                {result.findings.map((f, i) => {
                  const s = SEVERITY_STYLES[f.severity];
                  return (
                    <li
                      key={i}
                      className={`rounded-lg border border-[#232B3D] p-4 ${s.bg} ring-1 ${s.ring}`}
                    >
                      <div className="flex items-start justify-between gap-3">
                        <div className="flex items-center gap-2 min-w-0">
                          <span
                            className={`h-2 w-2 rounded-full ${s.dot} flex-shrink-0`}
                          />
                          <span
                            className={`font-mono text-xs font-semibold uppercase tracking-wide ${s.text} flex-shrink-0`}
                          >
                            {s.label}
                          </span>
                          <span className="font-mono text-xs text-[#7C89A6] truncate">
                            {f.type}
                          </span>
                        </div>
                      </div>
                      <p className="mt-2 break-all text-sm text-[#EAF0FA]">
                        {f.evidence}
                      </p>
                      <p className="mt-1 text-xs text-[#7C89A6] break-all">
                        {f.location}
                      </p>
                      <p className="mt-2 text-sm text-[#8FE3D3]">
                        {f.recommendation}
                      </p>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>

          {/* Sensitive path result */}
          {result.sensitivePathCheck && (
            <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-6">
              <div className="flex items-center gap-3 mb-4">
                <span className="font-mono text-xs uppercase tracking-widest text-[#F2A93C]">
                  Path Check
                </span>
                <span className="h-px flex-1 bg-[#232B3D]" />
              </div>

              <div className="space-y-3">
                <div className="flex flex-wrap items-center gap-2 bg-[#0E1420] rounded-lg px-3 py-2">
                  <span className="text-xs text-[#7C89A6]">Checked:</span>
                  <span className="font-mono text-xs text-[#EAF0FA] break-all">
                    {result.sensitivePathCheck.checked}
                  </span>
                </div>

                {result.sensitivePathCheck.reason && (
                  <div className="rounded-lg border border-[#F2A93C]/30 bg-[#F2A93C]/5 px-3 py-2">
                    <p className="text-sm text-[#F2A93C]">
                      {result.sensitivePathCheck.reason}
                    </p>
                  </div>
                )}

                {result.sensitivePathCheck.allowed && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="rounded-lg border border-[#232B3D] px-3 py-2">
                      <p className="text-xs text-[#7C89A6]">Status Code</p>
                      <p className="font-mono text-sm text-[#EAF0FA]">
                        {result.sensitivePathCheck.statusCode}
                      </p>
                    </div>
                    <div className="rounded-lg border border-[#232B3D] px-3 py-2">
                      <p className="text-xs text-[#7C89A6]">Exposed</p>
                      <p
                        className={`font-mono text-sm font-semibold ${result.sensitivePathCheck.exposed ? "text-[#E15252]" : "text-[#3FA796]"}`}
                      >
                        {result.sensitivePathCheck.exposed ? "⚠️ YES" : "✅ NO"}
                      </p>
                    </div>
                  </div>
                )}

                {result.sensitivePathCheck.matchedPatterns &&
                  result.sensitivePathCheck.matchedPatterns.length > 0 && (
                    <div className="rounded-lg border border-[#E15252]/30 bg-[#E15252]/5 px-3 py-2">
                      <p className="text-xs text-[#E15252] font-semibold">
                        Matched Patterns (
                        {result.sensitivePathCheck.matchedPatterns.length})
                      </p>
                      <div className="mt-1 flex flex-wrap gap-1.5">
                        {result.sensitivePathCheck.matchedPatterns.map(
                          (pattern, idx) => (
                            <span
                              key={idx}
                              className="px-2 py-0.5 bg-[#0E1420] rounded text-xs font-mono text-[#C9D2E3]"
                            >
                              {pattern}
                            </span>
                          ),
                        )}
                      </div>
                    </div>
                  )}

                {result.sensitivePathCheck.preview && (
                  <div className="rounded-lg border border-[#E15252]/30 bg-[#0E1420] px-3 py-2">
                    <p className="text-xs text-[#7C89A6] mb-1">
                      Preview (first 200 chars):
                    </p>
                    <pre className="font-mono text-xs text-[#C9D2E3] whitespace-pre-wrap break-all">
                      {result.sensitivePathCheck.preview}
                    </pre>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Disclaimer */}
          <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4">
            <p className="text-center text-xs text-[#4C5A78]">
              {result.disclaimer}
            </p>
          </div>
        </div>
      )}

      {/* ---- Sensitive path confirmation modal ---- */}
      {showSensitiveModal && pendingSensitivePath && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 px-4">
          <div className="w-full max-w-lg rounded-2xl border border-[#E15252]/40 bg-[#141B2A] p-6 shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <span className="text-2xl">⚠️</span>
              <h3 className="font-mono text-sm font-semibold text-[#E15252]">
                Sensitive Path Check
              </h3>
            </div>

            <p className="text-sm text-[#C9D2E3]">
              You're about to check a potentially sensitive path. This will make
              a single, read-only request to:
            </p>

            <div className="mt-3 rounded-lg bg-[#0E1420] border border-[#2A3348] px-4 py-3">
              <code className="font-mono text-sm text-[#EAF0FA] break-all">
                {pendingSensitivePath}
              </code>
            </div>

            <div className="mt-4 space-y-3">
              <div className="flex items-start gap-2 text-xs text-[#7C89A6]">
                <span className="text-[#3FA796]">✓</span>
                <span>Only checks the exact path you specified</span>
              </div>
              <div className="flex items-start gap-2 text-xs text-[#7C89A6]">
                <span className="text-[#3FA796]">✓</span>
                <span>No file contents are stored permanently</span>
              </div>
              <div className="flex items-start gap-2 text-xs text-[#7C89A6]">
                <span className="text-[#3FA796]">✓</span>
                <span>Only shows preview if credential patterns are found</span>
              </div>
            </div>

            <label className="mt-4 flex items-start gap-3 text-sm text-[#C9D2E3]">
              <input
                type="checkbox"
                checked={sensitiveOwnerAck}
                onChange={(e) => setSensitiveOwnerAck(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-[#2A3348] bg-[#0E1420] accent-[#E15252]"
              />
              <span>
                I confirm I own this domain or have explicit written permission
                to test it.
              </span>
            </label>

            <div className="mt-5 flex gap-3">
              <button
                onClick={() => setShowSensitiveModal(false)}
                className="flex-1 rounded-md border border-[#2A3348] px-4 py-2.5 text-sm text-[#C9D2E3] hover:bg-[#1A2233] transition"
              >
                Cancel
              </button>
              <button
                onClick={confirmSensitiveScan}
                disabled={!sensitiveOwnerAck}
                className="flex-1 rounded-md bg-[#E15252] px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-[#EC6E6E] disabled:cursor-not-allowed disabled:opacity-40"
              >
                Confirm & Check
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}