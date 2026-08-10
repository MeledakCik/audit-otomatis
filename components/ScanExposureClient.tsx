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
}

interface ScanResult {
  url: string;
  finalUrl: string;
  redirected: boolean;
  headers: Record<string, string>;
  findings: Finding[];
  sensitivePathCheck: SensitivePathResult | null;
  disclaimer: string;
}

const SEVERITY_STYLES: Record<Severity, { label: string; dot: string; text: string; ring: string }> = {
  critical: { label: "Critical", dot: "bg-[#E15252]", text: "text-[#E15252]", ring: "ring-[#E15252]/30" },
  medium: { label: "Medium", dot: "bg-[#F2A93C]", text: "text-[#F2A93C]", ring: "ring-[#F2A93C]/30" },
  low: { label: "Low", dot: "bg-[#3FA796]", text: "text-[#3FA796]", ring: "ring-[#3FA796]/30" },
  info: { label: "Info", dot: "bg-[#7C89A6]", text: "text-[#7C89A6]", ring: "ring-[#7C89A6]/30" },
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
          ownershipConfirmed: withSensitivePath ? true : undefined,
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
      setError("Enter the full path you want to check, e.g. https://example.com/.env");
      return;
    }
    setPendingSensitivePath(sensitivePath.trim());
    setSensitiveOwnerAck(false);
    setShowSensitiveModal(true);
  }

  function confirmSensitiveScan() {
    if (!pendingSensitivePath || !sensitiveOwnerAck) return;
    setShowSensitiveModal(false);
    setOwnershipConfirmed(true);
    runScan(pendingSensitivePath);
  }

  return (
    <div className="mx-auto max-w-3xl px-6 pb-24">
      {/* ---- Big disclaimer ---- */}
      <div className="mb-8 rounded-lg border border-[#E15252]/40 bg-[#E15252]/10 px-5 py-4">
        <p className="font-mono text-sm font-semibold uppercase tracking-wide text-[#E15252]">
          Passive check only. No exploitation performed.
        </p>
        <p className="mt-1 text-sm text-[#C9D2E3]">
          Sentinel-ID makes a small number of read-only requests to the target you provide. It never
          brute-forces paths, writes data, or accesses anything not explicitly listed by you or found in
          the page's own public source.
        </p>
      </div>

      {/* ---- Form ---- */}
      <div className="rounded-xl border border-[#232B3D] bg-[#141B2A] p-6">
        <label htmlFor="target-url" className="block font-mono text-xs uppercase tracking-widest text-[#7C89A6]">
          Target URL
        </label>
        <input
          id="target-url"
          type="text"
          placeholder="https://example.com"
          value={urlInput}
          onChange={(e) => setUrlInput(e.target.value)}
          className="mt-2 w-full rounded-md border border-[#2A3348] bg-[#0E1420] px-4 py-3 font-mono text-[#EAF0FA] placeholder:text-[#4C5A78] focus:border-[#3FA796] focus:outline-none focus:ring-2 focus:ring-[#3FA796]/40"
        />

        <label className="mt-4 flex items-start gap-3 text-sm text-[#C9D2E3]">
          <input
            type="checkbox"
            checked={ownershipConfirmed}
            onChange={(e) => setOwnershipConfirmed(e.target.checked)}
            className="mt-0.5 h-4 w-4 rounded border-[#2A3348] bg-[#0E1420] accent-[#3FA796]"
          />
          <span>I own, or have explicit permission to scan, this target.</span>
        </label>

        <button
          onClick={handleScanClick}
          disabled={loading}
          className="mt-5 w-full rounded-md bg-[#3FA796] px-4 py-3 font-mono text-sm font-semibold uppercase tracking-wide text-[#0E1420] transition hover:bg-[#57C4B2] disabled:cursor-not-allowed disabled:opacity-50"
        >
          {loading ? "Scanning…" : "Run passive scan"}
        </button>

        {/* ---- Optional sensitive path analyzer ---- */}
        <div className="mt-6 border-t border-[#232B3D] pt-5">
          <label htmlFor="sensitive-path" className="block font-mono text-xs uppercase tracking-widest text-[#7C89A6]">
            Check a specific path (optional)
          </label>
          <p className="mt-1 text-xs text-[#7C89A6]">
            Only checks the exact path you type — no guessing, no directory enumeration.
          </p>
          <div className="mt-2 flex flex-col gap-2 sm:flex-row">
            <input
              id="sensitive-path"
              type="text"
              placeholder="https://example.com/.env"
              value={sensitivePath}
              onChange={(e) => setSensitivePath(e.target.value)}
              className="flex-1 rounded-md border border-[#2A3348] bg-[#0E1420] px-4 py-2.5 font-mono text-sm text-[#EAF0FA] placeholder:text-[#4C5A78] focus:border-[#F2A93C] focus:outline-none focus:ring-2 focus:ring-[#F2A93C]/40"
            />
            <button
              onClick={handleSensitiveCheckClick}
              disabled={loading}
              className="rounded-md border border-[#F2A93C]/50 bg-transparent px-4 py-2.5 font-mono text-sm font-semibold text-[#F2A93C] transition hover:bg-[#F2A93C]/10 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Check path
            </button>
          </div>
        </div>

        {error && <p className="mt-4 text-sm text-[#E15252]">{error}</p>}
      </div>

      {/* ---- Sensitive path confirmation modal ---- */}
      {showSensitiveModal && pendingSensitivePath && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 px-4">
          <div className="w-full max-w-md rounded-xl border border-[#E15252]/50 bg-[#141B2A] p-6">
            <p className="font-mono text-sm font-semibold uppercase tracking-wide text-[#E15252]">
              You're about to check a sensitive path
            </p>
            <p className="mt-3 text-sm text-[#C9D2E3]">
              Sentinel-ID will make a single, read-only request to:
            </p>
            <p className="mt-2 break-all rounded-md bg-[#0E1420] px-3 py-2 font-mono text-xs text-[#EAF0FA]">
              {pendingSensitivePath}
            </p>
            <p className="mt-3 text-sm text-[#C9D2E3]">
              Only scan assets you own or are authorized to test. No file contents are stored — only a
              100-character preview is shown, and only if a credential-shaped pattern is found.
            </p>
            <label className="mt-4 flex items-start gap-3 text-sm text-[#C9D2E3]">
              <input
                type="checkbox"
                checked={sensitiveOwnerAck}
                onChange={(e) => setSensitiveOwnerAck(e.target.checked)}
                className="mt-0.5 h-4 w-4 rounded border-[#2A3348] bg-[#0E1420] accent-[#E15252]"
              />
              <span>I own this domain, or have explicit written permission to test it.</span>
            </label>
            <div className="mt-5 flex gap-3">
              <button
                onClick={() => setShowSensitiveModal(false)}
                className="flex-1 rounded-md border border-[#2A3348] px-4 py-2.5 text-sm text-[#C9D2E3] hover:bg-[#1A2233]"
              >
                Cancel
              </button>
              <button
                onClick={confirmSensitiveScan}
                disabled={!sensitiveOwnerAck}
                className="flex-1 rounded-md bg-[#E15252] px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-[#EC6E6E] disabled:cursor-not-allowed disabled:opacity-40"
              >
                Confirm & check
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ---- Results ---- */}
      {result && (
        <div className="mt-8 space-y-6">
          <div className="rounded-xl border border-[#232B3D] bg-[#141B2A] p-6">
            <p className="font-mono text-xs uppercase tracking-widest text-[#7C89A6]">Scanned</p>
            <p className="mt-1 break-all font-mono text-sm text-[#EAF0FA]">{result.finalUrl}</p>
            {result.redirected && (
              <p className="mt-1 text-xs text-[#7C89A6]">Followed 1 same-origin redirect.</p>
            )}
          </div>

          {/* Headers leak card */}
          <div className="rounded-xl border border-[#232B3D] bg-[#141B2A] p-6">
            <h3 className="font-mono text-sm font-semibold uppercase tracking-wide text-[#EAF0FA]">
              Headers leak
            </h3>
            <dl className="mt-3 space-y-2 font-mono text-xs">
              {["server", "x-powered-by"].map((h) => (
                <div key={h} className="flex justify-between gap-4 border-b border-[#232B3D] py-1.5">
                  <dt className="text-[#7C89A6]">{h}</dt>
                  <dd className="break-all text-right text-[#C9D2E3]">{result.headers[h] ?? "—"}</dd>
                </div>
              ))}
            </dl>
          </div>

          {/* Exposure findings card */}
          <div className="rounded-xl border border-[#232B3D] bg-[#141B2A] p-6">
            <h3 className="font-mono text-sm font-semibold uppercase tracking-wide text-[#EAF0FA]">
              Exposure found
            </h3>
            {result.findings.length === 0 ? (
              <p className="mt-3 text-sm text-[#7C89A6]">No exposure patterns found in this pass.</p>
            ) : (
              <ul className="mt-3 space-y-3">
                {result.findings.map((f, i) => {
                  const s = SEVERITY_STYLES[f.severity];
                  return (
                    <li key={i} className={`rounded-lg border border-[#232B3D] p-4 ring-1 ${s.ring}`}>
                      <div className="flex items-center gap-2">
                        <span className={`h-2 w-2 rounded-full ${s.dot}`} />
                        <span className={`font-mono text-xs font-semibold uppercase tracking-wide ${s.text}`}>
                          {s.label}
                        </span>
                        <span className="font-mono text-xs text-[#7C89A6]">{f.type}</span>
                      </div>
                      <p className="mt-2 break-all text-sm text-[#EAF0FA]">{f.evidence}</p>
                      <p className="mt-1 text-xs text-[#7C89A6]">{f.location}</p>
                      <p className="mt-2 text-sm text-[#8FE3D3]">{f.recommendation}</p>
                    </li>
                  );
                })}
              </ul>
            )}
          </div>

          {/* Sensitive path result */}
          {result.sensitivePathCheck && (
            <div className="rounded-xl border border-[#232B3D] bg-[#141B2A] p-6">
              <h3 className="font-mono text-sm font-semibold uppercase tracking-wide text-[#EAF0FA]">
                Path check
              </h3>
              <p className="mt-2 break-all font-mono text-xs text-[#C9D2E3]">
                {result.sensitivePathCheck.checked}
              </p>
              {result.sensitivePathCheck.reason && (
                <p className="mt-2 text-sm text-[#7C89A6]">{result.sensitivePathCheck.reason}</p>
              )}
              {result.sensitivePathCheck.allowed && (
                <div className="mt-3 space-y-1 text-sm">
                  <p className="text-[#C9D2E3]">
                    Status: <span className="font-mono text-[#EAF0FA]">{result.sensitivePathCheck.statusCode}</span>
                  </p>
                  <p className="text-[#C9D2E3]">
                    Exposed:{" "}
                    <span className={result.sensitivePathCheck.exposed ? "text-[#E15252]" : "text-[#3FA796]"}>
                      {String(result.sensitivePathCheck.exposed)}
                    </span>
                  </p>
                  {result.sensitivePathCheck.preview && (
                    <p className="mt-2 break-all rounded-md bg-[#0E1420] px-3 py-2 font-mono text-xs text-[#C9D2E3]">
                      {result.sensitivePathCheck.preview}
                    </p>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
