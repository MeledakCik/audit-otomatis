"use client";

import { useState, useEffect } from "react";
import {
  PieChart,
  Pie,
  Cell,
  ResponsiveContainer,
  Legend,
  Tooltip,
} from "recharts";

interface ScriptInfo {
  src: string;
  library: string | null;
  version: string | null;
  size: number;
  vulnerable: boolean;
  cve: string | null;
  cveDescription: string | null;
  cvss: number | null;
  outdated: boolean;
  framework: string | null;
  confidence: number;
}

interface TrackerInfo {
  domain: string;
  category: "Analytics" | "Ads" | "Session Replay" | "Social" | "CDN";
  count: number;
  risk: "low" | "medium" | "high";
  icon?: string;
}

interface FrameworkInfo {
  name: string;
  version: string | null;
  confidence: number;
}

interface ScanResult {
  url: string;
  scripts: ScriptInfo[];
  trackers: TrackerInfo[];
  frameworks: FrameworkInfo[];
  risk_score: number;
  total_scripts: number;
  vulnerable_count: number;
  outdated_count: number;
  tracker_count: number;
  scan_duration_ms: number;
  scanned_at: string;
  cached?: boolean;
  cachedAt?: string;
}

const CATEGORY_COLORS = {
  Analytics: "#3FA796",
  Ads: "#F2A93C",
  "Session Replay": "#E15252",
  Social: "#7C89A6",
  CDN: "#57C4B2",
};

const RISK_COLORS = {
  low: "bg-[#3FA796]/20 text-[#3FA796]",
  medium: "bg-[#F2A93C]/20 text-[#F2A93C]",
  high: "bg-[#E15252]/20 text-[#E15252]",
};

function normalizeUrl(input: string): string | null {
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

function formatFileSize(bytes: number): string {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1048576) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1048576).toFixed(1) + " MB";
}

export default function JSScannerClient() {
  const [urlInput, setUrlInput] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [isMounted, setIsMounted] = useState(false);

  useEffect(() => {
    setIsMounted(true);
  }, []);

  async function runScan() {
    const normalized = normalizeUrl(urlInput);
    if (!normalized) {
      setError("Masukkan URL yang valid, contoh: https://example.com");
      return;
    }

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      console.log("🚀 Sending request to /api/scan/js");
      
      const res = await fetch("/api/js", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: normalized }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || `Server error: ${res.status}`);
        return;
      }

      setResult(data as ScanResult);
    } catch (err) {
      console.error("❌ Fetch error:", err);
      setError("Tidak dapat terhubung ke server scanner. Periksa koneksi Anda.");
    } finally {
      setLoading(false);
    }
  }

  const riskLevel = result
    ? result.risk_score >= 50
      ? "High"
      : result.risk_score >= 25
      ? "Medium"
      : "Low"
    : "N/A";

  const riskColor = result
    ? result.risk_score >= 50
      ? "text-[#E15252]"
      : result.risk_score >= 25
      ? "text-[#F2A93C]"
      : "text-[#3FA796]"
    : "";

  const chartData = result
    ? Object.entries(
        result.trackers.reduce((acc, t) => {
          acc[t.category] = (acc[t.category] || 0) + t.count;
          return acc;
        }, {} as Record<string, number>)
      ).map(([name, value]) => ({ name, value }))
    : [];

  return (
    <div className="mx-auto max-w-5xl px-4 sm:px-6">
      {/* Input Section */}
      <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4 sm:p-6 lg:p-8">
        <div className="flex items-center gap-3 mb-4">
          <span className="font-mono text-xs uppercase tracking-widest text-[#3FA796]">
            Target URL
          </span>
          <span className="h-px flex-1 bg-[#232B3D]" />
        </div>

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3 sm:gap-4">
          <div className="flex-1">
            <div className="flex items-center gap-2 sm:gap-3 bg-[#0E1420] rounded-lg border border-[#2A3348] px-3 sm:px-4 py-2.5 sm:py-3 focus-within:border-[#3FA796] focus-within:ring-2 focus-within:ring-[#3FA796]/40 transition-all">
              <span className="text-[#4C5A78] font-mono text-xs sm:text-sm flex-shrink-0">https://</span>
              <input
                type="text"
                placeholder="example.com"
                value={urlInput.replace(/^https?:\/\//, "")}
                onChange={(e) => setUrlInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && runScan()}
                className="flex-1 bg-transparent font-mono text-sm sm:text-base text-[#EAF0FA] placeholder:text-[#4C5A78] focus:outline-none min-w-0"
              />
            </div>
          </div>
          <button
            onClick={runScan}
            disabled={loading}
            className="rounded-md bg-[#3FA796] px-6 sm:px-8 py-2.5 sm:py-3 font-mono text-sm font-semibold uppercase tracking-wide text-[#0E1420] transition hover:bg-[#57C4B2] disabled:cursor-not-allowed disabled:opacity-50 whitespace-nowrap"
          >
            {loading ? (
              <span className="flex items-center gap-2">
                <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                </svg>
                Scanning
              </span>
            ) : (
              "Scan JS"
            )}
          </button>
        </div>

        <div className="mt-4 flex items-start gap-2 rounded-lg border border-[#F2A93C]/20 bg-[#F2A93C]/5 px-3 py-2">
          <span className="text-[#F2A93C] text-sm flex-shrink-0">⚠️</span>
          <p className="text-xs text-[#C9D2E3]">
            For educational asset inventory purposes. Detects public JS libraries and trackers via server-side proxy request.
          </p>
        </div>

        {error && (
          <div className="mt-4 rounded-lg border border-[#E15252]/40 bg-[#E15252]/10 px-4 py-3">
            <p className="text-sm text-[#E15252]">{error}</p>
          </div>
        )}
      </div>

      {/* Results */}
      {result && (
        <div className="mt-6 sm:mt-8 space-y-4 sm:space-y-6">
          {/* Header / Risk Score */}
          <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4 sm:p-6">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div className="w-full sm:w-auto">
                <p className="text-xs text-[#7C89A6]">Scanned URL</p>
                <p className="font-mono text-sm sm:text-base text-[#EAF0FA] break-all">{result.url}</p>
                {result.cached && (
                  <span className="inline-block mt-1 text-xs text-[#3FA796]">✓ Cached result</span>
                )}
              </div>
              <div className="w-full sm:w-auto text-left sm:text-right">
                <p className="text-xs text-[#7C89A6]">Supply Chain Risk Score</p>
                <p className={`text-2xl sm:text-3xl font-bold ${riskColor}`}>
                  {result.risk_score}
                  <span className="text-sm font-normal text-[#7C89A6]">/100</span>
                </p>
                <p className={`text-sm font-semibold ${riskColor}`}>
                  {riskLevel} Risk
                </p>
              </div>
            </div>
            
            <div className="mt-4 grid grid-cols-2 sm:grid-cols-4 gap-3 sm:gap-4">
              <div>
                <p className="text-xs text-[#7C89A6]">Total Scripts</p>
                <p className="text-lg sm:text-xl font-semibold text-[#EAF0FA]">
                  {result.total_scripts}
                </p>
              </div>
              {result.vulnerable_count > 0 && (
                <div>
                  <p className="text-xs text-[#7C89A6]">Vulnerable</p>
                  <p className="text-lg sm:text-xl font-semibold text-[#E15252]">
                    {result.vulnerable_count}
                  </p>
                </div>
              )}
              {result.outdated_count > 0 && (
                <div>
                  <p className="text-xs text-[#7C89A6]">Outdated</p>
                  <p className="text-lg sm:text-xl font-semibold text-[#F2A93C]">
                    {result.outdated_count}
                  </p>
                </div>
              )}
              <div>
                <p className="text-xs text-[#7C89A6]">Trackers</p>
                <p className="text-lg sm:text-xl font-semibold text-[#EAF0FA]">
                  {result.tracker_count}
                </p>
              </div>
              <div className="col-span-2 sm:col-span-1">
                <p className="text-xs text-[#7C89A6]">Scan Duration</p>
                <p className="text-lg sm:text-xl font-semibold text-[#EAF0FA]">
                  {(result.scan_duration_ms / 1000).toFixed(1)}s
                </p>
              </div>
            </div>

            {/* Frameworks detected */}
            {result.frameworks && result.frameworks.length > 0 && (
              <div className="mt-4 pt-4 border-t border-[#232B3D]">
                <p className="text-xs text-[#7C89A6] mb-2">Frameworks Detected</p>
                <div className="flex flex-wrap gap-2">
                  {result.frameworks.map((fw, idx) => (
                    <span key={idx} className="px-3 py-1 rounded-full bg-[#0E1420] border border-[#2A3348] text-xs text-[#EAF0FA]">
                      {fw.name}
                      {fw.version && <span className="text-[#7C89A6] ml-1">v{fw.version}</span>}
                      <span className="text-[#4C5A78] ml-1">({fw.confidence}%)</span>
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>

          {/* Two-column layout */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4 sm:gap-6">
            {/* Scripts List */}
            <div className="lg:col-span-2 rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4 sm:p-6">
              <h3 className="font-mono text-sm font-semibold uppercase tracking-wide text-[#EAF0FA] mb-4">
                JavaScript Libraries
              </h3>
              <div className="space-y-3 max-h-[500px] overflow-y-auto pr-2 custom-scrollbar">
                {result.scripts.length === 0 ? (
                  <p className="text-sm text-[#7C89A6] text-center py-8">No external JS found.</p>
                ) : (
                  result.scripts.map((script, idx) => {
                    const isVuln = script.vulnerable;
                    const isOutdated = script.outdated && !script.vulnerable;
                    
                    return (
                      <div
                        key={idx}
                        className={`rounded-lg border p-3 sm:p-4 ${
                          isVuln
                            ? "border-[#E15252]/40 bg-[#E15252]/10"
                            : isOutdated
                            ? "border-[#F2A93C]/30 bg-[#F2A93C]/10"
                            : "border-[#232B3D] bg-[#0E1420]"
                        }`}
                      >
                        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
                          <div className="flex-1 min-w-0 w-full">
                            <p className="font-mono text-xs text-[#7C89A6] truncate" title={script.src}>
                              {script.src}
                            </p>
                            <div className="flex flex-wrap items-center gap-2 mt-1">
                              <span className="font-mono text-sm text-[#EAF0FA]">
                                {script.library || "Unknown"}
                              </span>
                              {script.version && (
                                <span className="text-xs text-[#7C89A6]">
                                  v{script.version}
                                </span>
                              )}
                              {script.confidence && script.confidence > 50 && (
                                <span className="text-xs text-[#4C5A78]">
                                  {script.confidence}%
                                </span>
                              )}
                              {script.size > 0 && (
                                <span className="text-xs text-[#4C5A78]">
                                  {formatFileSize(script.size)}
                                </span>
                              )}
                            </div>
                          </div>
                          <div className="flex flex-col items-start sm:items-end gap-1 w-full sm:w-auto">
                            {isVuln ? (
                              <span className="px-2 py-0.5 rounded-full bg-[#E15252]/20 text-[#E15252] text-xs font-semibold">
                                ⚠️ VULNERABLE
                              </span>
                            ) : isOutdated ? (
                              <span className="px-2 py-0.5 rounded-full bg-[#F2A93C]/20 text-[#F2A93C] text-xs font-semibold">
                                Outdated
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 rounded-full bg-[#3FA796]/20 text-[#3FA796] text-xs font-semibold">
                                ✓ OK
                              </span>
                            )}
                            {script.cve && (
                              <a
                                href={`https://nvd.nist.gov/vuln/detail/${script.cve}`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="text-xs text-[#E15252] hover:text-[#EC6E6E] transition font-mono"
                              >
                                {script.cve}
                                {script.cvss && <span className="ml-1 text-[#7C89A6]">CVSS {script.cvss}</span>}
                              </a>
                            )}
                          </div>
                        </div>
                        {script.cveDescription && (
                          <p className="mt-2 text-xs text-[#C9D2E3] border-t border-[#232B3D]/50 pt-2">
                            {script.cveDescription}
                          </p>
                        )}
                      </div>
                    );
                  })
                )}
              </div>
            </div>

            {/* Chart */}
            <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4 sm:p-6">
              <h3 className="font-mono text-sm font-semibold uppercase tracking-wide text-[#EAF0FA] mb-4">
                Tracker Categories
              </h3>
              {chartData.length > 0 && isMounted ? (
                <>
                  <div className="h-[200px] sm:h-[250px]">
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={chartData}
                          cx="50%"
                          cy="50%"
                          innerRadius={35}
                          outerRadius={70}
                          paddingAngle={2}
                          dataKey="value"
                        >
                          {chartData.map((entry, index) => (
                            <Cell
                              key={`cell-${index}`}
                              fill={
                                CATEGORY_COLORS[
                                  entry.name as keyof typeof CATEGORY_COLORS
                                ] || "#7C89A6"
                              }
                            />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{
                            backgroundColor: "#141B2A",
                            borderColor: "#232B3D",
                            color: "#EAF0FA",
                            borderRadius: "8px",
                            padding: "8px 12px",
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>
                  <Legend
                    formatter={(value) => (
                      <span className="text-xs text-[#C9D2E3]">{value}</span>
                    )}
                    className="mt-2"
                  />
                </>
              ) : (
                <p className="text-sm text-[#7C89A6] text-center py-8">
                  No trackers detected
                </p>
              )}
            </div>
          </div>

          {/* Trackers Table */}
          {result.trackers.length > 0 && (
            <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4 sm:p-6 overflow-hidden">
              <h3 className="font-mono text-sm font-semibold uppercase tracking-wide text-[#EAF0FA] mb-4">
                3rd-party Domains
              </h3>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#232B3D] text-left text-xs text-[#7C89A6]">
                      <th className="pb-2 font-mono px-2">Domain</th>
                      <th className="pb-2 font-mono px-2">Category</th>
                      <th className="pb-2 font-mono px-2 text-right">Count</th>
                      <th className="pb-2 font-mono px-2 text-right">Privacy Risk</th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.trackers.map((tracker, idx) => (
                      <tr
                        key={idx}
                        className="border-b border-[#232B3D]/50 last:border-0 hover:bg-[#0E1420]/50 transition"
                      >
                        <td className="py-2 px-2 font-mono text-xs text-[#C9D2E3]">
                          {tracker.icon && <span className="mr-1">{tracker.icon}</span>}
                          {tracker.domain}
                        </td>
                        <td className="py-2 px-2 text-xs text-[#C9D2E3]">
                          {tracker.category}
                        </td>
                        <td className="py-2 px-2 text-xs text-[#C9D2E3] text-right">
                          {tracker.count}
                        </td>
                        <td className="py-2 px-2 text-right">
                          <span
                            className={`px-2 py-0.5 rounded-full text-xs font-semibold ${
                              tracker.risk === "high"
                                ? "bg-[#E15252]/20 text-[#E15252]"
                                : tracker.risk === "medium"
                                ? "bg-[#F2A93C]/20 text-[#F2A93C]"
                                : "bg-[#3FA796]/20 text-[#3FA796]"
                            }`}
                          >
                            {tracker.risk.toUpperCase()}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* Scan Info */}
          <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4">
            <p className="text-center text-xs text-[#4C5A78]">
              Scanned at {new Date(result.scanned_at).toLocaleString()}
              {result.cached && " (cached)"}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}