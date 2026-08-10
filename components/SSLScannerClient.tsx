"use client";

import { useState, useEffect } from "react";
import { 
  Shield, 
  ShieldCheck, 
  ShieldAlert, 
  AlertTriangle, 
  Info, 
  Copy, 
  Check,
  Download,
  FileJson,
  FileKey,
  ChevronDown,
  ChevronRight,
  Clock,
  Calendar,
  Fingerprint,
  Key,
  Link,
  Server,
  Lock,
  Globe
} from "lucide-react";

interface CertificateInfo {
  subject: string;
  issuer: string;
  san: string[];
  valid_from: string;
  valid_to: string;
  days_left: number;
  serial: string;
  fingerprint_sha256: string;
  sig_algo: string;
  key_type: string;
  key_bits: number;
  self_signed: boolean;
  chain_length: number;
}

interface TLSInfo {
  negotiated_version: string;
  supports_deprecated_tls: string[];
  alpn: string | null;
}

interface Finding {
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  type: string;
  description?: string;
}

interface ScanResult {
  host: string;
  port: number;
  grade: string;
  cert: CertificateInfo;
  tls: TLSInfo;
  findings: Finding[];
  scanned_at: string;
  scan_duration_ms: number;
  cached?: boolean;
  cachedAt?: string;
}

const SEVERITY_CONFIG = {
  critical: { color: "text-[#E15252]", bg: "bg-[#E15252]/20", border: "border-[#E15252]/40", icon: ShieldAlert },
  high: { color: "text-[#E15252]", bg: "bg-[#E15252]/10", border: "border-[#E15252]/30", icon: ShieldAlert },
  medium: { color: "text-[#F2A93C]", bg: "bg-[#F2A93C]/10", border: "border-[#F2A93C]/30", icon: AlertTriangle },
  low: { color: "text-[#3FA796]", bg: "bg-[#3FA796]/10", border: "border-[#3FA796]/30", icon: Info },
  info: { color: "text-[#7C89A6]", bg: "bg-[#7C89A6]/10", border: "border-[#7C89A6]/30", icon: Info },
};

function normalizeDomain(input: string): string {
  let raw = input.trim();
  raw = raw.replace(/^https?:\/\//, '');
  raw = raw.split('/')[0];
  return raw;
}

function formatDate(dateStr: string): string {
  const date = new Date(dateStr);
  return date.toLocaleDateString('en-US', { 
    year: 'numeric', 
    month: 'short', 
    day: 'numeric' 
  });
}

function formatDateShort(dateStr: string): string {
  const date = new Date(dateStr);
  return date.toLocaleDateString('en-US', { 
    month: 'short', 
    day: 'numeric' 
  });
}

function getRiskColor(grade: string): string {
  switch (grade) {
    case "A+": return "text-[#3FA796]";
    case "A": return "text-[#57C4B2]";
    case "B": return "text-[#8FE3D3]";
    case "C": return "text-[#F2A93C]";
    case "D": return "text-[#E15252]";
    case "F": return "text-[#E15252]";
    default: return "text-[#7C89A6]";
  }
}

function getGradeBadge(grade: string): { color: string; bg: string; border: string } {
  switch (grade) {
    case "A+":
      return { color: "text-[#3FA796]", bg: "bg-[#3FA796]/20", border: "border-[#3FA796]" };
    case "A":
      return { color: "text-[#57C4B2]", bg: "bg-[#57C4B2]/20", border: "border-[#57C4B2]" };
    case "B":
      return { color: "text-[#8FE3D3]", bg: "bg-[#8FE3D3]/20", border: "border-[#8FE3D3]" };
    case "C":
      return { color: "text-[#F2A93C]", bg: "bg-[#F2A93C]/20", border: "border-[#F2A93C]" };
    case "D":
      return { color: "text-[#E15252]", bg: "bg-[#E15252]/20", border: "border-[#E15252]" };
    case "F":
      return { color: "text-[#E15252]", bg: "bg-[#E15252]/30", border: "border-[#E15252]" };
    default:
      return { color: "text-[#7C89A6]", bg: "bg-[#7C89A6]/20", border: "border-[#7C89A6]" };
  }
}

export default function SSLScannerClient() {
  const [domainInput, setDomainInput] = useState("");
  const [portInput, setPortInput] = useState("443");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<ScanResult | null>(null);
  const [copied, setCopied] = useState<string | null>(null);
  const [showRaw, setShowRaw] = useState(false);
  const [isMounted, setIsMounted] = useState(false);

  useEffect(() => {
    setIsMounted(true);
  }, []);

  async function runScan() {
    const domain = normalizeDomain(domainInput);
    if (!domain) {
      setError("Enter a valid domain, e.g. example.com");
      return;
    }

    const port = parseInt(portInput) || 443;

    setLoading(true);
    setError(null);
    setResult(null);

    try {
      const res = await fetch("/api/ssl", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain: `${domain}:${port}` }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || `Scan failed: ${res.status}`);
        return;
      }

      setResult(data as ScanResult);
    } catch (err) {
      console.error("❌ Fetch error:", err);
      setError("Could not connect to scanner server.");
    } finally {
      setLoading(false);
    }
  }

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const downloadJSON = () => {
    if (!result) return;
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ssl-cert-${result.host}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const downloadPEM = () => {
    // Simulated PEM download - in real implementation would extract raw cert
    if (!result) return;
    const pem = `-----BEGIN CERTIFICATE-----\n[Certificate data would be here]\n-----END CERTIFICATE-----`;
    const blob = new Blob([pem], { type: "application/x-pem-file" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `ssl-cert-${result.host}.pem`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const gradeBadge = result ? getGradeBadge(result.grade) : { color: "", bg: "", border: "" };

  // Validity timeline
  const getValidityPosition = (validFrom: string, validTo: string) => {
    const now = new Date().getTime();
    const from = new Date(validFrom).getTime();
    const to = new Date(validTo).getTime();
    const total = to - from;
    const current = now - from;
    return Math.min(Math.max((current / total) * 100, 0), 100);
  };

  return (
    <div className="mx-auto max-w-5xl px-4 sm:px-6">
      {/* Input Section */}
      <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4 sm:p-6 lg:p-8">
        <div className="flex items-center gap-3 mb-4">
          <Lock className="h-4 w-4 text-[#3FA796]" />
          <span className="font-mono text-xs uppercase tracking-widest text-[#3FA796]">
            Target Domain
          </span>
          <span className="h-px flex-1 bg-[#232B3D]" />
        </div>

        <div className="flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="flex-1">
            <div className="flex items-center gap-2 bg-[#0E1420] rounded-lg border border-[#2A3348] px-3 sm:px-4 py-2.5 sm:py-3 focus-within:border-[#3FA796] focus-within:ring-2 focus-within:ring-[#3FA796]/40 transition-all">
              <Globe className="h-4 w-4 text-[#4C5A78] flex-shrink-0" />
              <input
                type="text"
                placeholder="example.com"
                value={domainInput}
                onChange={(e) => setDomainInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && runScan()}
                className="flex-1 bg-transparent font-mono text-sm sm:text-base text-[#EAF0FA] placeholder:text-[#4C5A78] focus:outline-none min-w-0"
              />
            </div>
          </div>
          <div className="w-24 sm:w-28 flex-shrink-0">
            <div className="flex items-center gap-2 bg-[#0E1420] rounded-lg border border-[#2A3348] px-3 py-2.5 sm:py-3 focus-within:border-[#3FA796] focus-within:ring-2 focus-within:ring-[#3FA796]/40 transition-all">
              <Server className="h-4 w-4 text-[#4C5A78] flex-shrink-0" />
              <input
                type="number"
                placeholder="443"
                value={portInput}
                onChange={(e) => setPortInput(e.target.value)}
                className="w-full bg-transparent font-mono text-sm text-[#EAF0FA] placeholder:text-[#4C5A78] focus:outline-none"
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
              "Scan SSL"
            )}
          </button>
        </div>

        <div className="mt-4 flex items-start gap-2 rounded-lg border border-[#F2A93C]/20 bg-[#F2A93C]/5 px-3 py-2">
          <span className="text-[#F2A93C] text-sm flex-shrink-0">⚠️</span>
          <p className="text-xs text-[#C9D2E3]">
            Passive handshake only. No vulnerability exploitation. Supports ports: 443, 8443, 2083, 2087
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
        <div className="mt-6 space-y-4 sm:space-y-6">
          {/* Header / Grade */}
          <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4 sm:p-6">
            <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div className="flex items-center gap-4">
                <div className={`w-16 h-16 sm:w-20 sm:h-20 rounded-2xl border-2 ${gradeBadge.border} ${gradeBadge.bg} flex items-center justify-center`}>
                  <span className={`text-3xl sm:text-4xl font-bold ${gradeBadge.color}`}>
                    {result.grade}
                  </span>
                </div>
                <div>
                  <p className="font-mono text-lg sm:text-xl text-[#EAF0FA]">{result.host}</p>
                  <p className="text-xs text-[#7C89A6]">Port {result.port}</p>
                  {result.cached && (
                    <span className="inline-block mt-1 text-xs text-[#3FA796]">✓ Cached</span>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-4 text-right">
                <div>
                  <p className="text-xs text-[#7C89A6]">Days Until Expiry</p>
                  <p className={`text-2xl font-bold ${result.cert.days_left < 30 ? 'text-[#E15252]' : result.cert.days_left < 90 ? 'text-[#F2A93C]' : 'text-[#3FA796]'}`}>
                    {result.cert.days_left}
                  </p>
                </div>
                <div>
                  <p className="text-xs text-[#7C89A6]">TLS Version</p>
                  <p className="font-mono text-sm text-[#EAF0FA]">{result.tls.negotiated_version}</p>
                </div>
                <button
                  onClick={downloadJSON}
                  className="p-2 rounded-lg border border-[#232B3D] hover:border-[#3FA796] transition"
                  title="Download JSON"
                >
                  <FileJson className="h-4 w-4 text-[#7C89A6] hover:text-[#3FA796] transition" />
                </button>
                <button
                  onClick={downloadPEM}
                  className="p-2 rounded-lg border border-[#232B3D] hover:border-[#3FA796] transition"
                  title="Download PEM"
                >
                  <FileKey className="h-4 w-4 text-[#7C89A6] hover:text-[#3FA796] transition" />
                </button>
              </div>
            </div>

            {/* Validity Timeline */}
            <div className="mt-4 pt-4 border-t border-[#232B3D]">
              <div className="flex justify-between text-xs text-[#7C89A6] mb-1">
                <span>{formatDateShort(result.cert.valid_from)}</span>
                <span className="text-[#3FA796]">● Today</span>
                <span>{formatDateShort(result.cert.valid_to)}</span>
              </div>
              <div className="relative h-2 bg-[#232B3D] rounded-full overflow-hidden">
                <div 
                  className="absolute h-full bg-gradient-to-r from-[#3FA796] via-[#F2A93C] to-[#E15252] rounded-full transition-all"
                  style={{ width: `${Math.min(getValidityPosition(result.cert.valid_from, result.cert.valid_to), 100)}%` }}
                />
                <div 
                  className="absolute top-0 h-full w-0.5 bg-[#EAF0FA]"
                  style={{ left: `${Math.min(getValidityPosition(result.cert.valid_from, result.cert.valid_to), 100)}%` }}
                />
              </div>
            </div>
          </div>

          {/* Two-column layout */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 sm:gap-6">
            {/* Left: Certificate Details */}
            <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4 sm:p-6">
              <h3 className="font-mono text-sm font-semibold uppercase tracking-wide text-[#EAF0FA] mb-4 flex items-center gap-2">
                <Shield className="h-4 w-4 text-[#3FA796]" />
                Certificate Details
              </h3>
              
              <div className="space-y-3">
                <div>
                  <p className="text-xs text-[#7C89A6]">Subject</p>
                  <p className="font-mono text-sm text-[#EAF0FA] break-all">{result.cert.subject}</p>
                </div>
                <div>
                  <p className="text-xs text-[#7C89A6]">Issuer</p>
                  <p className="font-mono text-sm text-[#EAF0FA] break-all">{result.cert.issuer}</p>
                </div>
                <div>
                  <p className="text-xs text-[#7C89A6]">Subject Alternative Names (SAN)</p>
                  <div className="flex flex-wrap gap-1.5 mt-1">
                    {result.cert.san.length > 0 ? (
                      result.cert.san.map((name, idx) => (
                        <span 
                          key={idx}
                          className="group relative px-2 py-1 bg-[#0E1420] border border-[#2A3348] rounded text-xs font-mono text-[#C9D2E3] cursor-pointer hover:border-[#3FA796] transition"
                          onClick={() => copyToClipboard(name, `san-${idx}`)}
                        >
                          {name}
                          <span className="absolute -top-1 -right-1 opacity-0 group-hover:opacity-100 transition">
                            {copied === `san-${idx}` ? (
                              <Check className="h-3 w-3 text-[#3FA796]" />
                            ) : (
                              <Copy className="h-3 w-3 text-[#7C89A6]" />
                            )}
                          </span>
                        </span>
                      ))
                    ) : (
                      <span className="text-xs text-[#4C5A78]">No SAN entries</span>
                    )}
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <p className="text-xs text-[#7C89A6]">Serial Number</p>
                    <p className="font-mono text-xs text-[#C9D2E3] truncate">{result.cert.serial}</p>
                  </div>
                  <div>
                    <p className="text-xs text-[#7C89A6]">Chain Length</p>
                    <p className="font-mono text-sm text-[#EAF0FA]">{result.cert.chain_length}</p>
                  </div>
                </div>
                <div>
                  <p className="text-xs text-[#7C89A6]">SHA256 Fingerprint</p>
                  <div className="flex items-center gap-2">
                    <p className="font-mono text-xs text-[#C9D2E3] truncate flex-1">{result.cert.fingerprint_sha256}</p>
                    <button
                      onClick={() => copyToClipboard(result.cert.fingerprint_sha256, 'fingerprint')}
                      className="p-1 hover:text-[#3FA796] transition"
                    >
                      {copied === 'fingerprint' ? (
                        <Check className="h-3 w-3 text-[#3FA796]" />
                      ) : (
                        <Copy className="h-3 w-3 text-[#7C89A6]" />
                      )}
                    </button>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <p className="text-xs text-[#7C89A6]">Valid From</p>
                    <p className="font-mono text-xs text-[#C9D2E3]">{formatDate(result.cert.valid_from)}</p>
                  </div>
                  <div>
                    <p className="text-xs text-[#7C89A6]">Valid To</p>
                    <p className="font-mono text-xs text-[#C9D2E3]">{formatDate(result.cert.valid_to)}</p>
                  </div>
                </div>
              </div>
            </div>

            {/* Right: Security Assessment */}
            <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4 sm:p-6">
              <h3 className="font-mono text-sm font-semibold uppercase tracking-wide text-[#EAF0FA] mb-4 flex items-center gap-2">
                <ShieldCheck className="h-4 w-4 text-[#3FA796]" />
                Security Assessment
              </h3>

              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <p className="text-xs text-[#7C89A6]">Signature Algorithm</p>
                    <p className="font-mono text-sm text-[#EAF0FA]">{result.cert.sig_algo}</p>
                  </div>
                  <div>
                    <p className="text-xs text-[#7C89A6]">Key Type</p>
                    <p className="font-mono text-sm text-[#EAF0FA]">
                      {result.cert.key_type} {result.cert.key_bits}
                    </p>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <p className="text-xs text-[#7C89A6]">Self-Signed</p>
                    <span className={`text-sm font-semibold ${result.cert.self_signed ? 'text-[#E15252]' : 'text-[#3FA796]'}`}>
                      {result.cert.self_signed ? '⚠️ Yes' : '✓ No'}
                    </span>
                  </div>
                  <div>
                    <p className="text-xs text-[#7C89A6]">ALPN Protocol</p>
                    <p className="font-mono text-sm text-[#EAF0FA]">{result.tls.alpn || 'None'}</p>
                  </div>
                </div>
                {result.tls.supports_deprecated_tls.length > 0 && (
                  <div>
                    <p className="text-xs text-[#7C89A6]">Deprecated TLS Supported</p>
                    <div className="flex flex-wrap gap-1.5 mt-1">
                      {result.tls.supports_deprecated_tls.map((v, idx) => (
                        <span key={idx} className="px-2 py-0.5 bg-[#E15252]/20 border border-[#E15252]/30 rounded text-xs font-mono text-[#E15252]">
                          {v}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              {/* Findings */}
              {result.findings.length > 0 && (
                <div className="mt-4 pt-4 border-t border-[#232B3D]">
                  <p className="text-xs text-[#7C89A6] mb-2">Findings</p>
                  <div className="space-y-2">
                    {result.findings.map((finding, idx) => {
                      const config = SEVERITY_CONFIG[finding.severity];
                      const Icon = config.icon;
                      return (
                        <div key={idx} className={`rounded-lg border ${config.border} ${config.bg} p-3`}>
                          <div className="flex items-start gap-2">
                            <Icon className={`h-4 w-4 ${config.color} flex-shrink-0 mt-0.5`} />
                            <div>
                              <p className={`text-sm font-semibold ${config.color}`}>
                                {finding.title}
                              </p>
                              {finding.description && (
                                <p className="text-xs text-[#C9D2E3] mt-0.5">{finding.description}</p>
                              )}
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Raw Certificate Chain */}
          <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4 sm:p-6">
            <button
              onClick={() => setShowRaw(!showRaw)}
              className="flex items-center gap-2 w-full text-left hover:text-[#3FA796] transition"
            >
              {showRaw ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
              <span className="font-mono text-sm font-semibold uppercase tracking-wide text-[#EAF0FA]">
                Certificate Chain (Raw)
              </span>
              <span className="text-xs text-[#7C89A6] ml-2">{result.cert.chain_length} certificates</span>
            </button>
            
            {showRaw && (
              <div className="mt-4">
                <pre className="text-xs font-mono text-[#C9D2E3] bg-[#0E1420] rounded-lg p-4 overflow-x-auto max-h-[300px]">
                  {JSON.stringify(result, (key, value) => {
                    if (key === 'cert' && value.raw) {
                      return { ...value, raw: '[BINARY DATA]' };
                    }
                    return value;
                  }, 2)}
                </pre>
              </div>
            )}
          </div>

          {/* Recommendations */}
          {result.findings.length > 0 && (
            <div className="rounded-2xl border border-[#3FA796]/30 bg-[#3FA796]/5 p-4 sm:p-6">
              <h4 className="font-mono text-sm font-semibold text-[#3FA796] mb-2 flex items-center gap-2">
                <ShieldCheck className="h-4 w-4" />
                Recommendations
              </h4>
              <ul className="space-y-1 text-sm text-[#C9D2E3]">
                {result.findings.map((finding, idx) => {
                  switch (finding.type) {
                    case "EXPIRED":
                    case "EXPIRY_CRITICAL":
                    case "EXPIRY_SOON":
                      return (
                        <li key={idx}>• Renew your SSL certificate immediately. {finding.description}</li>
                      );
                    case "SELF_SIGNED":
                      return (
                        <li key={idx}>• Replace self-signed certificate with a certificate from a trusted CA.</li>
                      );
                    case "WEAK_SIG":
                      return (
                        <li key={idx}>• Update to a stronger signature algorithm (SHA-256 or higher).</li>
                      );
                    case "WEAK_KEY":
                      return (
                        <li key={idx}>• Upgrade to RSA 2048-bit or ECDSA 256-bit key.</li>
                      );
                    case "DEPRECATED_TLS":
                      return (
                        <li key={idx}>• Disable TLS 1.0 and 1.1, enable TLS 1.2 and 1.3 only.</li>
                      );
                    default:
                      return <li key={idx}>• {finding.title}</li>;
                  }
                })}
              </ul>
            </div>
          )}

          {/* Footer */}
          <div className="rounded-2xl border border-[#232B3D] bg-[#141B2A] p-4">
            <p className="text-center text-xs text-[#4C5A78]">
              Passive handshake only. No vulnerability exploitation.
              {result.scan_duration_ms && ` Scanned in ${(result.scan_duration_ms / 1000).toFixed(2)}s`}
            </p>
          </div>
        </div>
      )}
    </div>
  );
}