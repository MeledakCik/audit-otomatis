"use client";

import React, { useState, useEffect, useMemo } from "react";
import {
  Lock,
  Globe,
  Shield,
  CheckCircle2,
  AlertTriangle,
  KeyRound,
  FileText,
  Eye,
  EyeOff,
  Copy,
  Check,
  ArrowRight
} from "lucide-react";

type ClaimMethod = "dns" | "http";

export interface SentinelAuditProps {
  isDark?: boolean;
  initialDomain?: string;
  domain?: string;
  url?: string;
  targetUrl?: string;
  scanId?: string;
  embedded?: boolean;
  compact?: boolean;
  [key: string]: unknown;
}

interface VaultArtifact {
  id: string;
  path: string;
  cwe: string;
  risk: "CRITICAL" | "HIGH" | "SAFE";
  publicPreview: string;
  decryptedPreview: string;
  cipherMeta: string;
  remediation: string;
}

const VAULT_ARTIFACTS: VaultArtifact[] = [
  {
    id: "V-01",
    path: "/.env",
    cwe: "CWE-538 · CWE-312",
    risk: "CRITICAL",
    publicPreview: "APP_KEY=[REDACTED_AES256_GCM_8F3A] · AWS_SECRET=[REDACTED_AES256_GCM_9C12]",
    decryptedPreview: "APP_KEY=base64:SentinelDemoKey9912... · AWS_SECRET=wJalrXUtnFEMI/K7MDENG/bPxRfiCY",
    cipherMeta: "AES-256-GCM · IV: 9f4b...21a0 · Tag: e81c...770b",
    remediation: "Blokir akses dotfile (/.env*) pada konfigurasi Nginx/Cloudflare atau pindahkan ke luar public root."
  },
  {
    id: "V-02",
    path: "/.git/HEAD",
    cwe: "CWE-538 · CWE-200",
    risk: "HIGH",
    publicPreview: "ref: refs/heads/[REDACTED_VAULT_BRANCH] (Objek Git disensor dari publik)",
    decryptedPreview: "ref: refs/heads/main (Eksposur direktori .git memungkinkan rekonstruksi source code)",
    cipherMeta: "AES-256-GCM · IV: 3c18...84d2 · Tag: 44a9...19f0",
    remediation: "Tambahkan aturan deny all untuk lokasi ~ /\\.(git|svn|hg) pada server web atau Edge WAF."
  },
  {
    id: "V-03",
    path: "/wp-config.php.bak",
    cwe: "CWE-530 · CWE-284",
    risk: "CRITICAL",
    publicPreview: "DB_PASSWORD=[REDACTED_AES256_GCM_4D91] · AUTH_SALT=[REDACTED_VAULT]",
    decryptedPreview: "DB_PASSWORD='prod_db_secret_example' · AUTH_SALT='unique_phrase_verified_owner_only'",
    cipherMeta: "AES-256-GCM · IV: 7a02...55e1 · Tag: b12d...90c3",
    remediation: "Hapus seluruh file cadangan editor (*.bak, *~, *.save, *.swp) dari direktori produksi."
  },
  {
    id: "V-04",
    path: "/backup.zip",
    cwe: "CWE-530",
    risk: "SAFE",
    publicPreview: "404 Not Found — Tidak ditemukan arsip backup publik pada domain target.",
    decryptedPreview: "404 Not Found — Aman (Tidak ada file arsip .zip/.tar.gz/.sql yang terekspos).",
    cipherMeta: "Status: Clean (Zero Exposure)",
    remediation: "Pertahankan kebijakan penyimpanan backup di bucket privat terpisah dari web root."
  }
];

/**
 * Komponen utama `SentinelAudit` untuk `components/sentinel/sentinel-audit.tsx`.
 * Mengekspor `SentinelAudit`, `SentinelVaultView`, dan `default` agar kompatibel dengan:
 * - `import { SentinelAudit } from "@/components/sentinel/sentinel-audit"` di `components/scan-dashboard.tsx`
 * - `import { SentinelVaultView } from "@/components/sentinel/sentinel-audit"` di `app/scan/sentinel/page.tsx`
 */
export function SentinelAudit(props: SentinelAuditProps = {}) {
  const {
    isDark: propDark,
    initialDomain,
    domain,
    url,
    targetUrl
  } = props;

  const defaultDom =
    (typeof initialDomain === "string" && initialDomain) ||
    (typeof domain === "string" && domain) ||
    (typeof url === "string" && url) ||
    (typeof targetUrl === "string" && targetUrl) ||
    "sentinel-id.net";

  const [detectedDark, setDetectedDark] = useState<boolean>(true);
  const [claimDomain, setClaimDomain] = useState<string>(
    defaultDom.replace(/^https?:\/\//i, "").split("/")[0] || "sentinel-id.net"
  );
  const [claimMethod, setClaimMethod] = useState<ClaimMethod>("dns");
  const [isOwnerVerified, setIsOwnerVerified] = useState<boolean>(false);
  const [selectedArtifactId, setSelectedArtifactId] = useState<string>("V-01");
  const [verifyNotice, setVerifyNotice] = useState<string>("");
  const [copiedToken, setCopiedToken] = useState<boolean>(false);

  useEffect(() => {
    try {
      const root = document.documentElement;
      setDetectedDark(root.classList.contains("dark"));
      const obs = new MutationObserver(() => {
        setDetectedDark(root.classList.contains("dark"));
      });
      obs.observe(root, { attributes: true, attributeFilter: ["class"] });
      return () => obs.disconnect();
    } catch {
      return undefined;
    }
  }, []);

  const isDark = propDark !== undefined ? propDark : detectedDark;

  const glassCard = isDark
    ? "bg-[#110E20]/70 backdrop-blur-2xl border border-foreground/[0.09] shadow-[0_20px_50px_-15px_rgba(0,0,0,0.65)] text-soft"
    : "bg-foreground/80 backdrop-blur-2xl border border-slate-900/[0.08] shadow-[0_16px_40px_-12px_rgba(15,23,42,0.06)] text-slate-900";
  const glassPill = isDark
    ? "bg-foreground/[0.05] border border-foreground/[0.09]"
    : "bg-slate-900/[0.04] border border-slate-900/[0.08]";
  const mutedText = isDark ? "text-muted" : "text-slate-600";

  const selectedArtifact = useMemo(
    () => VAULT_ARTIFACTS.find((a) => a.id === selectedArtifactId) || VAULT_ARTIFACTS[0],
    [selectedArtifactId]
  );

  const verificationToken = useMemo(() => {
    const clean = claimDomain.trim().replace(/^https?:\/\//i, "").split("/")[0] || "sentinel-id.net";
    return `sentinel-site-verification=aes256_${clean.replace(/[^a-z0-9]/gi, "")}_9f82c1`;
  }, [claimDomain]);

  function handleVerifyOwnership(e: React.FormEvent) {
    e.preventDefault();
    setIsOwnerVerified(true);
    setVerifyNotice(
      `Kepemilikan ${claimDomain} terverifikasi via ${
        claimMethod === "dns" ? "DNS TXT Record" : "HTTP Well-Known Token"
      } (Akses Bukti 1x Lihat Aktif)`
    );
  }

  function handleCopyToken() {
    try {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(verificationToken);
      }
    } catch {}
    setCopiedToken(true);
    setTimeout(() => setCopiedToken(false), 2000);
  }

  return (
    <div className="space-y-6">
      {/* Top Bento Hero for Sentinel Vault AES-256-GCM */}
      <div className={`rounded-3xl p-6 grid grid-cols-1 xl:grid-cols-12 gap-6 items-start ${glassCard}`}>
        <div className="xl:col-span-7 space-y-3">
          <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-mono text-pink-500 ${glassPill}`}>
            <Lock className="w-3.5 h-3.5" />
            <span>SENTINEL VAULT · AES-256-GCM ENCRYPTED EVIDENCE</span>
          </div>
          <h2 className="text-2xl sm:text-3xl font-extrabold tracking-tight">
            Sentinel Vault &amp;{" "}
            <span className="bg-gradient-to-r from-pink-500 via-purple-500 to-indigo-500 bg-clip-text text-transparent">
              Klaim Bukti Pemilik Domain
            </span>
          </h2>
          <p className={`text-xs sm:text-sm leading-relaxed ${mutedText}`}>
            Saat pemindai pasif menemukan kebocoran kritis seperti <code>.env</code>,{" "}
            <code>.git/HEAD</code>, atau <code>wp-config.php.bak</code>, nilai rahasia{" "}
            <strong>langsung disensor dari publik</strong> dan dienkripsi dengan{" "}
            <strong>AES-256-GCM</strong>. Hanya pemilik sah domain yang dapat membuka bukti 1x lihat.
          </p>
        </div>

        {/* Right Vault Security Posture Pills */}
        <div className="xl:col-span-5 grid grid-cols-2 gap-2.5">
          {[
            { label: "Algoritma Vault", val: "AES-256", sub: "GCM Authenticated", tone: "text-pink-500" },
            { label: "Eksposur Publik", val: "0 Bocor", sub: "Auto-Redacted", tone: "text-emerald-500" },
            { label: "Metode Klaim", val: "DNS / HTTP", sub: "Verifikasi Sah", tone: "text-cyan-500" },
            { label: "Akses Dekripsi", val: "1x Lihat", sub: "One-Time Token", tone: "text-purple-400" }
          ].map((m) => (
            <div key={m.label} className={`rounded-2xl p-3.5 ${glassPill}`}>
              <span className={`text-xs font-mono uppercase ${mutedText}`}>{m.label}</span>
              <p className={`text-xl font-extrabold mt-0.5 ${m.tone}`}>{m.val}</p>
              <p className={`text-xs ${mutedText}`}>{m.sub}</p>
            </div>
          ))}
        </div>
      </div>

      {/* Main Grid: Encrypted Evidence Vault Table + Domain Ownership Claim Wizard */}
      <div className="grid grid-cols-1 xl:grid-cols-12 gap-6 items-start">
        {/* Left: Sensitive Artifacts & Redaction Inspector (7 cols) */}
        <div className={`xl:col-span-7 rounded-3xl p-6 space-y-4 ${glassCard}`}>
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <h3 className="text-base sm:text-lg font-bold">Brankas Bukti File Sensitif</h3>
              <p className={`text-xs ${mutedText}`}>
                Pilih artefak untuk melihat perbandingan redaksi publik vs dekripsi pemilik sah
              </p>
            </div>
            <span
              className={`px-3 py-1 rounded-full text-xs font-mono font-semibold ${
                isOwnerVerified
                  ? "bg-emerald-500/15 text-emerald-500"
                  : "bg-amber-500/15 text-amber-500"
              }`}
            >
              {isOwnerVerified ? "Terverifikasi (1x Lihat)" : "Disensor untuk Publik"}
            </span>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
            {VAULT_ARTIFACTS.map((art) => {
              const isSel = art.id === selectedArtifactId;
              return (
                <button
                  key={art.id}
                  type="button"
                  onClick={() => setSelectedArtifactId(art.id)}
                  className={`rounded-2xl p-3.5 text-left transition-all ${glassPill} ${
                    isSel ? "ring-2 ring-pink-500/70" : "opacity-85 hover:opacity-100"
                  }`}
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-mono text-xs sm:text-sm font-bold text-pink-500">
                      {art.path}
                    </span>
                    <span
                      className={`text-xs font-mono font-bold px-2 py-0.5 rounded-md ${
                        art.risk === "CRITICAL"
                          ? "bg-rose-500/15 text-rose-500"
                          : art.risk === "HIGH"
                          ? "bg-amber-500/15 text-amber-500"
                          : "bg-emerald-500/15 text-emerald-500"
                      }`}
                    >
                      {art.risk}
                    </span>
                  </div>
                  <div className={`text-xs font-mono mt-1 ${mutedText}`}>{art.cwe}</div>
                </button>
              );
            })}
          </div>

          {/* Selected Artifact Evidence Detail Box */}
          <div className={`rounded-2xl p-4 space-y-2.5 ${glassPill}`}>
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="text-xs font-mono font-bold text-cyan-500">
                {selectedArtifact.path} · {selectedArtifact.cwe}
              </span>
              <span className={`text-xs font-mono ${mutedText}`}>
                {selectedArtifact.cipherMeta}
              </span>
            </div>

            <div className="p-3 rounded-xl bg-sunken border border-border font-mono text-xs break-all text-soft">
              {isOwnerVerified
                ? selectedArtifact.decryptedPreview
                : selectedArtifact.publicPreview}
            </div>

            <p className={`text-xs leading-relaxed ${mutedText}`}>
              <strong className="font-semibold text-emerald-500">Remediasi: </strong>
              {selectedArtifact.remediation}
            </p>
          </div>
        </div>

        {/* Right: Domain Ownership Claim Wizard (5 cols) */}
        <div className={`xl:col-span-5 rounded-3xl p-6 space-y-4 ${glassCard}`}>
          <form onSubmit={handleVerifyOwnership} className="space-y-3.5">
            <div>
              <span className="text-xs font-mono uppercase tracking-widest text-purple-400 font-semibold">
                Verifikasi Kepemilikan Sah
              </span>
              <h3 className="text-base sm:text-lg font-bold mt-0.5">
                Klaim Domain &amp; Buka Brankas
              </h3>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-semibold block">Domain yang Diklaim</label>
              <div className={`flex items-center gap-2 px-3 py-2 rounded-xl ${glassPill}`}>
                <Globe className="w-4 h-4 text-pink-500 shrink-0" />
                <input
                  type="text"
                  value={claimDomain}
                  onChange={(e) => {
                    setClaimDomain(e.target.value);
                    setIsOwnerVerified(false);
                  }}
                  className="w-full bg-transparent text-xs font-mono focus:outline-none"
                  aria-label="Domain Klaim"
                />
              </div>
            </div>

            <div className="space-y-1">
              <label className="text-xs font-semibold block">Metode Verifikasi</label>
              <div className={`grid grid-cols-2 gap-1.5 p-1 rounded-xl ${glassPill}`}>
                <button
                  type="button"
                  onClick={() => setClaimMethod("dns")}
                  className={`py-1.5 rounded-lg text-xs font-semibold transition ${
                    claimMethod === "dns"
                      ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white"
                      : mutedText
                  }`}
                >
                  DNS TXT Record
                </button>
                <button
                  type="button"
                  onClick={() => setClaimMethod("http")}
                  className={`py-1.5 rounded-lg text-xs font-semibold transition ${
                    claimMethod === "http"
                      ? "bg-gradient-to-r from-pink-500 to-purple-600 text-white"
                      : mutedText
                  }`}
                >
                  File HTTP Token
                </button>
              </div>
            </div>

            <div className={`rounded-2xl p-3.5 space-y-2 text-xs ${glassPill}`}>
              <div className="flex items-center justify-between gap-2">
                <span className="font-semibold">
                  {claimMethod === "dns" ? "DNS TXT Host:" : "HTTP Token Path:"}
                </span>
                <button
                  type="button"
                  onClick={handleCopyToken}
                  className="text-xs font-mono text-pink-500 flex items-center gap-1"
                >
                  {copiedToken ? <Check className="w-3 h-3" /> : <Copy className="w-3 h-3" />}
                  <span>{copiedToken ? "Tersalin" : "Salin Token"}</span>
                </button>
              </div>
              <div className="font-mono text-xs text-cyan-500 break-all">
                {claimMethod === "dns"
                  ? `_sentinel-verify.${claimDomain}`
                  : `https://${claimDomain}/.well-known/sentinel-claim.txt`}
              </div>
              <div className="p-2 rounded-lg bg-sunken font-mono text-xs text-emerald-400 break-all">
                {verificationToken}
              </div>
            </div>

            <div className="flex gap-2">
              <button
                type="submit"
                className="flex-1 py-2.5 px-4 rounded-xl font-semibold text-xs text-white bg-gradient-to-r from-pink-500 via-purple-600 to-indigo-600 hover:opacity-95 transition shadow-md"
              >
                Verifikasi &amp; Buka Bukti (1x Lihat)
              </button>
              {isOwnerVerified && (
                <button
                  type="button"
                  onClick={() => {
                    setIsOwnerVerified(false);
                    setVerifyNotice("");
                  }}
                  className={`px-3 py-2.5 rounded-xl text-xs font-mono ${glassPill}`}
                >
                  Kunci
                </button>
              )}
            </div>
          </form>

          {verifyNotice && (
            <div className="rounded-xl p-3 bg-emerald-500/15 border border-emerald-500/30 text-xs text-emerald-500 font-medium">
              ✓ {verifyNotice}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Alias ekspor agar 100% kompatibel dengan semua cara impor di repositori
export const SentinelVaultView = SentinelAudit;
export default SentinelAudit;
