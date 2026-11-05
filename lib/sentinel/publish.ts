import { saveVault, getPublic, type PublicRecord } from "./store";
import { redis, K, TTL } from "./redis";
import type { PublicFinding, RawEvidence } from "./audit";
import { dossierToMarkdown, type CveDossier } from "./dossier";

export const sentinelConfigured = () => true;

/**
 * Dipanggil scanner (/scan) untuk temuan CRITICAL/HIGH yang sudah LOLOS validasi true-positive:
 * raw evidence → vault terenkripsi (24j), versi aman → public record (7h, di-merge).
 */
export async function publishScanCriticals(domain: string, findings: PublicFinding[], raw: RawEvidence[]) {
  if (findings.length === 0 && raw.length === 0) return;
  try {
    if (raw.length > 0) {
      await saveVault(raw);
    }
    const prev = await getPublic(domain);
    const seen = new Set((prev?.findings ?? []).map((f) => f.finding));
    const merged: PublicRecord = {
      domain,
      scannedAt: Date.now(),
      findings: [...findings.filter((f) => !seen.has(f.finding)), ...(prev?.findings ?? [])],
    };
    await redis().set(K.public(domain), JSON.stringify(merged), { ex: TTL.public });
  } catch (e) {
    console.error("[sentinel] publishScanCriticals gagal:", e instanceof Error ? e.message : e);
  }
}

/** Versi aman dossier untuk publik: hanya CVE/CWE + versi (info publik), tanpa header/banner/evidence mentah. */
export function dossierPublicFindings(d: CveDossier): PublicFinding[] {
  const out: PublicFinding[] = [];
  for (const r of d.rceSurface) {
    if (r.severity !== "CRITICAL" && r.severity !== "HIGH") continue;
    out.push({
      domain: d.domain,
      severity: r.severity,
      finding: `${r.title}${r.cve.length ? ` (${r.cve.join(", ")})` : ""}`,
      evidence_public: `200 OK, isi respons cocok penanda "${r.marker}" (isi tidak ditampilkan)`,
      fix: "Matikan debug/diagnostic endpoint di production atau batasi ke jaringan internal.",
    });
  }
  for (const h of d.cves.filter((x) => x.rce || x.severity === "CRITICAL" || x.severity === "HIGH").slice(0, 10)) {
    out.push({
      domain: d.domain,
      severity: "HIGH", // berbasis versi → maksimum HIGH
      finding: `${h.id}${h.cwe.length ? ` (${h.cwe.join(", ")})` : ""} — ${h.rce ? "potensi RCE: " : ""}${h.component} ${h.versionFound}`,
      evidence_public: `Versi ${h.component} ${h.versionFound} cocok rentang rentan (${h.source.toUpperCase()}); berbasis versi, perlu verifikasi`,
      fix: `Upgrade ${h.component} ke versi ter-patch.`,
    });
  }
  return out;
}

/**
 * Dossier lengkap → Vault admin (terenkripsi AES-256-GCM, TTL vault). User hanya mendapat ringkasan publik.
 * Raw view = laporan Markdown (tanpa snippet mentah); data JSON lengkap ada di field cveIntel.
 */
export async function publishDossier(domain: string, dossier: CveDossier, publicFindings: PublicFinding[]) {
  try {
    await saveVault([
      {
        domain,
        path: "/__cve-intel.json",
        status: 200,
        contentType: "application/json",
        marker: `CVE/CWE/RCE dossier — ${dossier.summary.cveTotal} CVE, ${dossier.summary.rcePotential} potensi RCE, ${dossier.summary.rceSurface} endpoint rawan`,
        snippet: dossierToMarkdown(dossier),
        cveIntel: dossier,
      },
    ]);
    if (publicFindings.length) {
      const prev = await getPublic(domain);
      const seen = new Set((prev?.findings ?? []).map((f) => f.finding));
      const merged: PublicRecord = {
        domain,
        scannedAt: Date.now(),
        findings: [...publicFindings.filter((f) => !seen.has(f.finding)), ...(prev?.findings ?? [])],
      };
      await redis().set(K.public(domain), JSON.stringify(merged), { ex: TTL.public });
    }
  } catch (e) {
    console.error("[sentinel] publishDossier gagal:", e instanceof Error ? e.message : e);
  }
}
