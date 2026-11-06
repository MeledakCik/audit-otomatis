// Pure (tanpa import node) → aman dipakai server (menyusun) & client admin (ekspor laporan).
import type { SensitiveDossier, SensitiveFileEntry } from "./sensitive-types";

export function buildSensitiveDossier(domain: string, origin: string, pathsChecked: number, entries: SensitiveFileEntry[]): SensitiveDossier {
  const byCategory: Record<string, number> = {};
  const secretTypes: Record<string, number> = {};
  const awsAccountIds = new Set<string>();
  let liveSecrets = 0, placeholderSecrets = 0;

  for (const e of entries) {
    byCategory[e.category] = (byCategory[e.category] ?? 0) + 1;
    for (const s of e.analysis.secrets) {
      if (s.live) { liveSecrets++; secretTypes[s.label] = (secretTypes[s.label] ?? 0) + 1; if (s.awsAccountId) awsAccountIds.add(s.awsAccountId); }
      else placeholderSecrets++;
    }
  }

  return {
    version: 1,
    domain,
    origin,
    generatedAt: Date.now(),
    pathsChecked,
    entries,
    summary: {
      totalFiles: entries.length,
      criticalFiles: entries.filter((e) => e.severity === "CRITICAL").length,
      liveSecrets,
      placeholderSecrets,
      byCategory,
      secretTypes,
      awsAccountIds: [...awsAccountIds],
    },
    caveats: [
      "Seluruh deteksi dihasilkan oleh pengecekan PASIF (GET-only). Tidak ada kredensial yang diuji, login, atau dipakai menghubungi layanan pihak ketiga (AWS/GitHub/DB/dsb).",
      "ID akun AWS (bila ada) diturunkan secara offline dari struktur Access Key ID, bukan dari pemanggilan API AWS.",
      "Nilai yang ditandai 'placeholder/default/contoh' kemungkinan besar bukan kredensial nyata dan sengaja tidak dihitung sebagai kebocoran kritis.",
      "Dokumen ini memuat rahasia dalam bentuk tersamarkan (preview). Nilai penuh hanya ada di Sentinel Vault dan hilang otomatis saat TTL habis.",
    ],
  };
}

const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");

/** Laporan Markdown untuk admin/pelaporan ke pihak domain. Memuat preview rahasia (tersamarkan), bukan nilai penuh. */
export function sensitiveDossierToMarkdown(d: SensitiveDossier): string {
  const L: string[] = [];
  const date = new Date(d.generatedAt).toISOString();
  L.push(`# Laporan Audit File Sensitif — ${d.domain}`, "");
  L.push(`- **Target:** ${d.origin}`, `- **Dibuat:** ${date}`, `- **Metode:** pasif (GET-only), ${d.pathsChecked} path diperiksa`);
  L.push(`- **Diverifikasi oleh:** ______________________ (nama / instansi / organisasi)`);
  L.push(`- **Dilaporkan kepada:** ______________________ (mis. pemilik domain / BSSN / CSIRT terkait)`, "");

  L.push("## Ringkasan", "");
  L.push("| File ditemukan | CRITICAL | Kredensial nyata (live) | Nilai placeholder |", "|---|---|---|---|");
  L.push(`| ${d.summary.totalFiles} | ${d.summary.criticalFiles} | ${d.summary.liveSecrets} | ${d.summary.placeholderSecrets} |`, "");
  const cat = Object.entries(d.summary.byCategory).map(([k, v]) => `${k}: ${v}`).join(" · ");
  if (cat) L.push(`Sebaran kategori: ${cat}`, "");
  if (d.summary.awsAccountIds.length) L.push(`ID Akun AWS yang terlibat (diturunkan offline): ${d.summary.awsAccountIds.join(", ")}`, "");

  if (d.entries.length) {
    L.push("## File yang ditemukan", "");
    L.push("| Path | Severity | Kategori | CWE | Live secrets |", "|---|---|---|---|---|");
    for (const e of d.entries)
      L.push(`| \`${esc(e.path)}\` | ${e.severity} | ${e.category} | ${e.cwe.join(", ") || "-"} | ${e.analysis.liveCount} |`);
    L.push("");

    L.push("## Rincian & rekomendasi per file", "");
    for (const e of d.entries) {
      L.push(`### \`${esc(e.path)}\` — ${esc(e.title)}`, "");
      L.push(`${e.severity} · ${e.fileKind} · HTTP ${e.status}${e.confidence === "existence-only" ? " · indikasi (belum diverifikasi eksekusinya)" : ""}`, "");
      if (e.analysis.secrets.length) {
        L.push("| Jenis | Pratinjau (tersamarkan) | Status |", "|---|---|---|");
        for (const s of e.analysis.secrets)
          L.push(`| ${s.label}${s.keyName ? ` (\`${esc(s.keyName)}\`)` : ""} | \`${esc(s.preview)}\` | ${s.live ? "**NYATA**" : `placeholder (${s.reason ?? "-"})`} |`);
        L.push("");
      }
      if (e.analysis.keyNames.length) L.push(`Nama variabel yang ditemukan: ${e.analysis.keyNames.map((k) => `\`${esc(k)}\``).join(", ")}`, "");
      if (e.analysis.sqlTables?.length) L.push(`Tabel dalam dump SQL: ${e.analysis.sqlTables.map((t) => `\`${esc(t)}\``).join(", ")}`, "");
      if (e.analysis.composer) L.push(`Composer: ${e.analysis.composer.total} paket (${e.analysis.composer.prod} prod, ${e.analysis.composer.dev} dev)${e.analysis.composer.phpunitInProd ? " — **phpunit/phpunit ada di dependency production**" : ""}`, "");
      L.push("**Rekomendasi:**");
      for (const r of e.analysis.remediation) L.push(`- ${r}`);
      L.push("");
    }
  }

  L.push("## Catatan & batasan", "");
  for (const c of d.caveats) L.push(`- ${c}`);
  L.push("", "> Nilai rahasia penuh (bukan pratinjau) tersimpan terenkripsi AES-256-GCM di Sentinel Vault dan otomatis hilang saat TTL habis. Dokumen ini aman dibagikan sebagai lampiran laporan, namun tetap batasi distribusinya karena memuat pratinjau rahasia.");
  return L.join("\n");
}
