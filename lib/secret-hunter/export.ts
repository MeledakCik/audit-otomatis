import type { SecretHuntReport } from "./types";

export function downloadSecretHuntAsJson(report: SecretHuntReport) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sentinel-secret-hunt-${report.hostname}-${report.id}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

const BASE_GITIGNORE = `# Env & secret files — jangan pernah commit ini
.env
.env.local
.env.*.local
.env.development
.env.production
*.pem
*.key
*.p12
*.pfx
credentials.json
serviceAccountKey.json
`;

/**
 * Bangun konten .gitignore + .env.example berdasarkan temuan scan:
 * - .gitignore: baseline standar untuk file env/credential.
 * - .env.example: daftar nama variable VITE_ / NEXT_PUBLIC_ yang terdeteksi
 *   berisi kata kunci rahasia, diisi placeholder (bukan value asli).
 */
export function buildHardeningKit(report: SecretHuntReport): { gitignore: string; envExample: string } {
  const gitignore = BASE_GITIGNORE;

  const envLines = report.envVarNamesFound.length
    ? report.envVarNamesFound.map((name) => `${name}=your_value_here`)
    : ["# Tidak ada variable VITE_*/NEXT_PUBLIC_* mencurigakan yang terdeteksi pada scan ini."];

  const envExample = `# .env.example — dihasilkan dari Sentinel-ID Secret Hunter
# Target: ${report.hostname}
# Catatan: variable dengan prefix VITE_ / NEXT_PUBLIC_ SELALU ikut ter-bundle
# ke client oleh design. Kalau isinya harus rahasia, pindahkan ke variable
# TANPA prefix tersebut dan akses hanya dari server component / API route.

${envLines.join("\n")}
`;

  return { gitignore, envExample };
}

export function downloadHardeningKit(report: SecretHuntReport) {
  const { gitignore, envExample } = buildHardeningKit(report);
  const content = `# ============================================================
# Sentinel-ID Secret Hunter — Hardening Kit
# Target: ${report.hostname}
# Generated: ${new Date(report.createdAt).toISOString()}
#
# File ini berisi DUA bagian. Salin masing-masing ke file terpisah
# di root project kamu: ".gitignore" dan ".env.example".
# ============================================================

# ---------- BEGIN .gitignore ----------
${gitignore}
# ---------- END .gitignore ----------


# ---------- BEGIN .env.example ----------
${envExample}
# ---------- END .env.example ----------
`;

  const blob = new Blob([content], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sentinel-hardening-kit-${report.hostname}.txt`;
  a.click();
  URL.revokeObjectURL(url);
}
