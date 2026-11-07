// Pure types + label statis (tanpa import node) → aman dipakai di client (panel admin / view pemilik).

export type SensitiveCategory =
  | "env" | "vcs" | "config" | "credentials" | "private-key" | "cloud-state"
  | "sql-dump" | "archive" | "log" | "ide" | "php-deps" | "php-diag" | "db-file"
  | "webshell" | "filemanager" | "misc";

export type SecretType =
  | "aws-access-key" | "aws-secret-key" | "google-api-key" | "github-token" | "slack-token"
  | "stripe-key" | "sendgrid-key" | "private-key" | "jwt" | "db-url-credentials" | "app-key"
  | "gcp-service-account" | "npm-token" | "password" | "generic-secret";

export const SECRET_LABELS: Record<SecretType, string> = {
  "aws-access-key": "AWS Access Key ID",
  "aws-secret-key": "AWS Secret Access Key",
  "google-api-key": "Google API key",
  "github-token": "GitHub token",
  "slack-token": "Slack token",
  "stripe-key": "Stripe live key",
  "sendgrid-key": "SendGrid API key",
  "private-key": "Private key (PEM)",
  jwt: "JWT",
  "db-url-credentials": "Kredensial di URL database",
  "app-key": "Laravel APP_KEY",
  "gcp-service-account": "GCP service account key",
  "npm-token": "npm auth token",
  password: "Password",
  "generic-secret": "Secret / token / API key",
};

export const REMEDIATION: Record<SecretType, string[]> = {
  "aws-access-key": ["Nonaktifkan (Deactivate) lalu hapus access key di IAM, buat key baru.", "Periksa CloudTrail sejak waktu kebocoran untuk aktivitas tak dikenal; aktifkan GuardDuty/alert."],
  "aws-secret-key": ["Rotasi pasangan access key + secret di IAM dan cabut yang lama.", "Tinjau kebijakan IAM: terapkan prinsip least-privilege."],
  "google-api-key": ["Batasi key (HTTP referrer / IP / API tertentu) atau buat key baru dan hapus yang lama."],
  "github-token": ["Cabut token di Settings → Developer settings, buat baru dengan scope minimal.", "Periksa audit log GitHub untuk aktivitas mencurigakan."],
  "slack-token": ["Cabut/regenerasi token di pengaturan aplikasi Slack dan periksa log akses."],
  "stripe-key": ["Roll key di dashboard Stripe segera dan periksa transaksi/log API."],
  "sendgrid-key": ["Hapus API key di SendGrid, buat baru dengan izin minimal, cek aktivitas pengiriman email."],
  "private-key": ["Anggap key sudah bocor: buat keypair baru, hapus public key lama dari authorized_keys/layanan terkait.", "Untuk kunci TLS: terbitkan ulang sertifikat dan cabut yang lama."],
  jwt: ["Pastikan token sudah kedaluwarsa/ dicabut; rotasi signing secret bila perlu."],
  "db-url-credentials": ["Ganti password user database, batasi akses jaringan (allowlist IP), periksa log koneksi mencurigakan."],
  "app-key": ["Rotasi APP_KEY (perhatikan: sesi dan data terenkripsi lama menjadi tidak valid), lalu deploy ulang."],
  "gcp-service-account": ["Hapus/rotasi service account key di IAM, periksa Cloud Audit Logs."],
  "npm-token": ["Revoke token di npmjs.com, buat baru dengan scope minimal."],
  password: ["Ganti password tersebut dan semua tempat yang memakai password yang sama."],
  "generic-secret": ["Rotasi secret/token tersebut di sistem asalnya dan periksa log penggunaan."],
};

export const COMMON_REMEDIATION = [
  "Hapus file dari webroot dan blokir pola path-nya di web server (dotfile, backup, *.sql, *.log).",
  "Periksa access log untuk path ini guna menilai apakah file sudah diunduh pihak lain.",
  "Letakkan konfigurasi/rahasia di luar direktori publik dan simpan di secret manager.",
];

export const BACKUP_REMEDIATION = [
  "Hapus backup dari webroot, simpan di storage privat terenkripsi.",
  "Anggap seluruh isi (kode, database, kredensial) sudah terbaca; rotasi semua kredensial di dalamnya.",
  ...COMMON_REMEDIATION.slice(1),
];

export const WEBSHELL_REMEDIATION = [
  "ISOLASI SEGERA: Hapus file webshell / file manager berbahaya dari server produksi dan cabut izin tulis (chmod) pada direktori webroot.",
  "Lakukan audit forensik pada access log, crontab, ~/.ssh/authorized_keys, dan proses background untuk mencari backdoor persistensi lain.",
  "Rotasi seluruh kredensial database, APP_KEY, token API, dan password akun administrator karena webshell memberikan akses baca penuh ke filesystem.",
];

export interface SecretFinding {
  type: SecretType;
  label: string;
  keyName?: string;
  /** Pratinjau teredaksi (hanya admin/pemilik). Bukan nilai penuh. */
  preview: string;
  /** 12 hex pertama SHA-256 — untuk mencocokkan dengan inventori key tanpa membuka nilainya. */
  hash12: string;
  /** true = tampak kredensial nyata; false = placeholder/default/contoh/kedaluwarsa. */
  live: boolean;
  reason?: string;
  note?: string;
  awsAccountId?: string;
}

export interface ComposerSummary {
  total: number;
  prod: number;
  dev: number;
  notable: string[]; // mis. "laravel/framework@8.40.0"
  phpunitInProd: boolean;
}

export interface SensitiveAnalysis {
  category: SensitiveCategory;
  fileKind: string;
  secrets: SecretFinding[];
  liveCount: number;
  placeholderCount: number;
  keyNames: string[];
  sizeBytes?: number;
  lastModified?: string;
  etag?: string;
  sqlTables?: string[];
  serverVersion?: string;
  composer?: ComposerSummary;
  remediation: string[];
  /** Ringkasan aman untuk publik: jenis + jumlah, tanpa nilai/pratinjau. */
  summaryPublic: string;
}

// ======================= Dossier admin (agregat lintas path) =======================

export interface SensitiveFileEntry {
  path: string;
  url: string;
  title: string;
  category: SensitiveCategory;
  severity: "CRITICAL" | "HIGH";
  fileKind: string;
  marker: string;
  status: number;
  confidence: "verified" | "existence-only";
  analysis: SensitiveAnalysis; // termasuk secrets[] lengkap — HANYA admin
  cwe: string[];
  cve?: string[];
  rce?: boolean;
  fix: string;
}

export interface SensitiveDossier {
  version: 1;
  domain: string;
  origin: string;
  generatedAt: number;
  pathsChecked: number;
  entries: SensitiveFileEntry[];
  summary: {
    totalFiles: number;
    criticalFiles: number;
    liveSecrets: number;
    placeholderSecrets: number;
    byCategory: Record<string, number>;
    secretTypes: Record<string, number>;
    awsAccountIds: string[];
  };
  caveats: string[];
}
