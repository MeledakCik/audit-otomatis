# Sentinel-ID: Unified Passive Security Audit + Encrypted Vault + Admin Telemetry

Platform **Sentinel-ID Auto Security Auditor** telah terverifikasi oleh **Google Developer Bandung (GDG Bandung)**.

## Setup
1. `npm i`
2. Isi variabel environment di `.env.local` (lihat `.env.example` bagian "Sentinel Vault + Admin" & Upstash Redis).
3. `npm run build && npm start` / deploy ke Vercel.

## Rute & Arsitektur Terintegrasi
| Rute | Fungsi |
|---|---|
| `/` & `/?tab=sentinel` | Launchpad Scan Utama: **Full Passive Scan + Sentinel Vault** dan tab **Sentinel Vault & Klaim Domain** |
| `/scan/[id]` | Dashboard Hasil Scan: menyertakan panel **Sentinel Vault & Klaim Kepemilikan Domain** secara langsung |
| `/scan/sentinel` | Halaman khusus modul Scan — Sentinel Vault Audit & Klaim Domain (`/sentinel` otomatis redirect ke bagian Scan) |
| `POST /api/sentinel/audit` | `{domain}` → audit pasif, simpan bukti mentah terenkripsi ke Vault, kembalikan hasil publik |
| `GET /api/sentinel/public/:domain` | Hasil publik tersimpan (TTL 7 hari) |
| `POST/GET /api/sentinel/claim` | Mulai klaim / verifikasi bukti DNS TXT atau HTTP File / cek status |
| `GET /api/sentinel/view/:token` | One-time view (`GETDEL` atomik) untuk melihat bukti mentah dari Vault |
| `/admin/login` → `POST /api/admin/login` | Login Admin Command Center |
| `/admin/activities` | **Dashboard Aktivitas & Data User**: memantau seluruh aktivitas user di semua 17+ modul, profil user (UID/IP/UA), dan seluruh riwayat Scan & QC |
| `/admin/vault` | Brankas bukti terenkripsi (`AES-256-GCM`, AAD=nama key) |
| `/admin/requests` | Panel persetujuan (`ACC` / `REJECT`) klaim kepemilikan domain |

## Redis Keys
- `sentinel:admin:user_activities` (7d, menyimpan seluruh log aktivitas & telemetri user lintas modul)
- `sentinel:public:{domain}` (7d)
- `sentinel:vault:admin:{domain}:{id}` (24h, AES-256-GCM, AAD=nama key)
- `sentinel:auth:{domain}:{userId}` (48h)
- `sentinel:temp:view:{token}` (10m, sekali pakai)
- `session:admin:{jti}` (12h)
- `block:{ip}` (15m) · `fail:{ip}` (15m)

## Master Audit: CVE / CWE / RCE (pasif)

Berjalan otomatis di dalam `/scan` (tanpa request tambahan ke target untuk CVE; endpoint RCE = GET-only).

| Tahap | Modul | Keterangan |
|---|---|---|
| Komponen | `lib/vuln/cve-intel.ts` `collectComponents` | versi library JS + header `Server`/`X-Powered-By` + meta generator WordPress |
| CVE | `runCveIntel` | OSV.dev (npm) + NVD 2.0 (CPE). Cache 24 jam (memori + Redis). Opsional `NVD_API_KEY` untuk limit lebih longgar |
| CWE | `lib/vuln/cwe.ts` | CWE dari feed + heuristik untuk temuan lama (`withCwe` di `addFinding`) |
| RCE | `lib/vuln/rce-surface.ts` | indikator pasif: CVE/CWE bertag RCE sesuai versi, + endpoint debug terbuka (Ignition, Werkzeug console, Actuator, Symfony Profiler, ELMAH, Jolokia, mod_status) dengan validasi isi respons |

**Tidak ada pengujian eksploitasi aktif.** Label "potensi RCE" = klasifikasi CWE/deskripsi CVE, bukan bukti eksploitasi.
Kecocokan berbasis versi dibatasi maksimum **HIGH** (backport bisa membuat false positive); CRITICAL hanya untuk yang tervalidasi dari isi respons.

**User** melihat: judul temuan + CVE/CWE + flag "POTENSI RCE" + tingkat keyakinan.
**Admin** (Vault) mendapat dossier terenkripsi AES-256-GCM (TTL vault 24 jam): komponen + bukti header/banner, daftar CVE lengkap, potongan respons endpoint rawan, ringkasan CWE, dan tombol **Export laporan (.md)** (tanpa snippet mentah) berisi kolom "Diverifikasi oleh" dan "Dilaporkan kepada".
Ekspor laporan sebelum TTL 24 jam habis.
