# Sentinel-ID: Unified Passive Security Audit + Encrypted Vault + Deep Shell/OOB Engine

Platform **Sentinel-ID Auto Security Auditor** sudah terverifikasi oleh **Google Developer Bandung (GDG Bandung)**.

## Audit File Sensitif & Brankas Bukti Terenkripsi (AES-256-GCM)
Mendeteksi kebocoran kritis (`.env`, `.git/HEAD`, `backup.zip`, `wp-config.php.bak`, `AWS keys`, `dump.sql`, `id_rsa`) secara pasif. Nilai rahasia tidak pernah bocor ke publik dan disimpan terenkripsi di Vault Admin untuk diklaim pemilik sah domain.

## Deep Shell-Surface & Out-of-Bounds (OOB) Security Checks (100% Pasif GET-Only)
1. **`wp2shell` (WordPress RCE & Config Surface)**:
   - `/wp-config.php.bak`, `/wp-config.php~`, `/wp-config.php.save`
   - `/wp-content/debug.log` (log debug PHP/WordPress terbuka)
   - `/wp-json/wp/v2/users` (enumerasi user REST API)
   - `/xmlrpc.php` (XML-RPC multicall & pingback surface)
   - `/wp-admin/install.php` & `/wp-content/uploads/` directory listing
   - Deteksi statis `admin-ajax.php` / `wp_ajax_nopriv_` di bundle JS
2. **`php2shell` (PHP Eval, Ignition, Profiler & FPM Surface)**:
   - `/_ignition/health-check` (Laravel Ignition debug RCE `CVE-2021-3129`)
   - `/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php` (`CVE-2017-9841`)
   - `/_profiler/` (Symfony Web Profiler)
   - `/phpinfo.php`, `/fpm-status`, `/composer.json`
3. **`node2shell` (Node.js V8 Inspector, PM2 & AST Sinks)**:
   - `/json/version` (Node.js V8 Inspector WebSocket Debugger port terbuka)
   - `/ecosystem.config.js` (konfigurasi proses & secret PM2)
   - `/__nextjs_original-stack-frame` (Next.js dev stack-frame)
   - Deteksi sink JS/Node: `child_process.exec`/`spawn`, `vm.runInNewContext`, deserialisasi `node-serialize`, dan `__proto__` prototype pollution (`CWE-1321`)
4. **`go2shell` (Go pprof, Cmdline & Expvar Runtime Surface)**:
   - `/debug/pprof/` (profil runtime Go, goroutine & heap dump)
   - `/debug/pprof/cmdline` (argumen baris perintah binary Go)
   - `/debug/vars` (`expvar` runtime variables & `memstats`)
   - Deteksi kebocoran stack trace `goroutine [running]`
5. **`py2shell` (Python Werkzeug, Jupyter, Celery & Django Debug Surface)**:
   - `/console` (Werkzeug / Flask Interactive Debug Console)
   - `/api/kernels` (Jupyter / IPython Kernel API tanpa autentikasi)
   - `/api/workers` (Celery Flower worker monitor API)
   - `/__debug__/` (Django Debug Toolbar)
6. **`node out of bound` (Node Out-of-Bounds / Memory Buffer & OOB Callback)**:
   - `/heapdump` & `/actuator/heapdump` (snapshot memori V8 / JVM HPROF)
   - `/graphql` (GraphiQL / Apollo Sandbox introspection surface)
   - Deteksi statis alokasi memori tidak aman: `Buffer.allocUnsafe`, `new Buffer()`, dan `DataView`/`TypedArray` out-of-bounds (`CWE-119`, `CWE-125`, `CWE-787`)
   - Deteksi kebocoran `RangeError: Index out of range` / `ERR_BUFFER_OUT_OF_BOUNDS`
   - Deteksi pasif parameter kandidat Out-of-Band (`callback`, `webhook`, `notify_url`, `pingback`, `oob`, `wsdl`, `xml`)

## Rute & Arsitektur Terintegrasi
| Rute | Fungsi |
|---|---|
| `/` & `/?tab=sentinel` | Launchpad Scan Utama: **Full Passive Scan + Deep Shell/OOB + Sentinel Vault** dan tab **Brankas AES-256-GCM & Klaim** |
| `/scan/[id]` | Dashboard Hasil Scan: menyertakan panel **Audit File Sensitif & Brankas Bukti Terenkripsi (AES-256-GCM)** secara langsung |
| `/scan/sentinel` | Halaman khusus modul Scan — Sentinel Vault Audit & Klaim Domain (`/sentinel` otomatis redirect ke bagian Scan) |
| `/scan/exposure` | Cloud Exposure, Sensitive File & Deep Shell Path Inspector (otomatis mengenkripsi temuan kritis ke Vault Admin) |
| `POST /api/sentinel/audit` | `{domain}` → audit pasif file sensitif + deep shell/OOB, simpan bukti mentah terenkripsi ke Vault, kembalikan hasil publik |
| `GET /api/sentinel/public/:domain` | Hasil publik tersimpan (TTL 7 hari) |
| `POST/GET /api/sentinel/claim` | Mulai klaim / verifikasi bukti DNS TXT atau HTTP File / cek status |
| `GET /api/sentinel/view/:token` | One-time view (`GETDEL` atomik) untuk melihat bukti mentah dari Vault |
| `/admin/activities` | **Dashboard Aktivitas & Data User**: memantau seluruh aktivitas user di semua modul |
| `/admin/vault` | Brankas bukti terenkripsi (`AES-256-GCM`, AAD=nama key) |
| `/admin/requests` | Panel persetujuan (`ACC` / `REJECT`) klaim kepemilikan domain |
