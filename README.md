# auto-sec-auditor

Passive-only security auditor untuk domain **milik sendiri** (atau yang sudah ada izin tertulis). Dibangun dengan Next.js 16 App Router, TypeScript, Tailwind v4, dan shadcn-style UI primitives.

> ⚠️ **Hanya untuk audit domain sendiri / berizin.** Tool ini tidak melakukan exploit, SQLi/XSS payload, atau bypass proteksi (termasuk Cloudflare). Semua request bersifat pasif (GET only) dan dibatasi rate limit.

## Menjalankan

```bash
npm install
npm run dev
```

Buka [http://localhost:3000](http://localhost:3000).

## Arsitektur

- **Server Actions** (`lib/actions.ts`) — memulai scan, bukan REST API lama. Scan dijalankan di background lewat `after()` sehingga user langsung diarahkan ke halaman progres.
- **Route Handlers** dipakai hanya untuk dua hal yang memang butuh streaming/response biner, bukan mutasi data:
  - `app/api/scan/[id]/stream/route.ts` — Server-Sent Events untuk progres realtime.
  - `app/api/scan/[id]/export/route.ts` — download laporan markdown.
- **`lib/crawler.ts`** — fetch homepage dengan header Chrome asli, parse dengan `cheerio` (link/script/form) dan `linkedom` (isi inline `<script>`). Hanya crawl 1 halaman + link internal, tidak rekursif ke domain lain.
- **`lib/js-analyzer.ts`** — parse file JS (eksternal & inline) dengan `acorn`/`acorn-walk`, cari pola `fetch()`, `axios.*`, `localStorage`, dan literal `"/api/..."`. Fallback ke regex kalau AST gagal parse (bundle production sering di-minify agresif).
- **`lib/tester.ts` + `lib/security-headers.ts`** — 4 kelas pengujian pasif (response leakage, anti-automation, exposed file, security headers ala securityheaders.com). Semua GET-only, tanpa payload.
- **`lib/rate-limit.ts`** — cooldown 1 scan/domain/5 menit + `RequestBudget` (max 100 request/scan, delay 500ms/request).
- **`lib/scan-store.ts`** — state scan disimpan **in-memory saja** (bukan file/DB permanen), auto-terhapus 30 menit setelah dibuat.
- **Cloudflare handling** — kalau terdeteksi challenge page / `cf-mitigated: challenge`, scan langsung dihentikan dan tidak mencoba bypass apa pun.

## Fitur audit mendalam (baru)

- **`lib/site-crawler.ts`** — crawl BFS same-origin sampai 3 level link internal, max 50 URL (`MAX_CRAWL_URLS`). Setiap halaman baru tetap masuk `RequestBudget` yang sama (tidak menambah total request di luar limit 100/scan). Membangun `GraphData` (`page -> js -> endpoint`) yang disimpan di `ScanState.graph`.
- **`lib/secret-scanner.ts`** — scan semua file JS (eksternal + inline) yang sudah diunduh untuk pola secret (Stripe/GitHub/AWS/Google key, JWT, Supabase, `NEXT_PUBLIC_*`, generic password/secret literal + entropy check). Key selalu di-redact sebagian sebelum disimpan sebagai `Finding.evidence`, tidak pernah disimpan utuh.
- **`lib/library-fingerprint.ts`** — fingerprint versi jQuery/lodash/moment/axios/React secara pasif dari string literal versi di HTML/JS, cocokkan ke tabel CVE publik hardcode. Murni pattern-matching, tidak ada exploit yang dijalankan.
- **`lib/report-html.ts`** — render `report.html` gaya pentest: executive summary (URL crawled, JS scanned, secrets, CVE) + temuan terurut CRITICAL→LOW dengan format `[VULN-XXX] [SEVERITY]`, CVSS estimasi, evidence, impact, PoC non-destruktif, remediation.
- **`GET /api/scan/[id]/graph`** — `graph.json` (`{ nodes, edges }`) untuk visualisasi; ditampilkan langsung di dashboard (`components/graph-view.tsx`, layout kolom SVG tanpa dependency tambahan).
- **`GET /api/scan/[id]/report`** — `report.html` siap unduh (`?download=1`) atau dilihat inline.

Semua fitur di atas tunduk pada batasan yang sama seperti sebelumnya: same-origin only, GET-only, tidak ada exploit/POST/DELETE/IDOR aktif, hanya deteksi pola.

## Batasan yang disengaja (bukan bug)

- Tidak bisa scan `localhost`/IP privat — ini SSRF guard di `lib/validate-domain.ts`.
- Tidak menampilkan isi file yang ter-expose (`.env`, `.git/HEAD`), hanya status "exposed".
- Tidak submit form dengan data acak — form action hanya diuji lewat GET.
- Data hasil scan hilang setelah restart server / 30 menit, sesuai desain "no permanent logging".
