# Sentinel-ID.net — Passive-Only Security Auditor

[[EN](https://img.shields.io/badge/lang-EN-blue.svg)](./README.md) [[ID](https://img.shields.io/badge/lang-ID-red.svg)](#)

> ⚠️ Hanya untuk domain milik sendiri. 100% pasif, hanya membaca, tanpa menyerang.

**Live:** https://www.sentinel-id.net | Sebelumnya: kasyaf-cv.my.id

### Tujuan Tool

Banyak tool audit di luar sana terlalu agresif, langsung nembak payload, POST form, sampai bikin WAF ke-trigger. Sentinel-ID dibuat untuk pemilik website yang mau cek celah dasar tanpa resiko nge-down-in website sendiri.

### Prinsip Kerja

**Same-Origin Only.** Tidak akan keluar dari domain yang di-scan. Kalau ketemu link ke domain lain, otomatis di-skip.

**GET Only.** Tidak ada percobaan login, tidak submit form, tidak inject payload. Endpoint POST yang ketemu cuma ditampilin buat testing manual via cURL.

**Budget Request.** Setiap scan dibatasi maksimal 100 request biar gak dianggap DDoS.

**Cloudflare Aware.** Kalau website dilindungi Cloudflare Challenge, scan akan berhenti otomatis dan kasih instruksi, bukan maksa bypass.

### Struktur Folder Baru v2

Setelah di refactor, struktur lib sekarang jadi lebih rapi:

**discovery** - Isinya logic untuk menjelajahi website. Dia jalanin BFS crawl maksimal 50 halaman untuk nemuin semua halaman, file JS, dan endpoint internal. Termasuk cek file well-known seperti robots.txt & sitemap.xml.

**parsers** - Tugasnya bongkar isi file JavaScript. Dari file JS biasanya ketahuan endpoint tersembunyi, API path, atau link yang gak keliatan di HTML.

**fingerprint** - Bagian identifikasi. Ada dua kerjaan di sini, pertama scan secret seperti API key atau token yang ke-leak di JS, kedua deteksi library dan versi nya untuk cek CVE.

**vuln** - Ini modul baru dari trout-with-passive-audit. Dia bukan ngetes exploit, tapi deteksi pola potensi saja, contohnya pola open redirect, pola IDOR di parameter URL, atau DOM sink berbahaya (innerHTML, location.search) di JS. Hasilnya ditandai POTENTIAL dan wajib review manual.

**fuzzer** - Modul untuk param discovery secara pasif, cuma nebak nama parameter umum tanpa ngirim payload berbahaya buat nemuin hidden API param.

**scan-runner** - Ini otak utamanya. Dia yang ngatur urutan, dari discovery dulu, lalu parsers, lalu fingerprint, vuln, dan fuzzer. Semua hasil akhirnya dikumpulin jadi Finding.

### Alur Logic Scan

Mulai dari URL utama, discovery jalan dulu buat kumpulin peta website. Hasil peta itu dikasih ke parsers buat bongkar JS. Setelah semua link dan file kekumpul, fingerprint jalan buat cek secret dan library. Terakhir vuln dan fuzzer jalan buat cari pola potensi. Semua temuan masuk ke scan-store terus ditampilin di UI berupa tabel Findings, Graph View (14 node / 13 edge), dan QC Score, dan bisa di export ke Laporan Pentest Markdown.

### Contoh Hasil Scan (kasyaf-cv.my.id)

- 1 URL Crawled, 11 JS di-scan, 29 Request
- 0 CRITICAL, 0 HIGH, 6 MEDIUM (false-positive wajar Next.js), 4 LOW, 2 INFO
- Catatan: Temuan MEDIUM di `/_next/static/chunks/*.js` dengan pola `innerHTML` itu wajar dari internal renderer React/Next.js dan hanya ditandai sebagai POTENTIAL lewat regex, bukan celah beneran.

### Batasan Etis

Tool ini sengaja tidak bisa untuk ngetes website orang lain secara agresif. Tidak ada fitur bypass WAF, brute force, atau exploit. Kalau mau scan, pastikan domain itu memang milik sendiri.

---
Also available in: [English](./README.md)