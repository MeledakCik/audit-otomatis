# Paket Redesign Glassmorphic Next.js 16 + Tailwind v4 untuk `MeledakCik/audit-otomatis`

Ekstrak file di dalam arsip ini ke root repositori `audit-otomatis` Anda:
1. `app/globals.css` — Menambahkan variabel Glassmorphism (`--surface`, `--surface-raised`, `.glass-panel`, `.glass-pill`) untuk **Light Mode** (`:root` `#f5f5f7`) dan **Dark Mode** (`.dark` `#07070c`).
2. `app/layout.tsx` — Mengaktifkan `enableSystem={true}` pada `ThemeProvider` agar sakelar Dark/Light Mode berjalan mulus.
3. `components/app-shell.tsx` — Mengubah header menjadi *floating glass dock* bergaya Apple lengkap dengan tombol ganti tema Dark/Light dan drawer mobile responsif.
4. `public/opengraph-image.png`, `public/image/image.png`, dan `public/icon.png` — Memperbaiki URL gambar yang sebelumnya 404 Not Found.
