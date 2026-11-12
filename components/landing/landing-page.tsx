import Link from "next/link";
import {
  ArrowRight, ShieldCheck, Radar, Lock, TrendingUp, Network, ClipboardCheck,
  Check, Globe, AtSign, EyeOff, ServerCog, FileCheck2, Sparkles, Terminal
} from "lucide-react";
import { GlassCanvas } from "@/components/landing/glass-canvas";
import { LandingNav } from "@/components/landing/landing-nav";
import { AUTHOR } from "@/lib/author";
import Image from "next/image";
const FEATURES = [
  {
    icon: ShieldCheck,
    title: "Audit pasif, tanpa eksploit",
    desc: "Hanya GET/HEAD dengan batas 100 request. Tidak ada payload berbahaya, tidak ada perubahan pada target.",
  },
  {
    icon: Radar,
    title: "8 engine deteksi runtime",
    desc: "Header, TLS, DNS, JavaScript, API, file sensitif, SEO, dan performa diperiksa secara paralel.",
  },
  {
    icon: Lock,
    title: "Brankas temuan AES-256",
    desc: "Temuan sensitif disimpan terenkripsi. Hanya pemilik yang dapat membuka dan mengklaim bukti.",
  },
  {
    icon: TrendingUp,
    title: "SEO & performa menyeluruh",
    desc: "35+ sinyal Google, hreflang, structured data, Core Web Vitals, hingga broken link.",
  },
  {
    icon: Network,
    title: "Peta serangan visual",
    desc: "Graf interaktif halaman, script, dan endpoint untuk memetakan permukaan serangan secara utuh.",
  },
  {
    icon: ClipboardCheck,
    title: "QC otomatis & laporan siap-klien",
    desc: "Laporan terprioritas berisi bukti, dampak, dan rekomendasi perbaikan yang dapat langsung dieksekusi.",
  },
];

const STEPS = [
  { title: "Masukkan domain", desc: "Satu domain, tanpa login, tanpa verifikasi kepemilikan.", icon: Terminal },
  { title: "Crawl pasif", desc: "Mesin menjelajah halaman publik dan memetakan permukaan serangan.", icon: Radar },
  { title: "Lihat temuan", desc: "Daftar temuan terprioritas lengkap dengan bukti dan tingkat keparahan.", icon: Sparkles },
  { title: "Klaim bukti", desc: "Simpan bukti terenkripsi dan bagikan laporan ke tim atau klien.", icon: FileCheck2 },
];

const TRUST = ["Tanpa login", "GET-only", "Zero-exploit", "AES-256", "Data terenkripsi"];

const STATS = [
  { value: "8", label: "Engine pemeriksa" },
  { value: "100", label: "Request maksimal" },
  { value: "35+", label: "Sinyal SEO" },
  { value: "0", label: "Eksploit dijalankan" },
];

const PRINCIPLES = [
  {
    icon: EyeOff,
    title: "Tidak menyentuh data sensitif",
    desc: "Kami tidak menyimpan kredensial, token, atau data pengguna akhir target Anda.",
  },
  {
    icon: ServerCog,
    title: "Tanpa perubahan pada target",
    desc: "Semua permintaan bersifat read-only. Tidak ada state, konfigurasi, atau konten yang dimodifikasi.",
  },
  {
    icon: FileCheck2,
    title: "Bukti yang dapat dipertanggungjawabkan",
    desc: "Setiap temuan dilengkapi bukti request/response, timestamp, dan tingkat keparahan yang jelas.",
  },
];

const cta =
  "inline-flex items-center justify-center gap-2 px-6 py-3.5 rounded-xl text-base font-semibold text-white bg-gradient-accent hover:brightness-110 hover:shadow-[0_0_20px_rgba(var(--accent),0.4)] transition-all duration-300";

export function LandingPage() {
  return (
    <div className="relative min-h-dvh overflow-x-clip bg-background selection:bg-accent/30">

      {/* ===== GLOBAL AMBIENT BACKGROUND ===== */}
      {/* Memberikan pendaran warna di seluruh halaman agar tidak hitam pekat */}
      <div className="fixed inset-0 -z-20 pointer-events-none overflow-hidden">
        <div className="absolute -top-[20%] left-1/2 -translate-x-1/2 w-[80vw] h-[60vh] bg-accent/10 blur-[120px] rounded-full mix-blend-screen opacity-50" />
        <div className="absolute top-[40%] -left-[10%] w-[50vw] h-[50vh] bg-accent-2/10 blur-[120px] rounded-full mix-blend-screen opacity-40" />
        <div className="absolute bottom-[-10%] right-[-10%] w-[60vw] h-[60vh] bg-accent/5 blur-[150px] rounded-full mix-blend-screen opacity-30" />
      </div>

      <LandingNav />

      <main id="main" className="relative">
        {/* ===== HERO ===== */}
        <section className="relative isolate min-h-[100svh] flex items-center pt-32 pb-20 px-4 sm:px-6">
          <GlassCanvas className="absolute inset-0 -z-10 w-full h-full opacity-80 [mask-image:linear-gradient(to_bottom,black_50%,transparent_100%)]" />

          <div className="max-w-6xl mx-auto w-full grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
            {/* Kiri: pesan utama */}
            <div className="lg:col-span-7 space-y-7">
              <span className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-medium glass-pill text-soft animate-fade-up">
                <ShieldCheck className="w-3.5 h-3.5 text-accent" aria-hidden />
                Audit keamanan pasif · tanpa login
              </span>

              <h1 className="text-4xl sm:text-5xl xl:text-6xl font-extrabold tracking-tight leading-[1.08] text-balance animate-fade-up">
                Ketahui risiko keamanan web Anda{" "}
                <span className="text-gradient-accent">dalam hitungan menit.</span>
              </h1>

              <p className="text-lg text-soft max-w-xl animate-fade-up" style={{ animationDelay: "70ms" }}>
                Masukkan domain, dapatkan temuan terprioritas lengkap dengan bukti — tanpa
                eksploit, tanpa login, dan tanpa mengubah apa pun pada target.
              </p>

              <div className="flex flex-wrap gap-3 animate-fade-up" style={{ animationDelay: "140ms" }}>
                <Link href="/dashboard" className={cta}>
                  Mulai audit sekarang <ArrowRight className="w-5 h-5" aria-hidden />
                </Link>
                <a href="#fitur" className="inline-flex items-center px-6 py-3.5 rounded-xl text-base font-semibold glass-pill hover:border-accent/40 hover:bg-foreground/5 transition-all">
                  Lihat fitur
                </a>
              </div>

              <ul className="flex flex-wrap gap-x-5 gap-y-2 text-sm text-muted animate-fade-up" style={{ animationDelay: "200ms" }}>
                {TRUST.map((t) => (
                  <li key={t} className="inline-flex items-center gap-1.5">
                    <Check className="w-4 h-4 text-ok" aria-hidden /> {t}
                  </li>
                ))}
              </ul>
            </div>

            {/* Kanan: preview dashboard */}
            <div className="lg:col-span-5 animate-fade-up" style={{ animationDelay: "160ms" }}>
              <div className="glass-panel rounded-3xl p-5 sm:p-6 space-y-5 shadow-2xl shadow-accent/5">
                <div className="flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <p className="text-xs text-muted">Hasil audit</p>
                    <p className="text-base font-semibold truncate">contoh-domain.id</p>
                  </div>
                  <span className="text-[11px] uppercase tracking-wide text-muted shrink-0 px-2 py-1 rounded-md bg-foreground/[0.06]">
                    Ilustrasi
                  </span>
                </div>

                <ul className="space-y-2.5 text-sm">
                  <li className="flex items-start gap-2.5">
                    <Check className="w-4 h-4 text-ok shrink-0 mt-0.5" aria-hidden />
                    <span>Header keamanan lengkap (HSTS, CSP, XFO)</span>
                  </li>
                  <li className="flex items-start gap-2.5">
                    <Check className="w-4 h-4 text-ok shrink-0 mt-0.5" aria-hidden />
                    <span>Tidak ada file sensitif terbuka</span>
                  </li>
                  <li className="flex items-start gap-2.5">
                    <span className="w-4 text-center text-warn font-bold shrink-0 mt-0.5" aria-hidden>!</span>
                    <span>CSP masih memuat <code className="text-xs">unsafe-inline</code></span>
                  </li>
                </ul>

                <div className="grid grid-cols-3 gap-2 text-center">
                  {[["0", "Critical"], ["2", "Medium"], ["4", "Low"]].map(([v, l]) => (
                    <div key={l} className="rounded-xl bg-foreground/[0.04] py-3 border border-border/50">
                      <div className="text-xl font-bold tabular-nums">{v}</div>
                      <div className="text-xs text-muted">{l}</div>
                    </div>
                  ))}
                </div>

                <div className="pt-1 border-t border-border/60 flex items-center justify-between text-xs text-muted">
                  <span>Durasi: 42 detik</span>
                  <span>Request: 87 / 100</span>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ===== STATS / TRUST BAR ===== */}
        <section className="px-4 sm:px-6 relative z-10">
          <div className="max-w-6xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-3 sm:gap-4">
            {STATS.map((s) => (
              <div key={s.label} className="glass-panel rounded-2xl px-5 py-6 text-center hover:border-accent/30 transition-colors">
                <div className="text-3xl font-extrabold tabular-nums text-gradient-accent">
                  {s.value}
                </div>
                <div className="text-sm text-muted mt-1">{s.label}</div>
              </div>
            ))}
          </div>
        </section>

        {/* ===== FITUR ===== */}
        <section id="fitur" className="px-4 sm:px-6 py-20 sm:py-28 relative">
          <div className="max-w-6xl mx-auto space-y-10">
            <header className="space-y-3 max-w-2xl">
              <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">Fitur utama</h2>
              <p className="text-lg text-soft">
                Semua yang Anda butuhkan untuk memahami risiko keamanan dan kualitas teknis
                sebuah domain — dalam satu dashboard.
              </p>
            </header>

            <ul className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 sm:gap-5">
              {FEATURES.map(({ icon: Icon, title, desc }) => (
                <li key={title} className="group glass-panel rounded-2xl p-6 flex flex-col gap-4 hover:border-accent/40 hover:-translate-y-1 hover:shadow-xl hover:shadow-accent/5 transition-all duration-300">
                  <span className="w-12 h-12 rounded-xl bg-accent/10 text-accent flex items-center justify-center shrink-0 group-hover:scale-110 group-hover:bg-accent/20 transition-all duration-300">
                    <Icon className="w-6 h-6" aria-hidden />
                  </span>
                  <div className="min-w-0">
                    <h3 className="text-lg font-semibold mb-1.5">{title}</h3>
                    <p className="text-sm text-muted leading-relaxed">{desc}</p>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </section>

        {/* ===== PRINSIP KEAMANAN ===== */}
        <section id="keamanan" className="px-4 sm:px-6 py-20 bg-foreground/[0.02] border-y border-border/40 relative">
          <div className="max-w-6xl mx-auto space-y-10">
            <header className="space-y-3 max-w-2xl">
              <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">Kenapa audit pasif?</h2>
              <p className="text-lg text-soft">
                Keamanan tidak harus invasif. Kami merancang setiap pemeriksaan agar aman
                bagi target dan dapat dipertanggungjawabkan hasilnya.
              </p>
            </header>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
              {PRINCIPLES.map(({ icon: Icon, title, desc }) => (
                <div key={title} className="glass-panel rounded-2xl p-6 space-y-4 hover:border-accent/30 transition-colors">
                  <span className="w-10 h-10 rounded-xl bg-accent/10 text-accent flex items-center justify-center">
                    <Icon className="w-5 h-5" aria-hidden />
                  </span>
                  <h3 className="text-lg font-semibold">{title}</h3>
                  <p className="text-sm text-muted leading-relaxed">{desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ===== CARA KERJA ===== */}
        <section id="cara-kerja" className="px-4 sm:px-6 py-20 sm:py-28 relative">
          <div className="max-w-6xl mx-auto space-y-10">
            <header className="space-y-3 max-w-2xl">
              <h2 className="text-3xl sm:text-4xl font-bold tracking-tight">Cara kerja</h2>
              <p className="text-lg text-soft">Empat langkah mudah, tanpa setup rumit.</p>
            </header>

            <ol className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 relative">
              {/* Garis penghubung visual di desktop */}
              <div className="hidden lg:block absolute top-[48px] left-[10%] right-[10%] h-[2px] bg-gradient-to-r from-transparent via-accent/30 to-transparent -z-10" />

              {STEPS.map((s, i) => (
                <li key={s.title} className="glass-panel rounded-2xl p-6 space-y-3 relative bg-background/80 backdrop-blur-md">
                  <div className="flex items-center justify-between">
                    <span className="w-10 h-10 rounded-full bg-accent/10 text-accent flex items-center justify-center">
                      <s.icon className="w-5 h-5" aria-hidden />
                    </span>
                    <span className="text-sm font-mono font-bold text-accent/50">
                      0{i + 1}
                    </span>
                  </div>
                  <div>
                    <p className="text-lg font-semibold">{s.title}</p>
                    <p className="text-sm text-muted leading-relaxed mt-1">{s.desc}</p>
                  </div>
                </li>
              ))}
            </ol>
          </div>
        </section>

        {/* ===== CTA ===== */}
        <section className="px-4 sm:px-6 pb-24 relative">
          <div className="max-w-4xl mx-auto rounded-3xl p-8 sm:p-12 text-center space-y-6 relative overflow-hidden glass-panel border-accent/20">
            {/* Efek glow di belakang CTA */}
            <div className="absolute inset-0 bg-gradient-to-b from-accent/10 to-transparent -z-10" />

            <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-balance">
              Siap memeriksa domain Anda?
            </h2>
            <p className="text-lg text-soft max-w-lg mx-auto">
              Mulai audit pertama Anda dalam hitungan detik. Tidak perlu kartu kredit, tidak
              perlu login.
            </p>
            <div className="pt-2">
              <Link href="/dashboard" className={cta}>
                Mulai audit sekarang <ArrowRight className="w-5 h-5" aria-hidden />
              </Link>
            </div>
          </div>
        </section>

        {/* ===== AUTHOR ===== */}
        <section id="author" className="px-4 sm:px-6 pb-20 relative">
          <div className="max-w-4xl mx-auto glass-panel rounded-3xl p-6 sm:p-8 flex flex-col sm:flex-row sm:items-center gap-6 group/card hover:border-accent/30 transition-colors duration-300">

            {/* CONTAINER FOTO PROFIL */}
            <div className="relative w-20 h-20 sm:w-24 sm:h-24 rounded-2xl overflow-hidden shrink-0 border-2 border-accent/20 shadow-lg shadow-accent/10 group-hover/card:border-accent/50 transition-all duration-300">
              <Image
                src="/image/profile.png" // Ganti dengan URL https://www.kasyaf.id/profile jika diizinkan di next.config.js
                alt={`Foto profil ${AUTHOR.name}`}
                fill
                sizes="(max-width: 640px) 80px, 96px"
                className="object-cover object-center transition-transform duration-500 group-hover/card:scale-110"
                priority={false}
              />
            </div>

            {/* INFO TEKS */}
            <div className="flex-1 min-w-0 text-center sm:text-left">
              <p className="text-sm text-muted mb-1">Dirancang dan dikembangkan oleh</p>
              <p className="text-xl font-bold text-foreground">{AUTHOR.name}</p>
              {/* Anda bisa menambahkan role/title di sini jika ada */}
              {/* <p className="text-xs text-accent font-medium mt-0.5">Security Researcher & Developer</p> */}
            </div>

            {/* TOMBOL LINK */}
            <div className="flex flex-wrap items-center justify-center sm:justify-end gap-3 shrink-0">
              <a
                href={AUTHOR.websiteUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-medium glass-pill hover:border-accent/40 hover:bg-foreground/5 hover:text-accent transition-all duration-300"
              >
                <Globe className="w-4 h-4" aria-hidden /> {AUTHOR.website}
              </a>
              <a
                href={AUTHOR.instagramUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 px-5 py-2.5 rounded-xl text-sm font-medium glass-pill hover:border-accent/40 hover:bg-foreground/5 hover:text-accent transition-all duration-300"
              >
                <AtSign className="w-4 h-4" aria-hidden /> {AUTHOR.instagramHandle}
              </a>
            </div>

          </div>
        </section>
      </main>

      <footer className="px-4 sm:px-6 pb-10 relative">
        <div className="max-w-6xl mx-auto border-t border-border/50 pt-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-muted">
          <span>
            © {new Date().getFullYear()} Sentinel-ID · oleh{" "}
            <a
              href={AUTHOR.websiteUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-foreground text-accent underline-offset-4 hover:underline transition-colors"
            >
              {AUTHOR.name}
            </a>
          </span>
          <nav aria-label="Tautan footer" className="flex gap-6">
            <Link href="/docs" className="hover:text-foreground transition-colors">
              Dokumentasi
            </Link>
            <Link href="/api-docs" className="hover:text-foreground transition-colors">
              API
            </Link>
          </nav>
        </div>
      </footer>
    </div>
  );
}