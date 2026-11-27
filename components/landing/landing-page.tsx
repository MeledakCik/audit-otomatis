import Link from "next/link";
import {
  ArrowRight, ShieldCheck, Radar, Lock, TrendingUp, Network, ClipboardCheck,
  Check, Globe, AtSign, EyeOff, ServerCog, FileCheck2, Sparkles, Terminal
} from "lucide-react";
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
  "inline-flex items-center justify-center gap-2 h-11 px-5 rounded-xl text-sm font-medium bg-accent text-accent-fg hover:bg-accent-dim transition-colors";
const ctaGhost =
  "inline-flex items-center justify-center gap-2 h-11 px-5 rounded-xl text-sm font-medium border border-border text-foreground hover:bg-foreground/5 transition-colors";
const section = "px-4 sm:px-6 lg:px-8";
const sectionTitle = "text-2xl sm:text-3xl font-semibold tracking-tight";
const sectionLead = "text-base text-muted leading-relaxed";

export function LandingPage() {
  return (
    <div className="min-h-dvh overflow-x-clip bg-background selection:bg-accent/20">

      <LandingNav />

      <main id="main">
        {/* ===== HERO ===== */}
        <section className={`${section} pt-32 sm:pt-40 pb-20 sm:pb-28`}>

          <div className="max-w-6xl mx-auto w-full grid grid-cols-1 lg:grid-cols-12 gap-12 lg:gap-16 items-center">
            {/* Kiri: pesan utama */}
            <div className="lg:col-span-7 space-y-6">
              <span className="inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs font-medium border border-border text-muted animate-fade-up">
                <ShieldCheck className="w-3.5 h-3.5 text-accent" aria-hidden />
                Audit keamanan pasif · tanpa login
              </span>

              <h1 className="text-4xl sm:text-5xl font-semibold tracking-tight leading-[1.1] text-balance animate-fade-up">
                Ketahui risiko keamanan web Anda{" "}
                <span className="text-gradient-accent">dalam hitungan menit.</span>
              </h1>

              <p className="text-base sm:text-lg text-muted leading-relaxed max-w-xl animate-fade-up" style={{ animationDelay: "70ms" }}>
                Masukkan domain, dapatkan temuan terprioritas lengkap dengan bukti — tanpa
                eksploit, tanpa login, dan tanpa mengubah apa pun pada target.
              </p>

              <div className="flex flex-wrap gap-3 pt-2 animate-fade-up" style={{ animationDelay: "140ms" }}>
                <Link href="/dashboard" className={cta}>
                  Mulai audit sekarang <ArrowRight className="w-4 h-4" aria-hidden />
                </Link>
                <a href="#fitur" className={ctaGhost}>
                  Lihat fitur
                </a>
              </div>

              <ul className="flex flex-wrap gap-x-5 gap-y-2 pt-2 text-sm text-muted animate-fade-up" style={{ animationDelay: "200ms" }}>
                {TRUST.map((t) => (
                  <li key={t} className="inline-flex items-center gap-1.5">
                    <Check className="w-4 h-4 text-ok" aria-hidden /> {t}
                  </li>
                ))}
              </ul>
            </div>

            {/* Kanan: preview dashboard */}
            <div className="lg:col-span-5 animate-fade-up" style={{ animationDelay: "160ms" }}>
              <div className="glass-panel rounded-2xl p-6 space-y-5">
                <div className="flex items-center justify-between gap-3">
                  <div className="min-w-0">
                    <p className="text-xs text-muted">Hasil audit</p>
                    <p className="text-base font-semibold truncate">contoh-domain.id</p>
                  </div>
                  <span className="text-[11px] text-muted-dim shrink-0 px-2 py-0.5 rounded-md border border-border">
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
                    <div key={l} className="rounded-xl bg-sunken py-3">
                      <div className="text-xl font-bold tabular-nums">{v}</div>
                      <div className="text-xs text-muted">{l}</div>
                    </div>
                  ))}
                </div>

                <div className="pt-4 border-t border-border flex items-center justify-between text-xs text-muted">
                  <span>Durasi: 42 detik</span>
                  <span>Request: 87 / 100</span>
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ===== STATS / TRUST BAR ===== */}
        <section className={section}>
          <dl className="max-w-6xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-y-8 border-y border-border py-10">
            {STATS.map((s) => (
              <div key={s.label} className="text-center px-4">
                <dd className="text-3xl font-semibold tabular-nums tracking-tight">{s.value}</dd>
                <dt className="text-sm text-muted mt-1">{s.label}</dt>
              </div>
            ))}
          </dl>
        </section>

        {/* ===== FITUR ===== */}
        <section id="fitur" className={`${section} py-20 sm:py-28`}>
          <div className="max-w-6xl mx-auto space-y-12">
            <header className="space-y-3 max-w-2xl">
              <h2 className={sectionTitle}>Fitur utama</h2>
              <p className={sectionLead}>
                Semua yang Anda butuhkan untuk memahami risiko keamanan dan kualitas teknis
                sebuah domain — dalam satu dashboard.
              </p>
            </header>

            <ul className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-x-10 gap-y-10">
              {FEATURES.map(({ icon: Icon, title, desc }) => (
                <li key={title} className="flex flex-col gap-3">
                  <span className="w-9 h-9 rounded-lg bg-accent/10 text-accent flex items-center justify-center shrink-0">
                    <Icon className="w-[18px] h-[18px]" aria-hidden />
                  </span>
                  <div className="min-w-0">
                    <h3 className="text-base font-semibold mb-1">{title}</h3>
                    <p className="text-sm text-muted leading-relaxed">{desc}</p>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </section>

        {/* ===== PRINSIP KEAMANAN ===== */}
        <section id="keamanan" className={`${section} py-20 sm:py-28 bg-sunken/60 border-y border-border`}>
          <div className="max-w-6xl mx-auto space-y-12">
            <header className="space-y-3 max-w-2xl">
              <h2 className={sectionTitle}>Kenapa audit pasif?</h2>
              <p className={sectionLead}>
                Keamanan tidak harus invasif. Kami merancang setiap pemeriksaan agar aman
                bagi target dan dapat dipertanggungjawabkan hasilnya.
              </p>
            </header>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-5">
              {PRINCIPLES.map(({ icon: Icon, title, desc }) => (
                <div key={title} className="glass-panel rounded-2xl p-6 space-y-3">
                  <Icon className="w-5 h-5 text-accent" aria-hidden />
                  <h3 className="text-base font-semibold">{title}</h3>
                  <p className="text-sm text-muted leading-relaxed">{desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ===== CARA KERJA ===== */}
        <section id="cara-kerja" className={`${section} py-20 sm:py-28`}>
          <div className="max-w-6xl mx-auto space-y-12">
            <header className="space-y-3 max-w-2xl">
              <h2 className={sectionTitle}>Cara kerja</h2>
              <p className={sectionLead}>Empat langkah mudah, tanpa setup rumit.</p>
            </header>

            <ol className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-x-8 gap-y-10">
              {STEPS.map((s, i) => (
                <li key={s.title} className="space-y-3 border-t border-border pt-5">
                  <div className="flex items-center gap-3">
                    <span className="text-xs font-mono text-muted-dim tabular-nums">0{i + 1}</span>
                    <s.icon className="w-4 h-4 text-accent" aria-hidden />
                  </div>
                  <div>
                    <p className="text-base font-semibold">{s.title}</p>
                    <p className="text-sm text-muted leading-relaxed mt-1">{s.desc}</p>
                  </div>
                </li>
              ))}
            </ol>
          </div>
        </section>

        {/* ===== CTA ===== */}
        <section className={`${section} pb-20 sm:pb-28`}>
          <div className="max-w-4xl mx-auto rounded-2xl px-6 py-12 sm:p-14 text-center space-y-5 glass-panel">
            <h2 className={`${sectionTitle} text-balance`}>
              Siap memeriksa domain Anda?
            </h2>
            <p className={`${sectionLead} max-w-lg mx-auto`}>
              Mulai audit pertama Anda dalam hitungan detik. Tidak perlu kartu kredit, tidak
              perlu login.
            </p>
            <div className="pt-3">
              <Link href="/dashboard" className={cta}>
                Mulai audit sekarang <ArrowRight className="w-4 h-4" aria-hidden />
              </Link>
            </div>
          </div>
        </section>

        {/* ===== AUTHOR ===== */}
        <section id="author" className={`${section} pb-20`}>
          <div className="max-w-4xl mx-auto flex flex-col sm:flex-row items-center gap-5 sm:gap-6">

            {/* CONTAINER FOTO PROFIL */}
            <div className="relative w-16 h-16 rounded-full overflow-hidden shrink-0 border border-border">
              <Image
                src="/image/profile.png" // Ganti dengan URL https://www.kasyaf.id/profile jika diizinkan di next.config.js
                alt={`Foto profil ${AUTHOR.name}`}
                fill
                sizes="64px"
                className="object-cover object-center"
                priority={false}
              />
            </div>

            {/* INFO TEKS */}
            <div className="flex-1 min-w-0 text-center sm:text-left">
              <p className="text-sm text-muted mb-1">Dirancang dan dikembangkan oleh</p>
              <p className="text-lg font-semibold text-foreground">{AUTHOR.name}</p>
              {/* Anda bisa menambahkan role/title di sini jika ada */}
              {/* <p className="text-xs text-accent font-medium mt-0.5">Security Researcher & Developer</p> */}
            </div>

            {/* TOMBOL LINK */}
            <div className="flex flex-wrap items-center justify-center sm:justify-end gap-2 shrink-0">
              <a
                href={AUTHOR.websiteUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 h-10 px-4 rounded-xl text-sm text-soft border border-border hover:bg-foreground/5 hover:text-foreground transition-colors"
              >
                <Globe className="w-4 h-4" aria-hidden /> {AUTHOR.website}
              </a>
              <a
                href={AUTHOR.instagramUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 h-10 px-4 rounded-xl text-sm text-soft border border-border hover:bg-foreground/5 hover:text-foreground transition-colors"
              >
                <AtSign className="w-4 h-4" aria-hidden /> {AUTHOR.instagramHandle}
              </a>
            </div>

          </div>
        </section>
      </main>

      <footer className="px-4 sm:px-6 lg:px-8 pb-10">
        <div className="max-w-6xl mx-auto border-t border-border pt-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-sm text-muted">
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