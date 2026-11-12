import Link from "next/link";
import {
  ArrowRight, ShieldCheck, Radar, Lock, TrendingUp, Network, ClipboardCheck,
  Check, Globe, AtSign, EyeOff, ServerCog, FileCheck2,
} from "lucide-react";
import { GlassCanvas } from "@/components/landing/glass-canvas";
import { LandingNav } from "@/components/landing/landing-nav";
import { AUTHOR } from "@/lib/author";

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
  { title: "Masukkan domain", desc: "Satu domain, tanpa login, tanpa verifikasi kepemilikan." },
  { title: "Crawl pasif", desc: "Mesin menjelajah halaman publik dan memetakan permukaan serangan." },
  { title: "Lihat temuan", desc: "Daftar temuan terprioritas lengkap dengan bukti dan tingkat keparahan." },
  { title: "Klaim bukti", desc: "Simpan bukti terenkripsi dan bagikan laporan ke tim atau klien." },
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
  "inline-flex items-center justify-center gap-2 px-6 py-3.5 rounded-xl text-base font-semibold text-white bg-gradient-accent hover:brightness-110 transition";

export function LandingPage() {
  return (
    <div className="relative min-h-dvh overflow-x-clip">
      <LandingNav />

      <main id="main">
        {/* ===== HERO ===== */}
        <section className="relative isolate min-h-[100svh] flex items-center pt-28 pb-16 px-4 sm:px-6">
          <GlassCanvas className="absolute inset-0 -z-10 w-full h-full opacity-80" />
          <div
            aria-hidden
            className="absolute inset-x-0 bottom-0 h-40 -z-10 bg-gradient-to-t from-background to-transparent"
          />

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

              <p
                className="text-lg text-soft max-w-xl animate-fade-up"
                style={{ animationDelay: "70ms" }}
              >
                Masukkan domain, dapatkan temuan terprioritas lengkap dengan bukti — tanpa
                eksploit, tanpa login, dan tanpa mengubah apa pun pada target.
              </p>

              <div
                className="flex flex-wrap gap-3 animate-fade-up"
                style={{ animationDelay: "140ms" }}
              >
                <Link href="/dashboard" className={cta}>
                  Mulai audit sekarang <ArrowRight className="w-5 h-5" aria-hidden />
                </Link>
                <a
                  href="#fitur"
                  className="inline-flex items-center px-6 py-3.5 rounded-xl text-base font-semibold glass-pill hover:border-accent/40 transition"
                >
                  Lihat fitur
                </a>
              </div>

              <ul
                className="flex flex-wrap gap-x-5 gap-y-2 text-sm text-muted animate-fade-up"
                style={{ animationDelay: "200ms" }}
              >
                {TRUST.map((t) => (
                  <li key={t} className="inline-flex items-center gap-1.5">
                    <Check className="w-4 h-4 text-ok" aria-hidden /> {t}
                  </li>
                ))}
              </ul>
            </div>

            {/* Kanan: preview dashboard */}
            <div
              className="lg:col-span-5 animate-fade-up"
              style={{ animationDelay: "160ms" }}
            >
              <div className="glass-panel rounded-3xl p-5 sm:p-6 space-y-5">
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
                    <span className="w-4 text-center text-warn font-bold shrink-0 mt-0.5" aria-hidden>
                      !
                    </span>
                    <span>CSP masih memuat <code className="text-xs">unsafe-inline</code></span>
                  </li>
                </ul>

                <div className="grid grid-cols-3 gap-2 text-center">
                  {[
                    ["0", "Critical"],
                    ["2", "Medium"],
                    ["4", "Low"],
                  ].map(([v, l]) => (
                    <div key={l} className="rounded-xl bg-foreground/[0.04] py-3">
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
        <section className="px-4 sm:px-6 pb-6">
          <div className="max-w-6xl mx-auto grid grid-cols-2 md:grid-cols-4 gap-3">
            {STATS.map((s) => (
              <div key={s.label} className="glass-panel rounded-2xl px-5 py-4 text-center">
                <div className="text-2xl font-bold tabular-nums text-gradient-accent">
                  {s.value}
                </div>
                <div className="text-xs text-muted mt-0.5">{s.label}</div>
              </div>
            ))}
          </div>
        </section>

        {/* ===== FITUR ===== */}
        <section id="fitur" className="px-4 sm:px-6 py-14 sm:py-20">
          <div className="max-w-6xl mx-auto space-y-8">
            <header className="space-y-2 max-w-2xl">
              <h2 className="text-2xl sm:text-3xl font-bold tracking-tight">Fitur utama</h2>
              <p className="text-soft">
                Semua yang Anda butuhkan untuk memahami risiko keamanan dan kualitas teknis
                sebuah domain — dalam satu dashboard.
              </p>
            </header>

            <ul className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {FEATURES.map(({ icon: Icon, title, desc }) => (
                <li
                  key={title}
                  className="glass-panel rounded-2xl p-5 flex items-start gap-4 hover:border-accent/40 hover:-translate-y-0.5 transition"
                >
                  <span className="w-11 h-11 rounded-xl bg-accent/10 text-accent flex items-center justify-center shrink-0">
                    <Icon className="w-5 h-5" aria-hidden />
                  </span>
                  <div className="min-w-0">
                    <h3 className="text-base font-semibold">{title}</h3>
                    <p className="text-sm text-muted mt-1 leading-relaxed">{desc}</p>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </section>

        {/* ===== PRINSIP KEAMANAN ===== */}
        <section id="keamanan" className="px-4 sm:px-6 py-14 sm:py-20">
          <div className="max-w-6xl mx-auto space-y-8">
            <header className="space-y-2 max-w-2xl">
              <h2 className="text-2xl sm:text-3xl font-bold tracking-tight">
                Kenapa audit pasif?
              </h2>
              <p className="text-soft">
                Keamanan tidak harus invasif. Kami merancang setiap pemeriksaan agar aman
                bagi target dan dapat dipertanggungjawabkan hasilnya.
              </p>
            </header>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {PRINCIPLES.map(({ icon: Icon, title, desc }) => (
                <div key={title} className="glass-panel rounded-2xl p-6 space-y-3">
                  <span className="w-10 h-10 rounded-xl bg-accent/10 text-accent flex items-center justify-center">
                    <Icon className="w-5 h-5" aria-hidden />
                  </span>
                  <h3 className="text-base font-semibold">{title}</h3>
                  <p className="text-sm text-muted leading-relaxed">{desc}</p>
                </div>
              ))}
            </div>
          </div>
        </section>

        {/* ===== CARA KERJA ===== */}
        <section id="cara-kerja" className="px-4 sm:px-6 py-14 sm:py-20">
          <div className="max-w-6xl mx-auto space-y-8">
            <header className="space-y-2 max-w-2xl">
              <h2 className="text-2xl sm:text-3xl font-bold tracking-tight">Cara kerja</h2>
              <p className="text-soft">Empat langkah, tanpa setup rumit.</p>
            </header>

            <ol className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {STEPS.map((s, i) => (
                <li key={s.title} className="glass-panel rounded-2xl p-5 space-y-2">
                  <span className="text-sm font-mono font-semibold text-accent">
                    {String(i + 1).padStart(2, "0")}
                  </span>
                  <p className="text-base font-semibold">{s.title}</p>
                  <p className="text-sm text-muted leading-relaxed">{s.desc}</p>
                </li>
              ))}
            </ol>
          </div>
        </section>

        {/* ===== CTA ===== */}
        <section className="px-4 sm:px-6 pb-20">
          <div className="max-w-3xl mx-auto glass-panel rounded-3xl p-8 sm:p-12 text-center space-y-5">
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-balance">
              Siap memeriksa domain Anda?
            </h2>
            <p className="text-soft max-w-md mx-auto">
              Mulai audit pertama Anda dalam hitungan detik. Tidak perlu kartu kredit, tidak
              perlu login.
            </p>
            <Link href="/dashboard" className={cta}>
              Mulai audit sekarang <ArrowRight className="w-5 h-5" aria-hidden />
            </Link>
          </div>
        </section>

        {/* ===== AUTHOR ===== */}
        <section id="author" className="px-4 sm:px-6 pb-14">
          <div className="max-w-3xl mx-auto glass-panel rounded-3xl p-6 sm:p-8 flex flex-col sm:flex-row sm:items-center gap-5">
            <span className="w-14 h-14 rounded-full bg-gradient-accent flex items-center justify-center text-white text-xl font-bold shrink-0">
              K
            </span>
            <div className="flex-1 min-w-0">
              <p className="text-sm text-muted">Dibuat dan dikelola oleh</p>
              <p className="text-xl font-bold">{AUTHOR.name}</p>
            </div>
            <div className="flex flex-wrap gap-2.5">
              <a
                href={AUTHOR.websiteUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium glass-pill hover:border-accent/40 transition"
              >
                <Globe className="w-4 h-4 text-accent" aria-hidden /> {AUTHOR.website}
              </a>
              <a
                href={AUTHOR.instagramUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-2 px-4 py-2.5 rounded-xl text-sm font-medium glass-pill hover:border-accent/40 transition"
              >
                <AtSign className="w-4 h-4 text-accent" aria-hidden /> {AUTHOR.instagramHandle}
              </a>
            </div>
          </div>
        </section>
      </main>

      <footer className="px-4 sm:px-6 pb-10">
        <div className="max-w-6xl mx-auto border-t border-border pt-6 flex flex-wrap items-center justify-between gap-3 text-sm text-muted">
          <span>
            © {new Date().getFullYear()} Sentinel-ID · oleh{" "}
            <a
              href={AUTHOR.websiteUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="hover:text-foreground underline-offset-4 hover:underline"
            >
              {AUTHOR.name}
            </a>
          </span>
          <nav aria-label="Tautan footer" className="flex gap-4">
            <Link href="/docs" className="hover:text-foreground">
              Dokumentasi
            </Link>
            <Link href="/api-docs" className="hover:text-foreground">
              API
            </Link>
          </nav>
        </div>
      </footer>
    </div>
  );
}