import Link from "next/link";
import {
  ArrowRight, ShieldCheck, Lock, TrendingUp, Radar, Network, ClipboardCheck,
  Globe, KeyRound, FileCode2, Check, Shield,
} from "lucide-react";
import { GlassCanvas } from "@/components/landing/glass-canvas";
import { LandingNav } from "@/components/landing/landing-nav";

const FEATURES = [
  { icon: ShieldCheck, title: "Audit 100% pasif", desc: "Hanya HTTP GET/HEAD dengan batas 100 request. Tanpa payload, tanpa brute-force, aman untuk server produksi." },
  { icon: Radar, title: "8 engine permukaan runtime", desc: "Deteksi pasif wp, php, node, go, py shell, WebShell, FileManager, dan out-of-bounds tanpa mengeksploitasi apa pun." },
  { icon: Lock, title: "Brankas AES-256-GCM", desc: "Temuan sensitif (.env, .git, kunci API) langsung disensor dari publik dan dienkripsi. Hanya pemilik domain yang dapat membukanya." },
  { icon: TrendingUp, title: "SEO Master", desc: "35+ sinyal Google SERP, 13 tag hreflang, JSON-LD Schema.org, dan Core Web Vitals dalam satu laporan." },
  { icon: Network, title: "Peta permukaan serangan", desc: "Graf interaktif hubungan halaman, bundle JavaScript, dan endpoint API yang ditemukan crawler." },
  { icon: ClipboardCheck, title: "QC otomatis", desc: "Audit kualitas SEO on-page, performa, dan broken link dengan skor yang mudah dibaca." },
];

const STEPS = [
  { n: "01", title: "Masukkan domain", desc: "Cukup domain milik Anda. Tidak perlu akun atau login." },
  { n: "02", title: "Crawl & analisis pasif", desc: "Maksimal 50 URL, hanya satu origin, tanpa mengirim payload." },
  { n: "03", title: "Lihat temuan", desc: "Setiap temuan diberi tingkat risiko dan langkah perbaikan." },
  { n: "04", title: "Klaim bukti", desc: "Verifikasi kepemilikan lewat DNS TXT atau file HTTP untuk membuka brankas." },
];

const TRUST = ["Tanpa login", "GET-only", "Zero-exploit", "Open audit log"];

const FAQ = [
  { q: "Apakah aman dipakai di server produksi?", a: "Ya. Sentinel-ID hanya mengirim permintaan baca (GET/HEAD), dibatasi 100 request per scan, dan dilengkapi SSRF guard. Tidak ada payload eksploitasi yang dikirim." },
  { q: "Perlu daftar atau login?", a: "Tidak. Tekan Masuk, isi domain, centang konfirmasi izin, lalu mulai audit. Area admin brankas dilindungi terpisah." },
  { q: "Bagaimana data sensitif ditangani?", a: "Isi file rahasia tidak pernah ditampilkan publik. Bukti dienkripsi AES-256-GCM dan hanya bisa dibuka pemilik domain yang lolos verifikasi." },
  { q: "Boleh memindai domain orang lain?", a: "Tidak. Gunakan hanya untuk domain milik sendiri atau yang Anda punya izin tertulis untuk mengauditnya." },
];

export function LandingPage() {
  return (
    <div className="relative min-h-dvh overflow-x-clip">
      <LandingNav />

      <main id="main">
        {/* ============================ HERO ============================ */}
        <section className="relative isolate min-h-[100svh] flex items-center pt-28 pb-16 px-4 sm:px-6">
          <GlassCanvas className="absolute inset-0 -z-10 w-full h-full" />
          {/* pudar di tepi bawah agar menyatu dengan section berikutnya */}
          <div aria-hidden className="absolute inset-x-0 bottom-0 h-40 -z-10 bg-gradient-to-t from-background to-transparent" />

          <div className="max-w-6xl mx-auto w-full grid grid-cols-1 lg:grid-cols-12 gap-8 lg:gap-10 items-center">
            <div className="lg:col-span-7 space-y-6">
              <span className="inline-flex items-center gap-2 px-3.5 py-1.5 rounded-full text-xs glass-pill animate-fade-up">
                <span className="w-2 h-2 rounded-full bg-ok animate-pulse" aria-hidden />
                <span className="font-mono font-semibold text-ok">GET-ONLY · ZERO-EXPLOIT · TANPA LOGIN</span>
              </span>

              <h1
                className="text-4xl sm:text-5xl xl:text-6xl font-extrabold tracking-tight leading-[1.05] text-balance animate-fade-up"
                style={{ animationDelay: "60ms" }}
              >
                Audit keamanan web,{" "}
                <span className="text-gradient-accent">jernih dan tanpa risiko.</span>
              </h1>

              <p
                className="text-base sm:text-lg leading-relaxed text-soft max-w-xl animate-fade-up"
                style={{ animationDelay: "120ms" }}
              >
                Periksa postur keamanan dan kesiapan SEO domain Anda tanpa mengirim payload apa pun.
                Cukup masukkan domain, tidak perlu akun.
              </p>

              <div className="flex flex-wrap gap-3 animate-fade-up" style={{ animationDelay: "180ms" }}>
                <Link
                  href="/dashboard"
                  className="inline-flex items-center gap-2 px-6 py-3.5 rounded-xl text-base font-semibold text-white bg-gradient-accent hover:brightness-110 transition shadow-lg shadow-pink-500/20"
                >
                  Masuk ke Dashboard <ArrowRight className="w-5 h-5" />
                </Link>
                <a
                  href="#fitur"
                  className="inline-flex items-center gap-2 px-6 py-3.5 rounded-xl text-base font-semibold glass-pill hover:bg-foreground/5 transition"
                >
                  Lihat fitur
                </a>
              </div>

              <ul className="flex flex-wrap gap-x-5 gap-y-2 text-sm text-muted animate-fade-up" style={{ animationDelay: "240ms" }}>
                {TRUST.map((t) => (
                  <li key={t} className="inline-flex items-center gap-1.5">
                    <Check className="w-4 h-4 text-ok" aria-hidden /> {t}
                  </li>
                ))}
              </ul>
            </div>

            {/* Kartu kaca: pratinjau ilustrasi (statis, tanpa JS) */}
            <div className="lg:col-span-5 animate-fade-up" style={{ animationDelay: "200ms" }}>
              <div className="glass-panel rounded-3xl p-5 sm:p-6 space-y-4">
                <div className="flex items-center gap-3">
                  <span className="w-11 h-11 rounded-2xl bg-gradient-accent flex items-center justify-center text-white shrink-0">
                    <Shield className="w-6 h-6" />
                  </span>
                  <div className="min-w-0">
                    <div className="text-xs font-mono uppercase tracking-widest text-ok font-semibold">Pratinjau ilustrasi</div>
                    <div className="text-base font-bold truncate">contoh-domain.id</div>
                  </div>
                </div>
                <div className="rounded-2xl bg-sunken/70 border border-border p-4 font-mono text-xs leading-relaxed space-y-1.5 overflow-hidden">
                  <p className="text-muted">$ sentinel --passive contoh-domain.id</p>
                  <p><span className="text-ok">✓</span> crawl: 38 URL, 11 bundle JS</p>
                  <p><span className="text-ok">✓</span> headers: HSTS, XFO, nosniff</p>
                  <p><span className="text-warn">!</span> CSP memuat unsafe-inline</p>
                  <p><span className="text-ok">✓</span> vault: 0 file sensitif terbuka</p>
                  <p className="text-muted">request: 29/100 · mode GET-only</p>
                </div>
                <div className="grid grid-cols-3 gap-2 text-center">
                  {[["0", "Critical"], ["2", "Medium"], ["4", "Low"]].map(([v, l]) => (
                    <div key={l} className="rounded-xl bg-sunken/70 border border-border py-2.5">
                      <div className="text-lg font-bold">{v}</div>
                      <div className="text-xs text-muted">{l}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* ============================ FITUR ============================ */}
        <section id="fitur" className="px-4 sm:px-6 py-16 sm:py-20">
          <div className="max-w-6xl mx-auto space-y-8">
            <div className="max-w-2xl space-y-2">
              <span className="text-xs font-mono uppercase tracking-widest text-accent font-semibold">Fitur</span>
              <h2 className="text-2xl sm:text-4xl font-bold tracking-tight text-balance">
                Satu alat untuk keamanan, SEO, dan kualitas situs
              </h2>
            </div>
            <ul className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {FEATURES.map(({ icon: Icon, title, desc }) => (
                <li key={title} className="glass-panel rounded-2xl p-5 space-y-3 transition hover:-translate-y-0.5 hover:border-accent/40">
                  <span className="w-11 h-11 rounded-xl bg-accent/10 text-accent flex items-center justify-center">
                    <Icon className="w-5 h-5" />
                  </span>
                  <h3 className="text-base font-bold">{title}</h3>
                  <p className="text-sm leading-relaxed text-muted">{desc}</p>
                </li>
              ))}
            </ul>
            <p className="text-sm text-muted flex flex-wrap items-center gap-x-4 gap-y-1">
              <span className="inline-flex items-center gap-1.5"><Globe className="w-4 h-4" /> DNS & subdomain</span>
              <span className="inline-flex items-center gap-1.5"><KeyRound className="w-4 h-4" /> Secret hunter</span>
              <span className="inline-flex items-center gap-1.5"><FileCode2 className="w-4 h-4" /> JS supply chain</span>
              <span>dan 22 modul lainnya di dashboard.</span>
            </p>
          </div>
        </section>

        {/* ========================== CARA KERJA ========================== */}
        <section id="cara-kerja" className="px-4 sm:px-6 py-16 sm:py-20">
          <div className="max-w-6xl mx-auto space-y-8">
            <div className="max-w-2xl space-y-2">
              <span className="text-xs font-mono uppercase tracking-widest text-ok font-semibold">Cara kerja</span>
              <h2 className="text-2xl sm:text-4xl font-bold tracking-tight text-balance">Empat langkah, tanpa daftar</h2>
            </div>
            <ol className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              {STEPS.map((s) => (
                <li key={s.n} className="glass-panel rounded-2xl p-5 space-y-2">
                  <span className="text-sm font-mono font-bold text-accent">{s.n}</span>
                  <h3 className="text-base font-bold">{s.title}</h3>
                  <p className="text-sm leading-relaxed text-muted">{s.desc}</p>
                </li>
              ))}
            </ol>
          </div>
        </section>

        {/* ============================== FAQ ============================== */}
        <section id="faq" className="px-4 sm:px-6 py-16 sm:py-20">
          <div className="max-w-3xl mx-auto space-y-6">
            <h2 className="text-2xl sm:text-4xl font-bold tracking-tight text-balance">Pertanyaan umum</h2>
            <div className="space-y-3">
              {FAQ.map((f) => (
                <details key={f.q} className="group glass-panel rounded-2xl p-4 sm:p-5">
                  <summary className="cursor-pointer list-none flex items-center justify-between gap-3 text-base font-semibold">
                    {f.q}
                    <span aria-hidden className="text-accent transition group-open:rotate-45 text-xl leading-none">+</span>
                  </summary>
                  <p className="mt-3 pt-3 border-t border-border text-sm leading-relaxed text-muted">{f.a}</p>
                </details>
              ))}
            </div>
          </div>
        </section>

        {/* ============================== CTA ============================== */}
        <section className="px-4 sm:px-6 pb-20">
          <div className="max-w-4xl mx-auto glass-panel rounded-3xl p-8 sm:p-12 text-center space-y-5">
            <h2 className="text-2xl sm:text-4xl font-bold tracking-tight text-balance">Siap memeriksa domain Anda?</h2>
            <p className="text-base text-soft max-w-xl mx-auto">Gratis, pasif, dan tanpa akun. Hasil pertama dalam beberapa menit.</p>
            <Link
              href="/dashboard"
              className="inline-flex items-center gap-2 px-7 py-3.5 rounded-xl text-base font-semibold text-white bg-gradient-accent hover:brightness-110 transition"
            >
              Masuk ke Dashboard <ArrowRight className="w-5 h-5" />
            </Link>
          </div>
        </section>
      </main>

      <footer className="px-4 sm:px-6 pb-10">
        <div className="max-w-6xl mx-auto border-t border-border pt-6 flex flex-wrap items-center justify-between gap-3 text-sm text-muted">
          <span>© {new Date().getFullYear()} Sentinel-ID · Passive-only security auditor</span>
          <nav aria-label="Tautan footer" className="flex gap-4">
            <Link href="/docs" className="hover:text-foreground">Dokumentasi</Link>
            <Link href="/api-docs" className="hover:text-foreground">API</Link>
            <Link href="/dashboard" className="hover:text-foreground">Dashboard</Link>
          </nav>
        </div>
      </footer>
    </div>
  );
}
