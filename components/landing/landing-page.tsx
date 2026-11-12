import Link from "next/link";
import {
  ArrowRight, ShieldCheck, Radar, Lock, TrendingUp, Network, ClipboardCheck, Check,
} from "lucide-react";
import { GlassCanvas } from "@/components/landing/glass-canvas";
import { LandingNav } from "@/components/landing/landing-nav";

const FEATURES = [
  { icon: ShieldCheck, title: "Audit pasif", desc: "GET/HEAD saja, maks 100 request" },
  { icon: Radar, title: "8 engine runtime", desc: "Deteksi eksposur tanpa eksploit" },
  { icon: Lock, title: "Brankas AES-256", desc: "Temuan sensitif terenkripsi" },
  { icon: TrendingUp, title: "SEO Master", desc: "35+ sinyal Google & hreflang" },
  { icon: Network, title: "Peta serangan", desc: "Graf halaman, JS, dan endpoint" },
  { icon: ClipboardCheck, title: "QC otomatis", desc: "SEO, performa, broken link" },
];

const STEPS = ["Masukkan domain", "Crawl pasif", "Lihat temuan", "Klaim bukti"];
const TRUST = ["Tanpa login", "GET-only", "Zero-exploit"];

const cta =
  "inline-flex items-center gap-2 px-6 py-3.5 rounded-xl text-base font-semibold text-white bg-gradient-accent hover:brightness-110 transition";

export function LandingPage() {
  return (
    <div className="relative min-h-dvh overflow-x-clip">
      <LandingNav />

      <main id="main">
        {/* HERO */}
        <section className="relative isolate min-h-[100svh] flex items-center pt-28 pb-16 px-4 sm:px-6">
          <GlassCanvas className="absolute inset-0 -z-10 w-full h-full opacity-80" />
          <div aria-hidden className="absolute inset-x-0 bottom-0 h-40 -z-10 bg-gradient-to-t from-background to-transparent" />

          <div className="max-w-6xl mx-auto w-full grid grid-cols-1 lg:grid-cols-12 gap-10 items-center">
            <div className="lg:col-span-7 space-y-6">
              <h1 className="text-4xl sm:text-5xl xl:text-6xl font-extrabold tracking-tight leading-[1.08] text-balance animate-fade-up">
                Audit keamanan web.{" "}
                <span className="text-gradient-accent">Pasif, tanpa login.</span>
              </h1>
              <p className="text-lg text-soft max-w-md animate-fade-up" style={{ animationDelay: "70ms" }}>
                Masukkan domain, dapatkan temuan dalam hitungan menit.
              </p>

              <div className="flex flex-wrap gap-3 animate-fade-up" style={{ animationDelay: "140ms" }}>
                <Link href="/dashboard" className={cta}>
                  Masuk ke Dashboard <ArrowRight className="w-5 h-5" />
                </Link>
                <a href="#fitur" className="inline-flex items-center px-6 py-3.5 rounded-xl text-base font-semibold glass-pill hover:border-accent/40">
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

            {/* Pratinjau ilustrasi */}
            <div className="lg:col-span-5 animate-fade-up" style={{ animationDelay: "160ms" }}>
              <div className="glass-panel rounded-3xl p-5 sm:p-6 space-y-4">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-base font-semibold truncate">contoh-domain.id</span>
                  <span className="text-xs text-muted shrink-0">ilustrasi</span>
                </div>
                <ul className="space-y-2.5 text-sm">
                  <li className="flex items-center gap-2.5"><Check className="w-4 h-4 text-ok shrink-0" /> Header keamanan lengkap</li>
                  <li className="flex items-center gap-2.5"><Check className="w-4 h-4 text-ok shrink-0" /> Tidak ada file sensitif terbuka</li>
                  <li className="flex items-center gap-2.5"><span className="w-4 text-center text-warn font-bold shrink-0">!</span> CSP memuat unsafe-inline</li>
                </ul>
                <div className="grid grid-cols-3 gap-2 text-center">
                  {[["0", "Critical"], ["2", "Medium"], ["4", "Low"]].map(([v, l]) => (
                    <div key={l} className="rounded-xl bg-foreground/[0.04] py-2.5">
                      <div className="text-xl font-bold">{v}</div>
                      <div className="text-xs text-muted">{l}</div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        </section>

        {/* FITUR */}
        <section id="fitur" className="px-4 sm:px-6 py-14 sm:py-20">
          <div className="max-w-6xl mx-auto space-y-8">
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight">Fitur utama</h2>
            <ul className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
              {FEATURES.map(({ icon: Icon, title, desc }) => (
                <li key={title} className="glass-panel rounded-2xl p-5 flex items-start gap-4 hover:border-accent/40 hover:-translate-y-0.5">
                  <span className="w-11 h-11 rounded-xl bg-accent/10 text-accent flex items-center justify-center shrink-0">
                    <Icon className="w-5 h-5" />
                  </span>
                  <div className="min-w-0">
                    <h3 className="text-base font-semibold">{title}</h3>
                    <p className="text-sm text-muted mt-0.5">{desc}</p>
                  </div>
                </li>
              ))}
            </ul>
          </div>
        </section>

        {/* CARA KERJA */}
        <section id="cara-kerja" className="px-4 sm:px-6 py-14 sm:py-20">
          <div className="max-w-6xl mx-auto space-y-8">
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight">Cara kerja</h2>
            <ol className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {STEPS.map((s, i) => (
                <li key={s} className="glass-panel rounded-2xl p-5 space-y-2">
                  <span className="text-sm font-mono font-semibold text-accent">{String(i + 1).padStart(2, "0")}</span>
                  <p className="text-base font-semibold">{s}</p>
                </li>
              ))}
            </ol>
          </div>
        </section>

        {/* CTA */}
        <section className="px-4 sm:px-6 pb-20">
          <div className="max-w-3xl mx-auto glass-panel rounded-3xl p-8 sm:p-12 text-center space-y-5">
            <h2 className="text-2xl sm:text-3xl font-bold tracking-tight text-balance">Siap memeriksa domain Anda?</h2>
            <Link href="/dashboard" className={cta}>
              Masuk ke Dashboard <ArrowRight className="w-5 h-5" />
            </Link>
          </div>
        </section>
      </main>

      <footer className="px-4 sm:px-6 pb-10">
        <div className="max-w-6xl mx-auto border-t border-border pt-6 flex flex-wrap items-center justify-between gap-3 text-sm text-muted">
          <span>© {new Date().getFullYear()} Sentinel-ID</span>
          <nav aria-label="Tautan footer" className="flex gap-4">
            <Link href="/docs" className="hover:text-foreground">Dokumentasi</Link>
            <Link href="/api-docs" className="hover:text-foreground">API</Link>
          </nav>
        </div>
      </footer>
    </div>
  );
}
