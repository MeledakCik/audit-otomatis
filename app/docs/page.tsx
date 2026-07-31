"use client";

import { useEffect, useRef, useState } from "react";
import Link from "next/link";
import { cn } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";

interface Section {
  id: string;
  label: string;
}

const SECTIONS: Section[] = [
  { id: "introduction", label: "Introduction" },
  { id: "quick-start", label: "Quick Start" },
  { id: "crawler", label: "Crawler" },
  { id: "redis-schema", label: "Redis Schema" },
  { id: "scoring-system", label: "Scoring System" },
  { id: "deployment", label: "Deployment" },
];

function CodeBlock({ children }: { children: string }) {
  return (
    <pre className="rounded-lg border border-[#333] bg-black px-4 py-3.5 overflow-x-auto text-[12.5px] leading-relaxed">
      <code className="font-mono text-[#00FF88] whitespace-pre">{children}</code>
    </pre>
  );
}

function Prose({ children }: { children: React.ReactNode }) {
  return <div className="space-y-3 text-sm text-muted leading-relaxed">{children}</div>;
}

function SectionHeading({ children }: { children: React.ReactNode }) {
  return <h2 className="text-lg font-bold text-foreground tracking-tight mb-3">{children}</h2>;
}

const STEPS = [
  {
    n: 1,
    title: "Passive Security Scan",
    body: "Dari halaman Overview, masukkan domain/URL target lalu centang konfirmasi kepemilikan/izin. Ini men-trigger startScanAction (Server Action, bukan endpoint REST) yang membuat scan ID lalu jalan di background.",
  },
  {
    n: 2,
    title: "QC Otomatis (SEO / Performance / Content)",
    body: "Di /qc, pilih modul yang mau dijalankan lalu submit. Ini memanggil POST /api/qc/scan yang mengembalikan qcId, dan progres bisa diikuti lewat GET /api/qc/[id]/stream (SSE).",
  },
  {
    n: 3,
    title: "Inspeksi Request Mentah",
    body: "Buka /requests untuk lihat semua scan yang pernah jalan, lalu masuk ke /requests/[id] untuk lihat header, preview HTML, dan cURL tiap request yang dilakukan crawler.",
  },
  {
    n: 4,
    title: "Baca Laporan",
    body: "Findings keamanan (severity, endpoint, evidence) ada di /scan/[id], sedangkan ringkasan semua scan + severity breakdown ada di /history.",
  },
];

export default function DocsPage() {
  const [active, setActive] = useState<string>(SECTIONS[0].id);
  const observerRef = useRef<IntersectionObserver | null>(null);

  useEffect(() => {
    observerRef.current = new IntersectionObserver(
      (entries) => {
        for (const entry of entries) {
          if (entry.isIntersecting) {
            setActive(entry.target.id);
            break;
          }
        }
      },
      { rootMargin: "-15% 0px -70% 0px", threshold: 0 }
    );

    for (const s of SECTIONS) {
      const el = document.getElementById(s.id);
      if (el) observerRef.current!.observe(el);
    }

    return () => observerRef.current?.disconnect();
  }, []);

  return (
    <div className="w-full min-h-full">
      <div className="mx-auto max-w-6xl px-6 lg:px-8 py-10">
        {/* Breadcrumb */}
        <div className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-widest text-muted-dim mb-3">
          <span>Resources</span>
          <span className="text-border-strong">/</span>
          <span className="text-accent-2">Documentation</span>
        </div>

        <h1 className="text-2xl lg:text-3xl font-extrabold tracking-tight text-foreground mb-8">
          Documentation
        </h1>

        <div className="flex gap-10">
          {/* Main content */}
          <div className="min-w-0 flex-1 space-y-10">
            <section id="introduction" className="scroll-mt-24">
              <SectionHeading>Introduction</SectionHeading>
              <Prose>
                <p>
                  <strong className="text-foreground">TROUT (AUTO-SEC-AUDITOR)</strong> adalah audit
                  otomatis pasif untuk website: dia meng-crawl domain target dengan permintaan GET
                  layaknya browser biasa (tidak ada exploit, brute force, atau serangan aktif),
                  lalu menganalisis hasil crawl untuk tiga hal:
                </p>
                <ul className="list-disc pl-5 space-y-1">
                  <li>
                    <strong className="text-foreground">Security findings</strong> — header keamanan
                    yang hilang, endpoint/form yang terekspos, library JS usang, dsb.
                  </li>
                  <li>
                    <strong className="text-foreground">QC Otomatis</strong> — skor SEO, Performance
                    (via PageSpeed Insights), dan Content/Link (broken link, aksesibilitas dasar).
                  </li>
                  <li>
                    <strong className="text-foreground">Request Inspector</strong> — data mentah tiap
                    request yang dikirim crawler (header, body preview, ukuran, status).
                  </li>
                </ul>
                <p>
                  Karena sifatnya pasif dan read-only, TROUT dimaksudkan untuk domain milik sendiri
                  atau yang sudah diberi izin tertulis — bukan pentest aktif.
                </p>
              </Prose>
            </section>

            <section id="quick-start" className="scroll-mt-24">
              <SectionHeading>Quick Start</SectionHeading>
              <Prose>
                <p>Alur pemakaian dari nol sampai dapat laporan lengkap:</p>
              </Prose>
              <div className="mt-4 space-y-3">
                {STEPS.map((s) => (
                  <Card key={s.n}>
                    <CardContent className="p-4 flex gap-4">
                      <span className="shrink-0 h-7 w-7 rounded-full border border-accent-2/50 text-accent-2 grid place-items-center text-xs font-bold font-mono">
                        {s.n}
                      </span>
                      <div className="space-y-1">
                        <div className="text-sm font-bold text-foreground">{s.title}</div>
                        <div className="text-xs text-muted leading-relaxed">{s.body}</div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            </section>

            <section id="crawler" className="scroll-mt-24">
              <SectionHeading>Crawler</SectionHeading>
              <Prose>
                <p>
                  Mesin crawl-nya terbagi dua file: <code className="text-accent-2">lib/crawler.ts</code>{" "}
                  (fetch dengan header ala Chrome asli, deteksi Cloudflare challenge, parsing HTML
                  via cheerio/linkedom) dan <code className="text-accent-2">lib/site-crawler.ts</code>{" "}
                  (loop BFS antar halaman, maksimal 50 halaman unik / <code className="text-accent-2">MAX_CRAWL_URLS</code>,
                  kedalaman default 3 level).
                </p>
                <p>
                  Total request HTTP per crawl dibatasi oleh{" "}
                  <code className="text-accent-2">RequestBudget</code> di{" "}
                  <code className="text-accent-2">lib/rate-limit.ts</code> — default{" "}
                  <strong className="text-foreground">maksimal 100 request</strong>, dengan jeda 500ms
                  antar request untuk Passive Scan (300ms untuk QC) supaya tidak membebani server
                  target.
                </p>
              </Prose>
              <div className="mt-3">
                <CodeBlock>{`// lib/rate-limit.ts
export class RequestBudget {
  constructor(private readonly max = 100, private readonly delayMs = 500) {}
  canSpend(n = 1): boolean { return this.used + n <= this.max; }
}

// dipakai di lib/scan-runner.ts
const budget = new RequestBudget(100, 500);`}</CodeBlock>
              </div>
            </section>

            <section id="redis-schema" className="scroll-mt-24">
              <SectionHeading>Redis Schema</SectionHeading>
              <Prose>
                <p>
                  Semua akses Redis wajib lewat <code className="text-accent-2">lib/redis.ts</code>{" "}
                  — <code className="text-accent-2">getKv()</code> otomatis pilih Upstash (REST) atau
                  node-redis (TCP) tergantung env yang tersedia, plus fallback in-memory kalau
                  keduanya kosong (dev lokal tanpa Redis).
                </p>
              </Prose>
              <div className="mt-3">
                <CodeBlock>{`import { getKv } from "@/lib/redis";
const kv = getKv();

// Passive Security Scan
trout:scan:{id}:meta   // ScanState tanpa logs (domain, status, findings, pages[], ...)
trout:scan:{id}:logs   // list ScanLogEvent (rpushJSON, dipakai stream SSE)

// QC Otomatis
trout:qc:{id}:meta            // QcState tanpa logs
trout:qc:{id}:logs            // list QcLogEvent
trout:qc:{id}:result:{module} // hasil per-modul: seo | perf | content

// Cooldown / rate limit
trout:cooldown:{userKey}:{hostname}

kv.getJSON(key) / kv.setJSON(key, val, ttl) / kv.keys(pattern)`}</CodeBlock>
              </div>
            </section>

            <section id="scoring-system" className="scroll-mt-24">
              <SectionHeading>Scoring System</SectionHeading>
              <Prose>
                <p>QC Otomatis punya 3 modul independen, masing-masing menghasilkan skor 0–100:</p>
                <ul className="list-disc pl-5 space-y-1">
                  <li>
                    <strong className="text-foreground">SEO</strong> —{" "}
                    <code className="text-accent-2">lib/qc-seo.ts</code>: title/meta description,
                    heading structure, alt text gambar, canonical, dsb.
                  </li>
                  <li>
                    <strong className="text-foreground">Performance</strong> —{" "}
                    <code className="text-accent-2">lib/qc-performance.ts</code>: Google PageSpeed
                    Insights (butuh <code className="text-accent-2">GOOGLE_PAGESPEED_API_KEY</code>),
                    dengan fallback estimasi dari ukuran HTML kalau API tidak tersedia.
                  </li>
                  <li>
                    <strong className="text-foreground">Content / Link</strong> —{" "}
                    <code className="text-accent-2">lib/qc-content.ts</code>: broken link (dari
                    request budget yang sama), aksesibilitas dasar.
                  </li>
                </ul>
                <p>
                  Skor akhir yang ditampilkan di dashboard adalah rata-rata dari modul yang
                  dijalankan (skip modul yang tidak dipilih).
                </p>
              </Prose>
            </section>

            <section id="deployment" className="scroll-mt-24">
              <SectionHeading>Deployment</SectionHeading>
              <Prose>
                <p>Environment variables yang dipakai (lihat <code className="text-accent-2">.env.example</code>):</p>
              </Prose>
              <div className="mt-3">
                <CodeBlock>{`# Wajib salah satu — Upstash direkomendasikan untuk Vercel
UPSTASH_REDIS_REST_URL=...
UPSTASH_REDIS_REST_TOKEN=...

# Alternatif: Redis TCP biasa (dev lokal / self-host)
REDIS_URL=redis://...

# Opsional — kalau kosong, modul Performance pakai estimasi fallback
GOOGLE_PAGESPEED_API_KEY=...`}</CodeBlock>
              </div>
              <Prose>
                <p className="pt-2">
                  Tanpa Redis sama sekali, app tetap jalan pakai in-memory store (cocok untuk demo
                  lokal singkat) — tapi data hilang tiap restart server dan tidak ke-share antar
                  serverless instance di production.
                </p>
              </Prose>
            </section>
          </div>

          {/* Right TOC */}
          <aside className="hidden xl:block w-52 shrink-0">
            <div className="sticky top-24 space-y-3">
              <div className="text-[10px] font-mono uppercase tracking-widest text-muted-dim px-1">
                On This Page
              </div>
              <nav className="space-y-0.5">
                {SECTIONS.map((s) => (
                  <Link
                    key={s.id}
                    href={`#${s.id}`}
                    className={cn(
                      "block px-3 py-1.5 rounded-md text-xs font-mono border-l-2 transition-colors",
                      active === s.id
                        ? "border-accent-2 text-accent-2 bg-accent-2/5"
                        : "border-transparent text-muted-dim hover:text-muted"
                    )}
                  >
                    {s.label}
                  </Link>
                ))}
              </nav>
            </div>
          </aside>
        </div>
      </div>
    </div>
  );
}
