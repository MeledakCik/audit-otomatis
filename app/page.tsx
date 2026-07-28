import { ScanForm } from "@/components/scan-form";
import { Search, Code2, ShieldCheck, FileText } from "lucide-react";
export const maxDuration = 300;

export default function Home() {
  return (
    <div className="w-full min-h-full">
      <div className="mx-auto max-w-6xl px-6 lg:px-8 py-10">

        <div className="grid grid-cols-1 lg:grid-cols-[1.15fr_0.85fr] gap-10 items-start">
   
          <div className="pt-2 space-y-6">
            <div className="inline-flex items-center px-3 py-1 rounded-md bg-purple-500/10 border border-purple-500/20 text-xs font-mono tracking-[0.2em] uppercase text-purple-400">
              $ AUDIT --DOMAIN
            </div>

            <div className="space-y-3">
              <h1 className="text-3xl lg:text-5xl font-extrabold leading-[1.1] tracking-tight text-white">
                Passive Security <br />
                <span className="text-transparent bg-clip-text bg-gradient-to-r from-purple-400 to-pink-400">
                  Audit
                </span>
              </h1>
              <p className="text-sm leading-relaxed text-slate-400 max-w-xl">
                Analyze your domain&apos;s security posture instantly. We crawl
                assets and analyze JS bundles without intrusive exploits.
              </p>
            </div>

            <div className="flex flex-wrap gap-2 pt-1">
              <div className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.02] px-3 py-1 text-xs text-slate-300 font-mono">
                <Search className="h-3 w-3 text-purple-400" /> Crawl
              </div>
              <div className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.02] px-3 py-1 text-xs text-slate-300 font-mono">
                <Code2 className="h-3 w-3 text-purple-400" /> JS Analyzer
              </div>
              <div className="inline-flex items-center gap-1.5 rounded-full border border-white/10 bg-white/[0.02] px-3 py-1 text-xs text-slate-300 font-mono">
                <ShieldCheck className="h-3 w-3 text-purple-400" /> Headers
              </div>
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 bg-[#130f1d] p-6 shadow-xl shadow-purple-950/20">
            <div className="mb-4">
              <div className="text-xs font-mono tracking-widest uppercase text-purple-300/80 font-semibold">
                Target Domain
              </div>
            </div>
            <ScanForm />
          </div>
        </div>

        <div className="my-10 border-t border-white/[0.06]" />

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            {
              n: "01",
              t: "Crawl",
              d: "link internal, script, form",
              icon: Search,
            },
            {
              n: "02",
              t: "JS Analyzer",
              d: "endpoint via acorn AST",
              icon: Code2,
            },
            {
              n: "03",
              t: "Passive Test",
              d: "leakage · headers · exposed",
              icon: ShieldCheck,
            },
            {
              n: "04",
              t: "Report",
              d: "export markdown Obsidian",
              icon: FileText,
            },
          ].map((c) => (
            <div
              key={c.n}
              className="flex flex-col justify-between rounded-xl border border-white/[0.06] bg-[#120e1b] p-5 hover:bg-[#181324] hover:border-purple-500/30 transition-all group"
            >
              <div className="flex items-start justify-between">
                <span className="text-xs font-mono font-bold text-purple-400">
                  {c.n}
                </span>
                <c.icon className="h-4 w-4 text-slate-500 group-hover:text-purple-300 transition-colors" />
              </div>
              <div className="mt-4">
                <div className="text-sm font-semibold text-white">{c.t}</div>
                <div className="text-xs text-slate-400 mt-1 font-mono">
                  {c.d}
                </div>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-6 flex items-center gap-2 text-xs font-mono text-slate-400 bg-white/[0.02] border border-white/[0.04] p-3 rounded-lg">
          <span className="inline-block w-1.5 h-1.5 rounded-full bg-purple-400" />
          <span>
            Passive-only · Max 100 req/scan · 500ms delay · 1 scan / 5 menit
          </span>
        </div>
      </div>
    </div>
  );
}
