"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";

export function QcForm() {
  const router = useRouter();
  const [domain, setDomain] = useState("");
  const [seo, setSeo] = useState(true);
  const [perf, setPerf] = useState(true);
  const [content, setContent] = useState(true);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    if (!seo && !perf && !content) {
      setError("Pilih minimal satu modul QC.");
      return;
    }

    setPending(true);
    try {
      const res = await fetch("/api/qc/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain, modules: { seo, perf, content } }),
      });
      const data = await res.json();
      if (!res.ok || !data.ok) {
        setError(data.error ?? "Gagal memulai QC.");
        setPending(false);
        return;
      }
      router.push(`/qc/${data.id}`);
    } catch {
      setError("Gagal terhubung ke server.");
      setPending(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="flex flex-col gap-4">
      <Input
        name="domain"
        placeholder="example.com"
        className="h-10 bg-background"
        required
        disabled={pending}
        value={domain}
        onChange={(e) => setDomain(e.target.value)}
      />

      <div className="flex flex-col gap-2.5 rounded-xl border border-border-strong bg-surface-raised px-3.5 py-3">
        <span className="text-[10px] uppercase tracking-widest text-muted-dim">Modul QC</span>
        <label className="flex items-center gap-2.5 cursor-pointer group">
          <Checkbox checked={seo} onCheckedChange={(v) => setSeo(v === true)} disabled={pending} />
          <span className="text-xs text-muted group-hover:text-foreground">SEO Otomatis</span>
        </label>
        <label className="flex items-center gap-2.5 cursor-pointer group">
          <Checkbox checked={perf} onCheckedChange={(v) => setPerf(v === true)} disabled={pending} />
          <span className="text-xs text-muted group-hover:text-foreground">Performance</span>
        </label>
        <label className="flex items-center gap-2.5 cursor-pointer group">
          <Checkbox checked={content} onCheckedChange={(v) => setContent(v === true)} disabled={pending} />
          <span className="text-xs text-muted group-hover:text-foreground">Content / Link</span>
        </label>
      </div>

      {error && (
        <div className="rounded-lg border border-sev-critical/30 bg-sev-critical/10 p-2 text-xs text-sev-critical">
          {error}
        </div>
      )}

      <Button disabled={pending} className="w-full h-10">
        {pending ? "STARTING..." : "RUN QC →"}
      </Button>

      <p className="text-[11px] text-center text-muted-dim">
        Max 100 request/scan · GET/HEAD-only · 1 QC / domain / 5 menit
      </p>
    </form>
  );
}
