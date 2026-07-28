"use client";

import { useMemo, useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import type { DiscoveredEndpoint } from "@/lib/types";
import { cn } from "@/lib/utils";

const METHOD_STYLES: Record<DiscoveredEndpoint["method"], string> = {
  GET: "text-accent border-accent/50 bg-accent/10",
  POST: "text-sev-high border-sev-high/50 bg-sev-high/10",
  PUT: "text-sev-medium border-sev-medium/50 bg-sev-medium/10",
  DELETE: "text-sev-critical border-sev-critical/50 bg-sev-critical/10",
  PATCH: "text-sev-medium border-sev-medium/50 bg-sev-medium/10",
};

const METHOD_ORDER = ["GET", "POST", "PUT", "DELETE", "PATCH"] as const;

function MethodBadge({ method }: { method: DiscoveredEndpoint["method"] }) {
  return (
    <span
      className={cn(
        "inline-flex items-center justify-center rounded-full border px-2 py-0.5 text-[10px] font-bold tracking-widest uppercase shrink-0 w-14",
        METHOD_STYLES[method],
      )}
    >
      {method}
    </span>
  );
}

function pathOf(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch {
    return url;
  }
}

function hostOf(url: string): string {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}
function buildCurl(ep: DiscoveredEndpoint): string {
  if (ep.method === "GET") {
    return `curl -sS -i \\\n  -X GET '${ep.url}' \\\n  -H 'User-Agent: Mozilla/5.0'`;
  }
  const fields = ep.payload && ep.payload.length > 0 ? ep.payload : [];
  const payloadObj =
    fields.length > 0
      ? JSON.stringify(Object.fromEntries(fields.map((f) => [f, ""])), null, 2)
      : "{}";
  const indented = payloadObj.split("\n").join("\n  ");
  return `curl -sS -i \\\n  -X ${ep.method} '${ep.url}' \\\n  -H 'Content-Type: application/json' \\\n  -d '${indented}'\n\n# Catatan: field body di atas cuma tebakan statis dari nama variabel di\n# JS/form (belum tentu lengkap/benar) — isi & verifikasi manual sebelum\n# dijalankan. Tool ini sendiri tidak pernah mengirim POST/PUT/DELETE.`;
}

function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <Button
      type="button"
      variant="outline"
      size="sm"
      onClick={async () => {
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1500);
        } catch {
          // clipboard API bisa gagal di context non-secure; abaikan diam-diam
        }
      }}
    >
      {copied ? "tersalin ✓" : "salin cURL"}
    </Button>
  );
}

interface TestResult {
  ok: boolean;
  status?: number;
  statusText?: string;
  timeMs?: number;
  headers?: Record<string, string>;
  bodyPreview?: string;
  truncated?: boolean;
  bodyLength?: number;
  finalUrl?: string;
  error?: string;
}

function statusColor(status?: number): string {
  if (!status) return "text-muted-dim";
  if (status < 300) return "text-accent";
  if (status < 400) return "text-sev-low";
  if (status < 500) return "text-sev-medium";
  return "text-sev-critical";
}

function EndpointCard({
  ep,
  scanId,
  defaultOpen,
}: {
  ep: DiscoveredEndpoint;
  scanId: string;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(!!defaultOpen);
  const [testing, setTesting] = useState(false);
  const [result, setResult] = useState<TestResult | null>(null);
  const curl = useMemo(() => buildCurl(ep), [ep]);
  const isGet = ep.method === "GET";

  async function runTest() {
    setTesting(true);
    setResult(null);
    try {
      const res = await fetch(`/api/scan/${scanId}/test-endpoint`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: ep.url }),
      });
      const data = (await res.json()) as TestResult;
      setResult(data);
    } catch (e) {
      setResult({
        ok: false,
        error: e instanceof Error ? e.message : "Request gagal.",
      });
    } finally {
      setTesting(false);
    }
  }

  return (
    <div className="rounded-xl border border-border bg-surface overflow-hidden">
      <button
        onClick={() => setOpen((v) => !v)}
        className="w-full flex items-center gap-3 px-3.5 py-2.5 text-left hover:bg-surface-raised transition-colors"
      >
        <MethodBadge method={ep.method} />
        <span className="flex-1 min-w-0 text-xs text-foreground font-mono truncate">
          {pathOf(ep.url)}
        </span>
        {ep.payload && ep.payload.length > 0 && (
          <Badge className="hidden sm:inline-flex">
            {ep.payload.length} field
          </Badge>
        )}
        <span
          className={cn(
            "text-muted-dim text-xs transition-transform duration-200 shrink-0",
            open && "rotate-90",
          )}
        >
          ›
        </span>
      </button>

      <div className={cn("accordion-rows", open && "is-open")}>
        <div className="accordion-inner">
          <div className="border-t border-border px-3.5 py-3 bg-surface-raised/40 flex flex-col gap-3 text-xs">
          <Row label="URL Lengkap" value={ep.url} mono />
          <Row label="Host" value={hostOf(ep.url)} mono />
          <Row label="Sumber Ditemukan" value={ep.source} mono />
          {ep.payload && ep.payload.length > 0 && (
            <Row
              label="Payload Field (terdeteksi statis)"
              value={ep.payload.join(", ")}
              mono
              accent
            />
          )}

          <div className="flex flex-col gap-1.5">
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase tracking-widest text-muted-dim">
                cURL — uji manual
              </span>
              <CopyButton text={curl} />
            </div>
            <pre className="overflow-x-auto whitespace-pre-wrap break-all bg-background border border-border rounded-lg px-3 py-2 text-[11px] leading-relaxed text-foreground font-mono">
              {curl}
            </pre>
          </div>

          <div className="flex flex-col gap-1.5">
            <div className="flex items-center justify-between flex-wrap gap-2">
              <span className="text-[10px] uppercase tracking-widest text-muted-dim">
                {isGet
                  ? "Kirim request langsung"
                  : "Test langsung tidak tersedia untuk method ini"}
              </span>
              {isGet ? (
                <Button
                  type="button"
                  variant="primary"
                  size="sm"
                  onClick={runTest}
                  disabled={testing}
                >
                  {testing ? "mengirim…" : "kirim GET"}
                </Button>
              ) : (
                <Badge>hanya GET yang dieksekusi otomatis</Badge>
              )}
            </div>
            {!isGet && (
              <p className="text-[11px] text-muted-dim leading-relaxed">
                Sejalan dengan kebijakan pasif tool ini (GET-only,
                non-destruktif), method{" "}
                <span className="font-mono text-muted">{ep.method}</span> tidak
                dieksekusi otomatis dari sini. Salin cURL di atas dan jalankan
                sendiri dari terminal kalau memang mau diuji.
              </p>
            )}

            {result && (
              <div className="rounded-lg border border-border bg-background px-3 py-2.5 flex flex-col gap-2">
                {result.ok ? (
                  <>
                    <div className="flex items-center gap-3 flex-wrap">
                      <span
                        className={cn(
                          "font-bold font-mono",
                          statusColor(result.status),
                        )}
                      >
                        {result.status} {result.statusText}
                      </span>
                      <span className="text-muted-dim">{result.timeMs}ms</span>
                      <span className="text-muted-dim">
                        {result.bodyLength?.toLocaleString("id-ID")} byte
                        {result.truncated
                          ? " (dipotong, preview 4000 char)"
                          : ""}
                      </span>
                    </div>
                    {result.headers &&
                      Object.keys(result.headers).length > 0 && (
                        <details className="text-[11px]">
                          <summary className="cursor-pointer text-muted-dim hover:text-muted">
                            response headers (
                            {Object.keys(result.headers).length})
                          </summary>
                          <div className="mt-1.5 flex flex-col gap-0.5 font-mono">
                            {Object.entries(result.headers).map(([k, v]) => (
                              <div key={k} className="break-all">
                                <span className="text-muted-dim">{k}:</span>{" "}
                                <span className="text-muted">{v}</span>
                              </div>
                            ))}
                          </div>
                        </details>
                      )}
                    {result.bodyPreview !== undefined && (
                      <details className="text-[11px]" open>
                        <summary className="cursor-pointer text-muted-dim hover:text-muted">
                          response body
                        </summary>
                        <pre className="mt-1.5 overflow-x-auto whitespace-pre-wrap break-all max-h-64 overflow-y-auto thin-scroll text-foreground">
                          {result.bodyPreview || "(kosong)"}
                        </pre>
                      </details>
                    )}
                  </>
                ) : (
                  <span className="text-sev-critical">
                    {result.error ?? "Request gagal."}
                  </span>
                )}
              </div>
            )}
          </div>
          </div>
        </div>
      </div>
    </div>
  );
}

export function EndpointsTable({
  endpoints,
  scanId,
}: {
  endpoints: DiscoveredEndpoint[];
  scanId?: string;
}) {
  const [filter, setFilter] = useState<"ALL" | DiscoveredEndpoint["method"]>(
    "ALL",
  );
  const [query, setQuery] = useState("");

  const counts = useMemo(() => {
    return Object.fromEntries(
      METHOD_ORDER.map((m) => [
        m,
        endpoints.filter((e) => e.method === m).length,
      ]),
    ) as Record<DiscoveredEndpoint["method"], number>;
  }, [endpoints]);

  // Cuma tampilkan tombol filter buat method yang benar-benar ada hasilnya,
  // biar bar filter nggak penuh tombol "PATCH (0)" kalau scan-nya nggak
  // nemu apa-apa buat method itu.
  const presentMethods = METHOD_ORDER.filter((m) => counts[m] > 0);

  const visible = useMemo(() => {
    let list =
      filter === "ALL"
        ? endpoints
        : endpoints.filter((e) => e.method === filter);
    const q = query.trim().toLowerCase();
    if (q) {
      list = list.filter(
        (e) =>
          e.url.toLowerCase().includes(q) || e.source.toLowerCase().includes(q),
      );
    }
    return list;
  }, [endpoints, filter, query]);

  if (endpoints.length === 0) {
    return (
      <div className="px-4 py-10 text-center text-xs text-muted-dim">
        Belum ada link/endpoint ditemukan. Muncul setelah tahap crawling &
        analisis JS selesai.
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex flex-col gap-2 px-3.5 py-2.5 border-b border-border shrink-0">
        <div className="flex items-center gap-1.5 flex-wrap">
          {(["ALL", ...presentMethods] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={cn(
                "rounded-full px-2.5 py-1 text-[10px] font-bold uppercase tracking-widest border transition-colors",
                filter === f
                  ? "border-accent text-accent bg-accent/10"
                  : "border-border-strong text-muted-dim hover:text-muted",
              )}
            >
              {f === "ALL"
                ? `Semua (${endpoints.length})`
                : `${f} (${counts[f]})`}
            </button>
          ))}
        </div>
        <Input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="cari path, param, atau sumber… (mis. /api, contact, token)"
          className="h-8 text-xs"
        />
      </div>
      <div className="overflow-y-auto thin-scroll p-2.5 flex flex-col gap-2">
        {visible.length === 0 ? (
          <div className="px-2 py-8 text-center text-xs text-muted-dim">
            Tidak ada endpoint yang cocok.
          </div>
        ) : (
          visible.map((ep, i) => (
            <EndpointCard
              key={`${ep.method} ${ep.url} ${i}`}
              ep={ep}
              scanId={scanId ?? ""}
            />
          ))
        )}
      </div>
    </div>
  );
}

function Row({
  label,
  value,
  mono,
  accent,
}: {
  label: string;
  value: string;
  mono?: boolean;
  accent?: boolean;
}) {
  return (
    <div className="flex flex-col gap-0.5">
      <span className="text-[10px] uppercase tracking-widest text-muted-dim">
        {label}
      </span>
      <span
        className={cn(
          "leading-relaxed break-words",
          mono && "font-mono text-muted",
          accent ? "text-accent" : !mono && "text-foreground",
        )}
      >
        {value}
      </span>
    </div>
  );
}
