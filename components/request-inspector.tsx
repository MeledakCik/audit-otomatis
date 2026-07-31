"use client";

import { useEffect, useMemo, useState } from "react";
import {
  Search,
  Download,
  ExternalLink,
  Copy,
  X,
  Check,
  Gauge,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import type { CrawledPage } from "@/lib/types";

interface RequestMeta {
  id: string;
  hostname: string;
  url: string;
  createdAt: number;
  status: string;
}

type ResourceType = "doc" | "script" | "css" | "img" | "xhr" | "other";
const TYPE_TABS: { key: "ALL" | ResourceType; label: string }[] = [
  { key: "ALL", label: "All" },
  { key: "doc", label: "Doc" },
  { key: "script", label: "Script" },
  { key: "css", label: "CSS" },
  { key: "img", label: "Img" },
  { key: "xhr", label: "XHR" },
];

const PAGE_SIZE = 25;

function typeOf(contentType?: string): ResourceType {
  const ct = (contentType ?? "").toLowerCase();
  if (ct.includes("text/html")) return "doc";
  if (ct.includes("javascript")) return "script";
  if (ct.includes("css")) return "css";
  if (ct.startsWith("image/")) return "img";
  if (ct.includes("json") || ct.includes("xml")) return "xhr";
  return "other";
}

function statusColor(status: number): string {
  if (status >= 200 && status < 300) return "text-accent";
  if (status >= 300 && status < 400) return "text-sev-low";
  if (status >= 400 && status < 500) return "text-sev-medium";
  if (status >= 500) return "text-sev-critical";
  return "text-muted-dim";
}

function buildCurl(page: CrawledPage): string {
  return `curl '${page.url}' \\\n  -H 'User-Agent: Mozilla/5.0' \\\n  -H 'Accept: ${page.contentType || "*/*"}'`;
}

function exportHAR(pages: CrawledPage[], hostname: string) {
  const har = {
    log: {
      version: "1.2",
      creator: { name: "TROUT", version: "1.0" },
      pages: [],
      entries: pages.map((p) => ({
        startedDateTime: new Date().toISOString(),
        request: { method: "GET", url: p.url, headers: [], queryString: [], headersSize: -1, bodySize: -1 },
        response: {
          status: p.status,
          statusText: "",
          content: { size: p.size ?? 0, mimeType: p.contentType ?? "" },
          headers: Object.entries(p.headers ?? {}).map(([name, value]) => ({ name, value })),
          headersSize: -1,
          bodySize: p.size ?? 0,
        },
        cache: {},
        timings: { send: 0, wait: 0, receive: 0 },
      })),
    },
  };
  const blob = new Blob([JSON.stringify(har, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `${hostname || "scan"}.har`;
  a.click();
  URL.revokeObjectURL(url);
}

function CopyIconButton({ text, className }: { text: string; className?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={async (e) => {
        e.stopPropagation();
        try {
          await navigator.clipboard.writeText(text);
          setCopied(true);
          setTimeout(() => setCopied(false), 1200);
        } catch {
          // clipboard bisa gagal di context non-secure; abaikan diam-diam
        }
      }}
      className={cn("inline-flex items-center gap-1 text-muted-dim hover:text-accent transition-colors", className)}
      title="Salin"
    >
      {copied ? <Check className="h-3 w-3 text-accent" /> : <Copy className="h-3 w-3" />}
    </button>
  );
}

function Drawer({
  page,
  onClose,
}: {
  page: CrawledPage;
  onClose: () => void;
}) {
  const [tab, setTab] = useState<"headers" | "preview" | "curl">("headers");
  const type = typeOf(page.contentType);
  const curl = buildCurl(page);

  return (
    <>
      <div className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm" onClick={onClose} />
      <div className="fixed top-0 right-0 z-50 h-screen w-full sm:w-[420px] bg-surface border-l border-border shadow-2xl flex flex-col">
        <div className="flex items-start justify-between gap-3 border-b border-border px-4 py-3.5 shrink-0">
          <div className="min-w-0">
            <div className="text-[10px] uppercase tracking-widest text-muted-dim mb-1">Request</div>
            <div className="text-xs font-mono text-foreground break-all">{page.url}</div>
          </div>
          <button
            onClick={onClose}
            className="shrink-0 h-7 w-7 grid place-items-center rounded-full text-muted-dim hover:text-foreground hover:bg-surface-raised transition-colors"
          >
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="flex items-center gap-1 px-4 pt-3 border-b border-border shrink-0">
          {(["headers", "preview", "curl"] as const).map((t) => (
            <button
              key={t}
              onClick={() => setTab(t)}
              className={cn(
                "px-3 py-1.5 text-[11px] font-mono uppercase tracking-wider border-b-2 -mb-px transition-colors",
                tab === t
                  ? "border-accent text-accent"
                  : "border-transparent text-muted-dim hover:text-muted"
              )}
            >
              {t}
            </button>
          ))}
        </div>

        <div className="flex-1 overflow-y-auto thin-scroll p-4">
          {tab === "headers" && (
            <pre className="text-[11px] font-mono leading-relaxed text-muted whitespace-pre-wrap break-all">
              {JSON.stringify(page.headers ?? {}, null, 2)}
            </pre>
          )}

          {tab === "preview" &&
            (type === "img" ? (
              // eslint-disable-next-line @next/next/no-img-element
              <img src={page.url} alt={page.url} className="max-w-full rounded-lg border border-border" />
            ) : type === "doc" && page.html ? (
              <pre className="text-[11px] font-mono leading-relaxed text-muted whitespace-pre-wrap break-all">
                {page.html.slice(0, 2000)}
              </pre>
            ) : (
              <p className="text-xs text-muted-dim">No preview</p>
            ))}

          {tab === "curl" && (
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <span className="text-[10px] uppercase tracking-widest text-muted-dim">cURL</span>
                <CopyIconButton text={curl} />
              </div>
              <pre className="text-[11px] font-mono leading-relaxed text-foreground whitespace-pre-wrap break-all bg-background border border-border rounded-lg px-3 py-2.5">
                {curl}
              </pre>
            </div>
          )}
        </div>

        <div className="border-t border-border px-4 py-3 flex items-center gap-2 shrink-0">
          <Button variant="outline" size="sm" onClick={() => window.open(page.url, "_blank")}>
            <ExternalLink className="h-3.5 w-3.5" />
            Open in new tab
          </Button>
          <Button
            variant="ghost"
            size="sm"
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(page.url);
              } catch {
                // abaikan diam-diam
              }
            }}
          >
            <Copy className="h-3.5 w-3.5" />
            Copy URL
          </Button>
        </div>
      </div>
    </>
  );
}

export function RequestInspector({ scanId }: { scanId: string }) {
  const [meta, setMeta] = useState<RequestMeta | null>(null);
  const [pages, setPages] = useState<CrawledPage[] | null>(null);
  const [techStack, setTechStack] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);

  const [query, setQuery] = useState("");
  const [typeFilter, setTypeFilter] = useState<"ALL" | ResourceType>("ALL");
  const [page, setPage] = useState(1);
  const [selected, setSelected] = useState<CrawledPage | null>(null);

  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        const res = await fetch(`/api/requests/${scanId}`);
        const data = await res.json();
        if (cancelled) return;
        if (!res.ok) {
          setError(data.error ?? `HTTP ${res.status}`);
          return;
        }
        setMeta(data.meta);
        setPages(data.pages ?? []);
        setTechStack(data.techStack ?? []);
      } catch (e) {
        if (!cancelled) setError(e instanceof Error ? e.message : "Request gagal.");
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [scanId]);

  const filtered = useMemo(() => {
    if (!pages) return [];
    const q = query.trim().toLowerCase();
    return pages.filter((p) => {
      if (typeFilter !== "ALL" && typeOf(p.contentType) !== typeFilter) return false;
      if (q && !p.url.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [pages, query, typeFilter]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const paged = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  const stats = useMemo(() => {
    const list = pages ?? [];
    const totalSizeKB = list.reduce((sum, p) => sum + (p.size ?? 0), 0) / 1024;
    const ok200 = list.filter((p) => p.status >= 200 && p.status < 300).length;
    const avg200 = list.length > 0 ? (ok200 / list.length) * 100 : 0;
    return { total: list.length, totalSizeKB, avg200 };
  }, [pages]);

  if (error) {
    return (
      <div className="w-full min-h-full">
        <div className="mx-auto max-w-3xl px-6 py-16">
          <div className="rounded-2xl border border-sev-critical/30 bg-sev-critical/10 px-5 py-4 font-mono text-sm text-sev-critical">
            $ cat: {`scan:${scanId}`}: {error}
          </div>
        </div>
      </div>
    );
  }

  if (!pages || !meta) {
    return (
      <div className="w-full min-h-full">
        <div className="mx-auto max-w-6xl px-6 py-16 text-center text-xs text-muted-dim font-mono">
          <span className="cursor-blink">$ loading scan:{scanId}…</span>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full min-h-full">
      <div className="mx-auto max-w-6xl px-6 lg:px-8 py-10 space-y-6">
        <div className="space-y-2">
          <div className="inline-flex items-center px-3 py-1 rounded-md bg-accent/10 border border-accent/20 text-xs font-mono tracking-[0.2em] uppercase text-accent">
            $ inspect {meta.hostname}
          </div>
          <h1 className="text-2xl font-extrabold tracking-tight text-foreground break-all">{meta.url}</h1>
        </div>

        {/* A. Top stats */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <Card>
            <CardContent className="p-4 space-y-1">
              <div className="text-[10px] uppercase tracking-widest text-muted-dim">Total Requests</div>
              <div className="text-2xl font-bold text-foreground">{stats.total}</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 space-y-1">
              <div className="text-[10px] uppercase tracking-widest text-muted-dim">Total Size</div>
              <div className="text-2xl font-bold text-foreground">{stats.totalSizeKB.toFixed(1)} KB</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 space-y-1">
              <div className="text-[10px] uppercase tracking-widest text-muted-dim flex items-center gap-1.5">
                <Gauge className="h-3 w-3" /> Avg Status 200
              </div>
              <div className="text-2xl font-bold text-accent">{stats.avg200.toFixed(0)}%</div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-4 space-y-1.5">
              <div className="text-[10px] uppercase tracking-widest text-muted-dim">Tech Stack</div>
              <div className="flex flex-wrap gap-1.5 pt-0.5">
                {techStack.length === 0 ? (
                  <span className="text-xs text-muted-dim">—</span>
                ) : (
                  techStack.map((t) => (
                    <span
                      key={t}
                      className="inline-flex items-center rounded-full border border-accent/50 text-accent px-2 py-0.5 text-[10px] font-mono"
                    >
                      {t}
                    </span>
                  ))
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* B. Toolbar */}
        <div className="flex flex-col sm:flex-row sm:items-center gap-2.5">
          <div className="relative flex-1 min-w-0">
            <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-dim" />
            <Input
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setPage(1);
              }}
              placeholder="filter url..."
              className="pl-9 h-9 text-xs font-mono"
            />
          </div>
          <div className="flex items-center gap-1.5 flex-wrap">
            {TYPE_TABS.map((t) => (
              <button
                key={t.key}
                onClick={() => {
                  setTypeFilter(t.key);
                  setPage(1);
                }}
                className={cn(
                  "rounded-full px-2.5 py-1 text-[10px] font-bold uppercase tracking-widest border transition-colors",
                  typeFilter === t.key
                    ? "border-accent text-accent bg-accent/10"
                    : "border-border-strong text-muted-dim hover:text-muted"
                )}
              >
                {t.label}
              </button>
            ))}
          </div>
          <Button variant="outline" size="sm" onClick={() => exportHAR(pages, meta.hostname)}>
            <Download className="h-3.5 w-3.5" />
            Export HAR
          </Button>
        </div>

        {/* C. Table log */}
        <Card>
          <CardContent className="p-0">
            {filtered.length === 0 ? (
              <div className="px-4 py-10 text-center text-xs text-muted-dim font-mono">
                &gt; No requests match this filter.
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs font-mono">
                  <thead>
                    <tr className="border-b border-border text-[10px] uppercase tracking-widest text-muted-dim">
                      <th className="text-left font-semibold px-4 py-2.5 w-10">#</th>
                      <th className="text-left font-semibold px-4 py-2.5">URL</th>
                      <th className="text-left font-semibold px-4 py-2.5">Status</th>
                      <th className="text-left font-semibold px-4 py-2.5">Type</th>
                      <th className="text-left font-semibold px-4 py-2.5">Size</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paged.map((p, i) => {
                      const idx = (page - 1) * PAGE_SIZE + i + 1;
                      const truncated = p.url.length > 60 ? `${p.url.slice(0, 60)}…` : p.url;
                      return (
                        <tr
                          key={`${p.url}-${i}`}
                          onClick={() => setSelected(p)}
                          className="border-b border-border last:border-0 hover:bg-surface-raised transition-colors cursor-pointer"
                        >
                          <td className="px-4 py-2.5 text-muted-dim">{idx}</td>
                          <td className="px-4 py-2.5 text-foreground">
                            <span className="inline-flex items-center gap-1.5">
                              <span title={p.url}>{truncated}</span>
                              <CopyIconButton text={p.url} />
                            </span>
                          </td>
                          <td className={cn("px-4 py-2.5 font-bold", statusColor(p.status))}>{p.status}</td>
                          <td className="px-4 py-2.5">
                            <Badge className="bg-surface-raised">{typeOf(p.contentType)}</Badge>
                          </td>
                          <td className="px-4 py-2.5 text-muted">{((p.size ?? 0) / 1024).toFixed(1)} KB</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}

            {totalPages > 1 && (
              <div className="flex items-center justify-between px-4 py-3 border-t border-border text-[11px] font-mono text-muted-dim">
                <span>
                  page {page}/{totalPages}
                </span>
                <div className="flex gap-1.5">
                  <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                    Prev
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={page >= totalPages}
                    onClick={() => setPage((p) => p + 1)}
                  >
                    Next
                  </Button>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {selected && <Drawer page={selected} onClose={() => setSelected(null)} />}
    </div>
  );
}
