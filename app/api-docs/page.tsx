"use client";

import { useMemo, useState } from "react";
import { Search, AlertTriangle, Gauge } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";

const BASE_URL = "https://audit-otomatis-phi.vercel.app";

type Method = "GET" | "POST";

interface Field {
  name: string;
  type: string;
  required: boolean;
  note: string;
}

interface Endpoint {
  method: Method;
  path: string;
  title: string;
  description: string;
  notReal?: string; // kalau diisi: endpoint ini TIDAK ADA sebagai REST route, ini catatan kenapa
  body?: Field[];
  response: string;
  curl: string;
}

function CodeBlock({ children }: { children: string }) {
  return (
    <pre className="rounded-lg border border-[#333] bg-black px-4 py-3.5 overflow-x-auto text-[12px] leading-relaxed">
      <code className="font-mono text-[#00FF88] whitespace-pre">{children}</code>
    </pre>
  );
}

const ENDPOINTS: Endpoint[] = [
  {
    method: "POST",
    path: "/api/scan",
    title: "Mulai Passive Security Scan",
    description:
      "Belum tersedia sebagai REST endpoint publik. Memulai scan saat ini dilakukan lewat Next.js Server Action (startScanAction di lib/actions.ts), dipanggil langsung dari form di halaman Overview — bukan lewat fetch ke /api/scan. Ditulis di sini supaya konsisten dengan rencana API, tapi cURL di bawah TIDAK akan berhasil sampai endpoint-nya benar-benar dibuat.",
    notReal:
      "Server Action, bukan REST route. Kalau butuh trigger scan dari luar browser (mis. CI, script), endpoint publik ini perlu dibuat dulu.",
    body: [
      { name: "domain", type: "string", required: true, note: "URL atau hostname target, mis. \"example.com\"" },
    ],
    response: `{
  "ok": true,
  "scanId": "aB3xQ9kLmZ"
}`,
    curl: `# BELUM BERFUNGSI — lihat catatan di atas
curl -X POST '${BASE_URL}/api/scan' \\
  -H 'Content-Type: application/json' \\
  -d '{"domain":"example.com"}'`,
  },
  {
    method: "GET",
    path: "/api/scan/[id]/stream",
    title: "Stream Progres Scan (SSE)",
    description:
      "Server-Sent Events. Tiap event berupa JSON ScanLogEvent ({type, message?, status?, finding?, endpoints?, timestamp}). type bisa log | status | finding | done | error | blocked | endpoints. Mendukung resume via header Last-Event-ID kalau koneksi putus.",
    response: `id: 12
data: {"type":"finding","finding":{...},"timestamp":1785457624177}

id: 13
data: {"type":"done","status":"done","timestamp":1785457630001}`,
    curl: `curl -N '${BASE_URL}/api/scan/aB3xQ9kLmZ/stream'`,
  },
  {
    method: "GET",
    path: "/api/scan/[id]",
    title: "Ambil Ringkasan Scan",
    description: "Snapshot status scan saat ini (bukan realtime — pakai /stream untuk itu).",
    response: `{
  "id": "aB3xQ9kLmZ",
  "domain": "example.com",
  "status": "done",
  "createdAt": 1785457624177,
  "requestsMade": 87,
  "endpointsDiscovered": 14,
  "pagesCrawled": 12,
  "jsFilesScanned": 6,
  "findingsCount": 3,
  "blockedReason": null
}`,
    curl: `curl '${BASE_URL}/api/scan/aB3xQ9kLmZ'`,
  },
  {
    method: "POST",
    path: "/api/qc/scan",
    title: "Mulai QC Otomatis",
    description:
      "Membuat QC run baru lalu langsung menjalankannya di background. Field body sebenarnya domain (bukan url seperti di rencana awal) — nama field ini yang divalidasi oleh validateDomainInput().",
    body: [
      { name: "domain", type: "string", required: true, note: "URL atau hostname target" },
      { name: "modules.seo", type: "boolean", required: false, note: "default true" },
      { name: "modules.perf", type: "boolean", required: false, note: "default true" },
      { name: "modules.content", type: "boolean", required: false, note: "default true" },
    ],
    response: `{ "ok": true, "id": "qC7nR2wXpL" }`,
    curl: `curl -X POST '${BASE_URL}/api/qc/scan' \\
  -H 'Content-Type: application/json' \\
  -d '{"domain":"example.com","modules":{"seo":true,"perf":true,"content":false}}'`,
  },
  {
    method: "GET",
    path: "/api/qc/[id]/stream",
    title: "Stream Progres QC (SSE)",
    description:
      "Sama seperti scan stream tapi payload QcLogEvent: {type, message?, status?, module?, timestamp}. type: log | status | module_done | done | error.",
    response: `id: 4
data: {"type":"module_done","module":"seo","timestamp":1785457901234}`,
    curl: `curl -N '${BASE_URL}/api/qc/qC7nR2wXpL/stream'`,
  },
  {
    method: "GET",
    path: "/api/qc/[id]",
    title: "Ambil Hasil QC",
    description: "Snapshot QC state termasuk result per modul (skor 0–100 masing-masing).",
    response: `{
  "id": "qC7nR2wXpL",
  "domain": "example.com",
  "status": "done",
  "modules": { "seo": true, "perf": true, "content": false },
  "result": {
    "seo": { "score": 82, "issues": [...] },
    "perf": { "score": 91, "metrics": { "source": "pagespeed", ... } }
  },
  "requestsMade": 41
}`,
    curl: `curl '${BASE_URL}/api/qc/qC7nR2wXpL'`,
  },
  {
    method: "GET",
    path: "/api/requests",
    title: "Daftar Riwayat Scan",
    description: "List semua scan (Passive + QC berbagi store yang sama), terbaru dulu, maks 50.",
    response: `{
  "scans": [
    {
      "id": "aB3xQ9kLmZ",
      "domain": "example.com",
      "origin": "https://example.com",
      "createdAt": 1785457624177,
      "status": "done",
      "pagesCount": 12,
      "findingsCount": 3,
      "severityCounts": { "CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 0, "INFO": 0 }
    }
  ]
}`,
    curl: `curl '${BASE_URL}/api/requests'`,
  },
  {
    method: "GET",
    path: "/api/requests/[id]",
    title: "Detail Request per Scan",
    description:
      "Semua halaman yang di-crawl untuk satu scan, lengkap dengan header, content-type, ukuran, dan preview HTML — plus deteksi tech stack sederhana. 404 kalau scan tidak ada / sudah kedaluwarsa.",
    response: `{
  "meta": { "id": "aB3xQ9kLmZ", "hostname": "example.com", "url": "https://example.com", "createdAt": 1785457624177, "status": "done" },
  "pages": [
    { "url": "https://example.com", "status": 200, "contentType": "text/html", "size": 15342, "headers": {...} }
  ],
  "techStack": ["Next.js", "Vercel"]
}`,
    curl: `curl '${BASE_URL}/api/requests/aB3xQ9kLmZ'`,
  },
];

function MethodBadge({ method }: { method: Method }) {
  return (
    <span
      className={cn(
        "inline-flex items-center justify-center rounded-md border px-2 py-0.5 text-[10px] font-bold font-mono tracking-widest shrink-0",
        method === "POST"
          ? "border-[#00FF88]/40 text-[#00FF88] bg-[#00FF88]/10"
          : "border-sev-low/40 text-sev-low bg-sev-low/10"
      )}
    >
      {method}
    </span>
  );
}

export default function ApiDocsPage() {
  const [query, setQuery] = useState("");

  const filtered = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return ENDPOINTS;
    return ENDPOINTS.filter(
      (e) =>
        e.path.toLowerCase().includes(q) ||
        e.title.toLowerCase().includes(q) ||
        e.method.toLowerCase().includes(q)
    );
  }, [query]);

  return (
    <div className="w-full min-h-full">
      <div className="mx-auto max-w-6xl px-6 lg:px-8 py-10 space-y-6">
        {/* Breadcrumb */}
        <div>
          <div className="flex items-center gap-2 text-[10px] font-mono uppercase tracking-widest text-muted-dim mb-3">
            <span>Resources</span>
            <span className="text-border-strong">/</span>
            <span className="text-accent-2">API Reference</span>
          </div>
          <h1 className="text-2xl lg:text-3xl font-extrabold tracking-tight text-foreground mb-2">
            API Reference
          </h1>
          <p className="text-xs font-mono text-muted-dim">
            Base URL: <span className="text-accent-2">{BASE_URL}</span>
          </p>
        </div>

        {/* Rate limit box */}
        <Card>
          <CardContent className="p-4 flex items-start gap-3">
            <Gauge className="h-4 w-4 text-accent-2 shrink-0 mt-0.5" />
            <div className="text-xs text-muted leading-relaxed">
              <span className="font-bold text-foreground">Rate limit per crawl: </span>
              maksimal 100 request HTTP ke domain target ( <code className="text-accent-2">RequestBudget</code>{" "}
              di <code className="text-accent-2">lib/rate-limit.ts</code>). Cooldown per domain:{" "}
              <span className="font-bold text-foreground">5 menit</span> di production,{" "}
              <span className="font-bold text-foreground">10 detik</span> saat{" "}
              <code className="text-accent-2">NODE_ENV=development</code>. Cooldown scan pasif dan QC
              dihitung terpisah (prefix Redis beda).
            </div>
          </CardContent>
        </Card>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-dim" />
          <Input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="filter endpoint (path, method, judul)..."
            className="pl-9 h-9 text-xs font-mono max-w-md"
          />
        </div>

        {/* Endpoint list */}
        <div className="space-y-6">
          {filtered.length === 0 && (
            <div className="text-center text-xs text-muted-dim font-mono py-10">
              &gt; No endpoints match &quot;{query}&quot;
            </div>
          )}

          {filtered.map((e) => (
            <Card key={e.path + e.method}>
              <CardContent className="p-0">
                <div className="flex items-center gap-3 px-5 py-4 border-b border-border">
                  <MethodBadge method={e.method} />
                  <code className="text-sm font-mono text-foreground">{e.path}</code>
                  <span className="text-xs text-muted-dim ml-auto hidden sm:block">{e.title}</span>
                </div>

                {e.notReal && (
                  <div className="mx-5 mt-4 flex items-start gap-2.5 rounded-lg border border-sev-high/30 bg-sev-high/10 px-3.5 py-3 text-xs text-sev-high leading-relaxed">
                    <AlertTriangle className="h-3.5 w-3.5 shrink-0 mt-0.5" />
                    <span>{e.notReal}</span>
                  </div>
                )}

                <div className="grid lg:grid-cols-2 gap-6 p-5">
                  {/* Left: description + body table */}
                  <div className="space-y-4">
                    <p className="text-xs text-muted leading-relaxed">{e.description}</p>

                    {e.body && (
                      <div className="rounded-lg border border-border overflow-hidden">
                        <table className="w-full text-[11px] font-mono">
                          <thead>
                            <tr className="bg-surface-raised text-[10px] uppercase tracking-widest text-muted-dim">
                              <th className="text-left font-semibold px-3 py-2">Field</th>
                              <th className="text-left font-semibold px-3 py-2">Type</th>
                              <th className="text-left font-semibold px-3 py-2">Req.</th>
                              <th className="text-left font-semibold px-3 py-2">Note</th>
                            </tr>
                          </thead>
                          <tbody>
                            {e.body.map((f) => (
                              <tr key={f.name} className="border-t border-border">
                                <td className="px-3 py-2 text-accent-2">{f.name}</td>
                                <td className="px-3 py-2 text-muted">{f.type}</td>
                                <td className="px-3 py-2">
                                  {f.required ? (
                                    <span className="text-sev-critical">yes</span>
                                  ) : (
                                    <span className="text-muted-dim">no</span>
                                  )}
                                </td>
                                <td className="px-3 py-2 text-muted-dim">{f.note}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    )}
                  </div>

                  {/* Right: code, sticky */}
                  <div className="space-y-3 lg:sticky lg:top-24 self-start">
                    <div>
                      <div className="text-[10px] uppercase tracking-widest text-muted-dim mb-1.5">
                        Response
                      </div>
                      <CodeBlock>{e.response}</CodeBlock>
                    </div>
                    <div>
                      <div className="text-[10px] uppercase tracking-widest text-muted-dim mb-1.5">
                        cURL
                      </div>
                      <CodeBlock>{e.curl}</CodeBlock>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}
