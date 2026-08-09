"use client";

import { useRef, useState } from "react";
import { ReactFlowProvider } from "@xyflow/react";
import { ShieldOff, ScanSearch } from "lucide-react";
import { TopBar } from "./top-bar";
import { FlowCanvas, type FlowCanvasHandle } from "./flow-canvas";
import { StatsPanel } from "./stats-panel";
import { RiskBanner } from "./risk-banner";
import { DetailDrawer } from "./detail-drawer";
import { saveAttackMapToHistory } from "@/lib/attack-map/history-store";
import { downloadAttackMapAsJson, exportMapAsPng } from "@/lib/attack-map/export";
import type { AttackMapNode, AttackMapReport } from "@/lib/attack-map/types";

export function AttackMapView() {
  const [report, setReport] = useState<AttackMapReport | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [liveStatus, setLiveStatus] = useState<string | null>(null);
  const [selectedNode, setSelectedNode] = useState<AttackMapNode | null>(null);
  const canvasRef = useRef<FlowCanvasHandle>(null);

  async function handleScan(domain: string) {
    setLoading(true);
    setError(null);
    setSelectedNode(null);
    setLiveStatus(`Crawling ${domain} (depth 2, GET-only, same-origin)...`);
    try {
      const res = await fetch("/api/scan-map", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ domain }),
      });
      const data = await res.json();
      if (!data.ok) {
        setError(data.error || "Gagal membangun attack surface map.");
        setLiveStatus(null);
        return;
      }
      const nextReport = data.report as AttackMapReport;
      setReport(nextReport);
      setLiveStatus(`Selesai — ${nextReport.stats.totalNodes} node, ${nextReport.pagesCrawled} halaman di-crawl.`);
      saveAttackMapToHistory(nextReport);
    } catch {
      setError("Tidak bisa menghubungi server. Coba lagi.");
      setLiveStatus(null);
    } finally {
      setLoading(false);
    }
  }

  function handleExportPng() {
    if (!report || !canvasRef.current) return;
    const el = canvasRef.current.getViewportEl();
    if (!el) return;
    exportMapAsPng(el, `sentinel-attack-map-${report.hostname}.png`);
  }

  return (
    <div className="flex h-full flex-col">
      <TopBar
        onScan={handleScan}
        loading={loading}
        hasReport={!!report}
        onFitView={() => canvasRef.current?.fitView()}
        onExportPng={handleExportPng}
        onExportJson={() => report && downloadAttackMapAsJson(report)}
        liveStatus={liveStatus}
      />

      {error && (
        <div className="px-4 sm:px-6 pt-3">
          <div className="rounded-lg border border-sev-critical/40 bg-sev-critical/10 px-4 py-2.5 text-xs font-mono text-sev-critical">
            {error}
          </div>
        </div>
      )}

      <div className="relative flex-1 min-h-0">
        {!report && !loading && (
          <div className="absolute inset-0 grid place-items-center">
            <div className="text-center space-y-2">
              <ShieldOff className="h-8 w-8 text-muted-dim mx-auto" />
              <p className="text-sm text-muted">Belum ada map.</p>
              <p className="text-xs text-muted-dim">Masukkan domain di atas, lalu klik Scan.</p>
            </div>
          </div>
        )}

        {loading && (
          <div className="absolute inset-0 grid place-items-center">
            <div className="text-center space-y-4">
              <div className="relative mx-auto h-40 w-72 overflow-hidden rounded-xl border border-accent/30 bg-[#0a0710]">
                <div className="sentinel-scan-line absolute left-0 right-0 h-px bg-accent shadow-[0_0_12px_2px_var(--accent)]" />
                <div className="absolute inset-0 grid place-items-center">
                  <ScanSearch className="h-8 w-8 text-accent/70 animate-pulse" />
                </div>
              </div>
              <p className="text-xs font-mono uppercase tracking-widest text-muted animate-pulse">
                Membangun attack surface graph...
              </p>
            </div>
          </div>
        )}

        {report && (
          <>
            <ReactFlowProvider>
              <FlowCanvas ref={canvasRef} nodes={report.nodes} edges={report.edges} onNodeSelect={setSelectedNode} />
            </ReactFlowProvider>

            {!selectedNode && (
              <div className="absolute top-4 right-4 z-10">
                <StatsPanel stats={report.stats} />
              </div>
            )}

            <div className="absolute bottom-4 left-4 z-10" style={{ right: selectedNode ? 336 : 16 }}>
              <RiskBanner highlights={report.riskHighlights} />
            </div>

            <DetailDrawer node={selectedNode} hostname={report.hostname} onClose={() => setSelectedNode(null)} />
          </>
        )}
      </div>
    </div>
  );
}
