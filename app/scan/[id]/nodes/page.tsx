"use client";

import { useEffect, useState, useMemo } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import type { GraphNode, ScanStatus } from "@/lib/types";
import {
  Search,
  Filter,
  ArrowUpDown,
  Globe,
  FileCode,
  Cpu,
  ShieldCheck,
  Clock,
  AlertCircle,
  ExternalLink,
  ArrowLeft,
  Activity,
  Layers,
  Sparkles,
  Radio,
} from "lucide-react";

const POLL_MS = 2500;

export default function NodeExplorerPage() {
  const params = useParams();
  const scanId =
    (params?.scanId as string) || window.location.pathname.split("/")[2];

  const [nodes, setNodes] = useState<GraphNode[]>([]);
  const [status, setStatus] = useState<ScanStatus | "connecting">("connecting");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [activeFilter, setActiveFilter] = useState<string>("all");
  const [sortBy, setSortBy] = useState<"default" | "type" | "label">("default");

  useEffect(() => {
    if (!scanId) return;
    let cancelled = false;

    async function fetchData() {
      try {
        const statusRes = await fetch(`/api/scan/${scanId}`, {
          cache: "no-store",
        });
        if (statusRes.ok) {
          const statusData = await statusRes.json();
          if (!cancelled && statusData.status) {
            setStatus(statusData.status);
          }
        }

        const res = await fetch(`/api/scan/${scanId}/graph`, {
          cache: "no-store",
        });
        const data = await res.json();

        if (!cancelled) {
          let extractedNodes: GraphNode[] = [];
          if (Array.isArray(data)) {
            extractedNodes = data;
          } else if (data.nodes && Array.isArray(data.nodes)) {
            extractedNodes = data.nodes;
          } else if (data.data && Array.isArray(data.data)) {
            extractedNodes = data.data;
          }

          setNodes(extractedNodes);
          setLoading(false);
        }
      } catch (err) {
        console.error("Error fetching graph:", err);
        if (!cancelled) {
          setError("Gagal memuat data node graph secara menyeluruh.");
          setLoading(false);
        }
      }
    }

    fetchData();

    const interval = setInterval(fetchData, POLL_MS);
    return () => {
      cancelled = true;
      clearInterval(interval);
    };
  }, [scanId]);

  const stats = useMemo(() => {
    const totalNodes = nodes.length;
    const jsBundles = nodes.filter((n) => n.type === "js").length;
    const rootPages = nodes.filter((n) => n.type === "page").length;
    const endpoints = nodes.filter((n) => n.type === "endpoint").length;
    return { totalNodes, jsBundles, rootPages, endpoints };
  }, [nodes]);

  const filteredNodes = useMemo(() => {
    let result = nodes;
    if (activeFilter !== "all") {
      result = result.filter((n) => n.type === activeFilter);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (n) =>
          n.label?.toLowerCase().includes(q) ||
          n.id?.toLowerCase().includes(q) ||
          n.type?.toLowerCase().includes(q),
      );
    }
    if (sortBy === "type") {
      result = [...result].sort((a, b) =>
        (a.type || "").localeCompare(b.type || ""),
      );
    } else if (sortBy === "label") {
      result = [...result].sort((a, b) =>
        (a.label || "").localeCompare(b.label || ""),
      );
    }

    return result;
  }, [nodes, searchQuery, activeFilter, sortBy]);

  return (
    <div className="min-h-screen bg-[#05070d] text-zinc-100 font-sans p-4 md:p-8 lg:p-10 selection:bg-emerald-500/30 selection:text-emerald-300 relative overflow-hidden">
      {/* Background Cyberpunk Glow Effects */}
      <div className="absolute top-0 left-1/4 w-96 h-96 bg-emerald-500/10 rounded-full blur-3xl pointer-events-none animate-pulse" />
      <div className="absolute bottom-1/3 right-10 w-96 h-96 bg-blue-500/10 rounded-full blur-3xl pointer-events-none" />

      <div className="max-w-7xl mx-auto space-y-6 relative z-10">
        {/* Top Navigation & Header Banner */}
        <div className="flex flex-col gap-6 bg-gradient-to-br from-[#0b0f19]/90 to-[#070a12]/90 border border-zinc-800/80 p-6 md:p-8 rounded-3xl shadow-2xl backdrop-blur-xl relative overflow-hidden group">
          <div className="absolute top-0 right-0 w-64 h-32 bg-gradient-to-l from-emerald-500/5 to-transparent pointer-events-none" />

          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
            <div className="space-y-2">
              <Link
                href={`/scan/${scanId}`}
                className="inline-flex items-center gap-2 text-xs font-mono text-emerald-400 hover:text-emerald-300 transition-all transform hover:-translate-x-1 mb-1"
              >
                <ArrowLeft className="w-3.5 h-3.5" /> KEMBALI KE DASHBOARD SCAN
              </Link>
              <div className="flex items-center gap-3">
                <h1 className="text-2xl md:text-4xl font-extrabold tracking-tight text-transparent bg-clip-text bg-gradient-to-r from-zinc-100 via-emerald-200 to-emerald-400">
                  Sentinel Node Map Explorer
                </h1>
                <span className="hidden md:inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-[10px] font-mono font-medium bg-emerald-950/60 border border-emerald-500/30 text-emerald-400 animate-pulse">
                  <Radio className="w-3 h-3" /> LIVE STREAM
                </span>
              </div>
              <p className="text-xs md:text-sm text-zinc-400 max-w-2xl leading-relaxed">
                Eksplorasi mendalam seluruh aset, halaman root, bundle
                JavaScript, dan endpoint target pemindaian target{" "}
                <span className="font-mono text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-900/50">
                  {scanId}
                </span>
                .
              </p>
            </div>

            <a
              href={`/api/scan/${scanId}/graph`}
              target="_blank"
              rel="noreferrer"
              className="inline-flex items-center justify-center gap-2.5 bg-gradient-to-r from-zinc-900 to-[#121824] hover:from-zinc-800 hover:to-zinc-800 border border-zinc-700/80 px-5 py-3 rounded-2xl text-xs font-mono font-semibold text-zinc-200 transition-all shadow-lg hover:shadow-emerald-500/10 hover:border-emerald-500/40 self-start sm:self-auto group/btn"
            >
              <Sparkles className="w-3.5 h-3.5 text-emerald-400 transition-transform group-hover/btn:rotate-12" />
              LIHAT GRAPH.JSON
              <ExternalLink className="w-3.5 h-3.5 text-zinc-400 group-hover/btn:translate-x-0.5 transition-transform" />
            </a>
          </div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3.5 pt-4 border-t border-zinc-800/60">
            <StatBox
              icon={<Cpu className="w-4 h-4 text-emerald-400" />}
              label="Total Nodes"
              value={stats.totalNodes}
              colorBorder="group-hover:border-emerald-500/40"
            />
            <StatBox
              icon={<Globe className="w-4 h-4 text-emerald-500" />}
              label="Root Pages"
              value={stats.rootPages}
              colorBorder="group-hover:border-emerald-500/40"
            />
            <StatBox
              icon={<FileCode className="w-4 h-4 text-blue-400" />}
              label="JS Bundles"
              value={stats.jsBundles}
              colorBorder="group-hover:border-blue-500/40"
            />
            <StatBox
              icon={<ShieldCheck className="w-4 h-4 text-rose-400" />}
              label="Endpoints"
              value={stats.endpoints}
              colorBorder="group-hover:border-rose-500/40"
            />
          </div>
        </div>
        <div className="flex flex-col md:flex-row items-stretch md:items-center justify-between gap-4">
          <div className="relative flex-1 max-w-xl">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-400" />
            <input
              type="text"
              placeholder="Cari berdasarkan URL, chunk JS, atau tipe aset..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full bg-[#0b0f19]/90 border border-zinc-800/80 rounded-2xl pl-11 pr-4 py-3.5 text-xs text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-emerald-500/60 focus:ring-2 focus:ring-emerald-500/20 transition-all shadow-inner"
            />
            {searchQuery && (
              <button
                onClick={() => setSearchQuery("")}
                className="absolute right-3.5 top-1/2 -translate-y-1/2 text-[10px] font-mono text-zinc-500 hover:text-zinc-300 bg-zinc-800/50 px-2 py-1 rounded-lg"
              >
                Clear
              </button>
            )}
          </div>

          <div className="flex items-center gap-2.5 overflow-x-auto pb-1 md:pb-0">
            {/* Filter Buttons */}
            <div className="flex items-center bg-[#0b0f19] border border-zinc-800/80 p-1 rounded-2xl">
              <FilterButton
                active={activeFilter === "all"}
                onClick={() => setActiveFilter("all")}
              >
                Semua
              </FilterButton>
              <FilterButton
                active={activeFilter === "page"}
                onClick={() => setActiveFilter("page")}
              >
                Pages
              </FilterButton>
              <FilterButton
                active={activeFilter === "js"}
                onClick={() => setActiveFilter("js")}
              >
                JS
              </FilterButton>
              <FilterButton
                active={activeFilter === "endpoint"}
                onClick={() => setActiveFilter("endpoint")}
              >
                API
              </FilterButton>
            </div>
            <button
              onClick={() => {
                if (sortBy === "default") setSortBy("type");
                else if (sortBy === "type") setSortBy("label");
                else setSortBy("default");
              }}
              className="flex items-center gap-2 bg-[#0b0f19] hover:bg-zinc-900 border border-zinc-800/80 px-4 py-3 rounded-2xl text-xs font-mono font-medium text-zinc-300 transition-colors shadow-sm shrink-0"
            >
              <ArrowUpDown className="w-3.5 h-3.5 text-emerald-400" />
              Sort:{" "}
              <span className="text-emerald-400 uppercase font-bold">
                {sortBy}
              </span>
            </button>
          </div>
        </div>

        {/* State Error Banner */}
        {error && (
          <div className="p-4 text-xs text-red-400 bg-red-950/30 rounded-2xl border border-red-900/50 flex items-center gap-3 animate-shake">
            <AlertCircle className="w-5 h-5 text-red-500 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {/* Grid Kartu Nodes dengan Transisi Halus */}
        {loading ? (
          <div className="flex flex-col items-center justify-center p-24 bg-[#0b0f19]/40 border border-zinc-800/80 rounded-3xl text-center space-y-4">
            <div className="relative">
              <div className="w-12 h-12 border-4 border-emerald-500/20 border-t-emerald-500 rounded-full animate-spin" />
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="w-3 h-3 bg-emerald-400 rounded-full animate-ping" />
              </div>
            </div>
            <p className="text-xs text-zinc-400 font-mono tracking-wider animate-pulse">
              Memuat struktur node graph keamanan sistem...
            </p>
          </div>
        ) : filteredNodes.length === 0 ? (
          <div className="flex flex-col items-center justify-center p-20 bg-[#0b0f19]/40 border border-zinc-800/80 rounded-3xl text-center space-y-3">
            <div className="p-4 rounded-2xl bg-zinc-900 border border-zinc-800 text-zinc-500">
              <AlertCircle className="w-8 h-8" />
            </div>
            <p className="text-xs text-zinc-300 font-mono font-medium">
              Tidak ada node yang ditemukan atau sesuai dengan filter aktif.
            </p>
            <button
              onClick={() => {
                setSearchQuery("");
                setActiveFilter("all");
              }}
              className="text-xs font-mono text-emerald-400 hover:underline pt-1"
            >
              Reset Filter & Pencarian
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4.5">
            {filteredNodes.map((node, index) => {
              const isSelected = selectedId === node.id;
              const isPage = node.type === "page";
              const isEndpoint = node.type === "endpoint";

              return (
                <div
                  key={node.id || index}
                  onClick={() => setSelectedId(isSelected ? null : node.id)}
                  className={`group relative flex flex-col justify-between p-5 rounded-3xl border transition-all duration-300 cursor-pointer backdrop-blur-xl shadow-xl hover:-translate-y-1 ${
                    isSelected
                      ? "bg-gradient-to-br from-[#111827] to-[#0d1322] border-emerald-500/80 shadow-emerald-950/50 ring-2 ring-emerald-500/30 scale-[1.01]"
                      : "bg-[#0b0f19]/70 hover:bg-[#111827]/80 border-zinc-800/80 hover:border-zinc-700/80 hover:shadow-2xl"
                  }`}
                >
                  <div>
                    <div className="flex items-center justify-between mb-4">
                      <div
                        className={`p-2.5 rounded-2xl border transition-colors ${
                          isPage
                            ? "bg-emerald-950/40 border-emerald-900/60 text-emerald-400 group-hover:bg-emerald-900/50"
                            : isEndpoint
                              ? "bg-rose-950/40 border-rose-900/60 text-rose-400 group-hover:bg-rose-900/50"
                              : "bg-blue-950/40 border-blue-900/60 text-blue-400 group-hover:bg-blue-900/50"
                        }`}
                      >
                        {isPage ? (
                          <Globe className="w-4 h-4" />
                        ) : isEndpoint ? (
                          <ShieldCheck className="w-4 h-4" />
                        ) : (
                          <FileCode className="w-4 h-4" />
                        )}
                      </div>
                      <span
                        className={`text-[10px] font-mono tracking-wider px-3 py-1 rounded-lg border uppercase font-semibold ${
                          isPage
                            ? "bg-emerald-950/20 border-emerald-900/40 text-emerald-400"
                            : isEndpoint
                              ? "bg-rose-950/20 border-rose-900/40 text-rose-400"
                              : "bg-blue-950/20 border-blue-900/40 text-blue-400"
                        }`}
                      >
                        {node.type?.toUpperCase() || "NODE"}
                      </span>
                    </div>

                    <div className="space-y-2 my-1">
                      <h4 className="text-[11px] font-mono font-bold tracking-wider text-emerald-400/90 uppercase truncate">
                        {isPage
                          ? "ROOT_DOMAIN"
                          : isEndpoint
                            ? "API_ENDPOINT"
                            : `BUNDLE_${node.label?.split("/").pop()?.slice(0, 8) || index}`}
                      </h4>
                      <p className="text-xs font-mono text-zinc-200 break-all line-clamp-3 leading-relaxed group-hover:text-zinc-100 transition-colors">
                        {node.label || node.id}
                      </p>
                    </div>
                  </div>

                  <div className="pt-4 mt-4 border-t border-zinc-800/60 flex items-center justify-between text-[11px] text-zinc-500 font-mono">
                    <span className="flex items-center gap-1.5 text-zinc-400">
                      {isPage ? (
                        <>
                          <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />{" "}
                          URL Utama Sistem
                        </>
                      ) : isEndpoint ? (
                        <>
                          <AlertCircle className="w-3.5 h-3.5 text-rose-400" />{" "}
                          Discovered Route
                        </>
                      ) : (
                        <>
                          <Clock className="w-3.5 h-3.5 text-blue-400" />{" "}
                          Verified Chunk
                        </>
                      )}
                    </span>
                    {isPage && (
                      <span className="text-[10px] bg-zinc-900/90 px-2.5 py-0.5 rounded-lg border border-zinc-800 text-zinc-400">
                        Depth: {node.depth ?? 0}
                      </span>
                    )}
                  </div>
                  {isSelected && (
                    <div className="absolute inset-x-0 bottom-0 h-1 bg-gradient-to-r from-emerald-500 via-emerald-300 to-transparent rounded-b-3xl shadow-[0_0_15px_rgba(16,185,129,0.8)]" />
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function StatBox({
  icon,
  label,
  value,
  colorBorder,
}: {
  icon: React.ReactNode;
  label: string;
  value: number;
  colorBorder: string;
}) {
  return (
    <div
      className={`group flex items-center gap-3.5 bg-[#070a12]/80 border border-zinc-800/80 px-4 py-3.5 rounded-2xl shadow-inner transition-all duration-300 hover:bg-[#111827]/90 ${colorBorder}`}
    >
      <div className="p-2.5 rounded-xl bg-zinc-900/90 border border-zinc-800/80 shadow-sm group-hover:scale-110 transition-transform">
        {icon}
      </div>
      <div>
        <div className="text-[10px] font-mono text-zinc-400 tracking-wider uppercase">
          {label}
        </div>
        <div className="text-lg font-bold font-mono text-zinc-100 group-hover:text-emerald-400 transition-colors">
          {value}
        </div>
      </div>
    </div>
  );
}

function FilterButton({
  children,
  active,
  onClick,
}: {
  children: React.ReactNode;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={`px-3.5 py-2 rounded-xl text-xs font-mono transition-all ${
        active
          ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 shadow-sm font-semibold"
          : "text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/60 border border-transparent"
      }`}
    >
      {children}
    </button>
  );
}
