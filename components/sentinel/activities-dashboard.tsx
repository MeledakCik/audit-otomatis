"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import {
  Activity,
  Users,
  Radar,
  ShieldAlert,
  Lock,
  KeyRound,
  Search,
  RefreshCw,
  ExternalLink,
  Clock,
  Globe,
  Monitor,
  Eye,
  X,
  FileJson,
  GitBranch,
  Copy,
  Check,
  Download,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { UserActivityRecord, UserProfileSummary } from "@/lib/activity-store";
import type { GitIntelReport } from "@/lib/sentinel/git-intel";

interface AdminStats {
  totalActivities: number;
  uniqueUsers: number;
  totalScans: number;
  totalQcs: number;
  vaultItemsCount: number;
  pendingClaimsCount: number;
  totalClaimsCount: number;
  criticalEventsCount: number;
}

interface ScanItem {
  id: string;
  domain: string;
  origin: string;
  createdAt: number;
  status: string;
  pagesCount: number;
  findingsCount: number;
  severityCounts: Record<string, number>;
}

interface QcItem {
  id: string;
  domain: string;
  createdAt: number;
  status: string;
  overallScore?: number;
  requestsMade: number;
}

function fmtDate(ts: number): string {
  try {
    return new Date(ts).toLocaleString("id-ID", {
      day: "2-digit",
      month: "short",
      year: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return String(ts);
  }
}

function relTime(ts: number): string {
  const sec = Math.max(0, Math.floor((Date.now() - ts) / 1000));
  if (sec < 10) return "baru saja";
  if (sec < 60) return `${sec}d lalu`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m lalu`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}j lalu`;
  return `${Math.floor(hr / 24)}h lalu`;
}

function parseGitIntelFromActivity(act: UserActivityRecord): GitIntelReport | null {
  const raw = act.meta?.gitIntelJson;
  if (!raw || typeof raw !== "string") return null;
  try {
    return JSON.parse(raw) as GitIntelReport;
  } catch {
    return null;
  }
}

const STATUS_BADGE: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-300 border-red-500/40",
  WARNING: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  SUCCESS: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
  RUNNING: "bg-purple-500/20 text-purple-300 border-purple-500/40",
  BLOCKED: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  ERROR: "bg-rose-500/20 text-rose-300 border-rose-500/40",
};

export function ActivitiesDashboard() {
  const [loading, setLoading] = useState(true);
  const [stats, setStats] = useState<AdminStats | null>(null);
  const [activities, setActivities] = useState<UserActivityRecord[]>([]);
  const [users, setUsers] = useState<UserProfileSummary[]>([]);
  const [scans, setScans] = useState<ScanItem[]>([]);
  const [qcs, setQcs] = useState<QcItem[]>([]);
  const [subTab, setSubTab] = useState<"feed" | "gitjson" | "users" | "scans">("feed");

  const [search, setSearch] = useState("");
  const [moduleFilter, setModuleFilter] = useState("ALL");
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [selectedActivity, setSelectedActivity] = useState<UserActivityRecord | null>(null);
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const r = await fetch("/api/admin/activities");
      if (r.status === 401) {
        window.location.href = "/admin/login";
        return;
      }
      const data = await r.json();
      if (data.ok) {
        setStats(data.stats);
        setActivities(data.activities ?? []);
        setUsers(data.users ?? []);
        setScans(data.scans ?? []);
        setQcs(data.qcs ?? []);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    load();
    const t = setInterval(load, 15000);
    return () => clearInterval(t);
  }, [load]);

  function copyJson(id: string, payload: unknown) {
    try {
      const str = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
      navigator.clipboard.writeText(str);
      setCopiedId(id);
      setTimeout(() => setCopiedId(null), 2000);
    } catch {
      // ignore
    }
  }

  function downloadJson(filename: string, payload: unknown) {
    const str = typeof payload === "string" ? payload : JSON.stringify(payload, null, 2);
    const blob = new Blob([str], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  const uniqueModules = useMemo(() => {
    const map = new Map<string, string>();
    for (const a of activities) map.set(a.module, a.moduleLabel);
    return Array.from(map.entries());
  }, [activities]);

  const filteredActivities = useMemo(() => {
    const q = search.trim().toLowerCase();
    return activities.filter((a) => {
      if (moduleFilter !== "ALL" && a.module !== moduleFilter) return false;
      if (statusFilter !== "ALL" && a.status !== statusFilter) return false;
      if (!q) return true;
      const repoUrl = String(a.meta?.gitRepoUrl ?? "").toLowerCase();
      return (
        a.target.toLowerCase().includes(q) ||
        a.action.toLowerCase().includes(q) ||
        a.summary.toLowerCase().includes(q) ||
        a.ip.toLowerCase().includes(q) ||
        a.userId.toLowerCase().includes(q) ||
        a.moduleLabel.toLowerCase().includes(q) ||
        repoUrl.includes(q)
      );
    });
  }, [activities, search, moduleFilter, statusFilter]);

  const gitActivities = useMemo(() => {
    return filteredActivities.filter(
      (a) => Boolean(a.meta?.gitExposed) || Boolean(a.meta?.gitRepoUrl) || Boolean(a.meta?.gitIntelJson)
    );
  }, [filteredActivities]);

  const filteredUsers = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return users;
    return users.filter(
      (u) =>
        u.ip.toLowerCase().includes(q) ||
        u.userId.toLowerCase().includes(q) ||
        u.userAgent.toLowerCase().includes(q) ||
        u.domainsTargeted.some((d) => d.toLowerCase().includes(q))
    );
  }, [users, search]);

  return (
    <div className="space-y-6">
      {/* KPI Overview Row */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          {
            label: "Total Aktivitas",
            val: stats?.totalActivities ?? 0,
            sub: "Semua modul",
            icon: Activity,
            accent: "text-purple-400",
          },
          {
            label: "Data User Unik",
            val: stats?.uniqueUsers ?? 0,
            sub: "Berdasarkan UID/IP",
            icon: Users,
            accent: "text-sky-400",
          },
          {
            label: "Full Scan & QC",
            val: (stats?.totalScans ?? 0) + (stats?.totalQcs ?? 0),
            sub: `${stats?.totalScans ?? 0} Scan · ${stats?.totalQcs ?? 0} QC`,
            icon: Radar,
            accent: "text-emerald-400",
          },
          {
            label: "Event Critical",
            val: stats?.criticalEventsCount ?? 0,
            sub: "Eksposur kritis & Git",
            icon: ShieldAlert,
            accent: "text-red-400",
          },
          {
            label: "Item di Vault",
            val: stats?.vaultItemsCount ?? 0,
            sub: "AES-256-GCM",
            icon: Lock,
            accent: "text-pink-400",
          },
          {
            label: "Klaim Domain",
            val: stats?.pendingClaimsCount ?? 0,
            sub: `${stats?.totalClaimsCount ?? 0} total klaim`,
            icon: KeyRound,
            accent: "text-amber-400",
          },
        ].map((k) => {
          const Icon = k.icon;
          return (
            <div
              key={k.label}
              className="rounded-2xl border border-white/[0.08] bg-gradient-to-b from-[#161025] to-[#110c1c] p-4 flex flex-col justify-between"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-[11px] font-mono uppercase tracking-wider text-slate-400">
                  {k.label}
                </span>
                <Icon className={cn("h-4 w-4 shrink-0", k.accent)} />
              </div>
              <div className="mt-2">
                <div className="text-2xl font-extrabold text-white tabular-nums">{k.val}</div>
                <div className="text-[11px] font-mono text-slate-400 mt-0.5">{k.sub}</div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Sub-navigation & Filters Bar */}
      <div className="rounded-2xl border border-white/10 bg-[#120d1d] p-4 space-y-4">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => setSubTab("feed")}
              className={cn(
                "inline-flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-mono font-bold transition-all cursor-pointer",
                subTab === "feed"
                  ? "bg-purple-600 text-white shadow-md shadow-purple-600/25"
                  : "border border-white/10 bg-white/[0.03] text-slate-300 hover:text-white"
              )}
            >
              <Activity className="h-3.5 w-3.5" />
              <span>Log Semua Aktivitas ({activities.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setSubTab("gitjson")}
              className={cn(
                "inline-flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-mono font-bold transition-all cursor-pointer",
                subTab === "gitjson"
                  ? "bg-gradient-to-r from-purple-600 to-pink-600 text-white shadow-md shadow-pink-600/25"
                  : "border border-pink-500/35 bg-pink-500/10 text-pink-200 hover:bg-pink-500/20"
              )}
            >
              <FileJson className="h-3.5 w-3.5" />
              <span>Git &amp; Repo Intel (JSON View)</span>
              {gitActivities.length > 0 && (
                <span className="rounded-full bg-red-500 px-1.5 py-0.2 text-[10px] text-white font-extrabold">
                  {gitActivities.length}
                </span>
              )}
            </button>

            <button
              type="button"
              onClick={() => setSubTab("users")}
              className={cn(
                "inline-flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-mono font-bold transition-all cursor-pointer",
                subTab === "users"
                  ? "bg-purple-600 text-white shadow-md shadow-purple-600/25"
                  : "border border-white/10 bg-white/[0.03] text-slate-300 hover:text-white"
              )}
            >
              <Users className="h-3.5 w-3.5" />
              <span>Data &amp; Profil User ({users.length})</span>
            </button>

            <button
              type="button"
              onClick={() => setSubTab("scans")}
              className={cn(
                "inline-flex items-center gap-2 rounded-xl px-4 py-2 text-xs font-mono font-bold transition-all cursor-pointer",
                subTab === "scans"
                  ? "bg-purple-600 text-white shadow-md shadow-purple-600/25"
                  : "border border-white/10 bg-white/[0.03] text-slate-300 hover:text-white"
              )}
            >
              <Radar className="h-3.5 w-3.5" />
              <span>Semua Sesi Scan &amp; QC ({scans.length + qcs.length})</span>
            </button>
          </div>

          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => downloadJson(`sentinel-admin-telemetry-${Date.now()}.json`, { stats, activities: filteredActivities, users })}
              className="inline-flex items-center gap-1.5 rounded-xl border border-emerald-500/30 bg-emerald-500/10 hover:bg-emerald-500/20 px-3.5 py-2 text-xs font-mono text-emerald-300 cursor-pointer"
            >
              <Download className="h-3.5 w-3.5" />
              <span>Export JSON</span>
            </button>
            <button
              type="button"
              onClick={load}
              className="inline-flex items-center gap-1.5 rounded-xl border border-white/10 bg-white/[0.04] hover:bg-white/[0.08] px-3.5 py-2 text-xs font-mono text-slate-200 cursor-pointer"
            >
              <RefreshCw className={cn("h-3.5 w-3.5", loading && "animate-spin")} />
              <span>Refresh</span>
            </button>
          </div>
        </div>

        {/* Search & Filters */}
        <div className="flex flex-col sm:flex-row gap-2.5">
          <div className="relative flex-1">
            <Search className="h-4 w-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2 pointer-events-none" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Cari domain target, URL GitHub/GitLab, IP address, User ID, atau jenis aktivitas..."
              className="w-full h-10 rounded-xl border border-white/10 bg-black/40 pl-10 pr-4 text-xs font-mono text-white placeholder:text-slate-500 outline-none focus:border-purple-400"
            />
          </div>

          {(subTab === "feed" || subTab === "gitjson") && (
            <>
              <select
                value={moduleFilter}
                onChange={(e) => setModuleFilter(e.target.value)}
                aria-label="Filter modul"
                className="h-10 rounded-xl border border-white/10 bg-black/40 px-3 text-xs font-mono text-slate-200 outline-none focus:border-purple-400"
              >
                <option value="ALL">Semua Modul ({activities.length})</option>
                {uniqueModules.map(([mod, label]) => (
                  <option key={mod} value={mod}>
                    {label}
                  </option>
                ))}
              </select>

              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                aria-label="Filter status"
                className="h-10 rounded-xl border border-white/10 bg-black/40 px-3 text-xs font-mono text-slate-200 outline-none focus:border-purple-400"
              >
                <option value="ALL">Semua Status</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="WARNING">WARNING</option>
                <option value="SUCCESS">SUCCESS</option>
                <option value="RUNNING">RUNNING</option>
                <option value="BLOCKED">BLOCKED</option>
                <option value="ERROR">ERROR</option>
              </select>
            </>
          )}
        </div>
      </div>

      {/* SubTab 1: Live User Activity Feed */}
      {subTab === "feed" && (
        <div className="rounded-2xl border border-white/10 bg-[#120d1d] overflow-hidden shadow-xl">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="border-b border-white/10 bg-black/30 font-mono uppercase text-[11px] text-slate-400">
                <tr>
                  <th className="p-3.5">Waktu</th>
                  <th className="p-3.5">User (UID / IP)</th>
                  <th className="p-3.5">Modul Fitur</th>
                  <th className="p-3.5">Target Domain</th>
                  <th className="p-3.5">Aktivitas, Ringkasan &amp; Git Repo</th>
                  <th className="p-3.5">Status</th>
                  <th className="p-3.5 text-right">JSON / Detail</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-white/[0.06]">
                {filteredActivities.map((act) => {
                  const repoUrl = typeof act.meta?.gitRepoUrl === "string" ? act.meta.gitRepoUrl : null;
                  const repoProvider = typeof act.meta?.gitProvider === "string" ? act.meta.gitProvider : null;
                  return (
                    <tr key={act.id} className="hover:bg-white/[0.03] transition-colors">
                      <td className="p-3.5 whitespace-nowrap font-mono">
                        <div className="text-white font-semibold">{relTime(act.timestamp)}</div>
                        <div className="text-[10px] text-slate-400">{fmtDate(act.timestamp)}</div>
                      </td>
                      <td className="p-3.5 font-mono">
                        <div className="text-purple-300 font-semibold">{act.userId}</div>
                        <div className="text-[11px] text-slate-400">{act.ip}</div>
                      </td>
                      <td className="p-3.5 whitespace-nowrap">
                        <span className="inline-flex items-center rounded-lg border border-purple-500/30 bg-purple-500/10 px-2.5 py-1 font-mono text-[11px] font-semibold text-purple-200">
                          {act.moduleLabel}
                        </span>
                      </td>
                      <td className="p-3.5 font-mono font-bold text-white max-w-[180px] truncate">
                        {act.target}
                      </td>
                      <td className="p-3.5 max-w-md space-y-1">
                        <div className="font-semibold text-slate-200">{act.action}</div>
                        <div className="text-slate-400 text-[11px] truncate">{act.summary}</div>
                        {repoUrl && (
                          <div className="pt-0.5 flex flex-wrap items-center gap-1.5">
                            <a
                              href={repoUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="inline-flex items-center gap-1 rounded-md bg-emerald-500/15 border border-emerald-500/35 px-2 py-0.5 font-mono text-[10px] font-bold text-emerald-300 hover:bg-emerald-500/25"
                            >
                              <GitBranch className="h-3 w-3" />
                              <span>{repoProvider?.toUpperCase() || "GIT"}: {repoUrl}</span>
                              <ExternalLink className="h-2.5 w-2.5" />
                            </a>
                          </div>
                        )}
                      </td>
                      <td className="p-3.5 whitespace-nowrap">
                        <span
                          className={cn(
                            "inline-flex items-center rounded-full border px-2.5 py-0.5 font-mono text-[10px] font-bold uppercase",
                            STATUS_BADGE[act.status] ?? STATUS_BADGE.SUCCESS
                          )}
                        >
                          {act.status}
                        </span>
                      </td>
                      <td className="p-3.5 text-right whitespace-nowrap space-x-1.5">
                        {act.meta?.scanId && act.module === "FULL_SCAN" && (
                          <Link
                            href={`/scan/${act.meta.scanId}`}
                            className="inline-flex items-center gap-1 rounded-lg border border-emerald-500/30 bg-emerald-500/10 hover:bg-emerald-500/20 px-2.5 py-1 font-mono text-[11px] text-emerald-300"
                          >
                            <span>Scan</span>
                            <ExternalLink className="h-3 w-3" />
                          </Link>
                        )}
                        <button
                          type="button"
                          onClick={() => setSelectedActivity(act)}
                          className="inline-flex items-center gap-1 rounded-lg border border-purple-500/30 bg-purple-500/15 hover:bg-purple-500/25 px-2.5 py-1 font-mono text-[11px] font-semibold text-purple-200 cursor-pointer"
                        >
                          <FileJson className="h-3 w-3" />
                          <span>JSON</span>
                        </button>
                      </td>
                    </tr>
                  );
                })}
                {filteredActivities.length === 0 && (
                  <tr>
                    <td colSpan={7} className="p-10 text-center font-mono text-slate-400">
                      {loading
                        ? "Memuat data aktivitas user..."
                        : "Belum ada aktivitas user yang cocok dengan filter."}
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* SubTab 2: Dedicated Git & Repository Intelligence JSON View */}
      {subTab === "gitjson" && (
        <div className="space-y-4">
          <div className="rounded-2xl border border-pink-500/30 bg-gradient-to-r from-[#181028] via-[#130d20] to-[#0e0a18] p-5 flex flex-wrap items-center justify-between gap-4">
            <div className="space-y-1">
              <div className="inline-flex items-center gap-1.5 rounded-full bg-pink-500/15 border border-pink-500/30 px-2.5 py-0.5 text-[10px] font-mono font-bold text-pink-300">
                <GitBranch className="h-3 w-3" />
                PASSIVE GIT &amp; REPOSITORY INTELLIGENCE (JSON)
              </div>
              <h2 className="text-base sm:text-lg font-extrabold text-white">
                Hasil Ekstraksi <code className="text-pink-300">/.git/config</code>, <code className="text-pink-300">/logs/HEAD</code>, <code className="text-pink-300">/.git/refs/heads/main</code> &amp; URL Repo GitHub/GitLab
              </h2>
              <p className="text-xs text-slate-300">
                Menampilkan seluruh hasil tangkapan pasif metadata Git dan seluruh aktivitas user dalam format JSON terstruktur.
              </p>
            </div>
            <button
              type="button"
              onClick={() => copyJson("all_git_json", gitActivities.length > 0 ? gitActivities : filteredActivities)}
              className="inline-flex items-center gap-1.5 rounded-xl bg-purple-600 hover:bg-purple-500 px-4 py-2 text-xs font-mono font-bold text-white cursor-pointer"
            >
              {copiedId === "all_git_json" ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
              <span>{copiedId === "all_git_json" ? "JSON Tersalin!" : "Salin Semua JSON"}</span>
            </button>
          </div>

          {gitActivities.length > 0 ? (
            <div className="grid grid-cols-1 gap-4">
              {gitActivities.map((act) => {
                const gitIntel = parseGitIntelFromActivity(act);
                const jsonPayload = gitIntel ?? act;
                return (
                  <div
                    key={act.id}
                    className="rounded-2xl border border-white/10 bg-[#120d1d] p-5 space-y-4 shadow-xl"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 pb-3">
                      <div className="flex flex-wrap items-center gap-2.5">
                        <span className="font-mono text-sm font-extrabold text-white">{act.target}</span>
                        {gitIntel?.primaryRepository?.webUrl && (
                          <a
                            href={gitIntel.primaryRepository.webUrl}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-1.5 rounded-full bg-emerald-500/20 border border-emerald-500/40 px-3 py-0.5 font-mono text-xs font-bold text-emerald-300 hover:bg-emerald-500/30"
                          >
                            <GitBranch className="h-3.5 w-3.5" />
                            <span>
                              {gitIntel.primaryRepository.provider.toUpperCase()}: {gitIntel.primaryRepository.webUrl}
                            </span>
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        )}
                        {gitIntel?.head?.activeBranch && (
                          <span className="rounded-md bg-purple-500/20 border border-purple-500/30 px-2.5 py-0.5 font-mono text-xs text-purple-200">
                            branch: {gitIntel.head.activeBranch}
                          </span>
                        )}
                        {gitIntel?.commits?.latestSha && (
                          <span className="rounded-md bg-white/[0.05] border border-white/10 px-2.5 py-0.5 font-mono text-xs text-slate-300">
                            SHA: {gitIntel.commits.latestSha.slice(0, 12)}
                          </span>
                        )}
                      </div>

                      <div className="flex items-center gap-2">
                        <button
                          type="button"
                          onClick={() => copyJson(act.id, jsonPayload)}
                          className="inline-flex items-center gap-1 rounded-lg border border-white/15 bg-white/5 hover:bg-white/10 px-3 py-1 font-mono text-xs text-emerald-300 cursor-pointer"
                        >
                          {copiedId === act.id ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                          <span>{copiedId === act.id ? "Tersalin" : "Copy JSON"}</span>
                        </button>
                      </div>
                    </div>

                    <pre className="rounded-xl bg-[#08060e] border border-white/10 p-4 font-mono text-xs text-emerald-300 whitespace-pre-wrap break-all max-h-96 overflow-y-auto thin-scroll">
                      {JSON.stringify(jsonPayload, null, 2)}
                    </pre>
                  </div>
                );
              })}
            </div>
          ) : (
            <div className="rounded-2xl border border-white/10 bg-[#120d1d] p-5 space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs font-mono font-bold text-purple-300 uppercase">
                  Live JSON Dump — Seluruh Aktivitas User ({filteredActivities.length} records)
                </span>
                <button
                  type="button"
                  onClick={() => copyJson("raw_all", filteredActivities)}
                  className="inline-flex items-center gap-1 rounded-lg border border-white/15 bg-white/5 px-3 py-1 font-mono text-xs text-emerald-300 cursor-pointer"
                >
                  {copiedId === "raw_all" ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                  <span>{copiedId === "raw_all" ? "Tersalin" : "Copy JSON"}</span>
                </button>
              </div>
              <pre className="rounded-xl bg-[#08060e] border border-white/10 p-4 font-mono text-xs text-emerald-300 whitespace-pre-wrap break-all max-h-[65vh] overflow-y-auto thin-scroll">
                {JSON.stringify(filteredActivities, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* SubTab 3: User Profiles & Telemetry Directory */}
      {subTab === "users" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {filteredUsers.map((u) => (
            <div
              key={u.userKey}
              className="rounded-2xl border border-white/10 bg-gradient-to-b from-[#161025] to-[#110c1c] p-5 space-y-3.5 flex flex-col justify-between"
            >
              <div className="space-y-3">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm font-extrabold text-white">{u.userId}</span>
                      <span className="rounded-md bg-purple-500/20 border border-purple-500/30 px-2 py-0.5 font-mono text-[10px] text-purple-300">
                        IP: {u.ip}
                      </span>
                    </div>
                    <div className="mt-1 flex items-center gap-1.5 text-[11px] text-slate-400 font-mono">
                      <Monitor className="h-3.5 w-3.5 text-slate-500 shrink-0" />
                      <span className="truncate max-w-sm">{u.userAgent}</span>
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <div className="text-lg font-extrabold text-purple-300 tabular-nums">
                      {u.totalActivities} aksi
                    </div>
                    {u.criticalHits > 0 && (
                      <span className="inline-block rounded-full bg-red-500/20 border border-red-500/40 px-2 py-0.5 text-[10px] font-mono font-bold text-red-300">
                        {u.criticalHits} CRITICAL
                      </span>
                    )}
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="text-[11px] font-mono text-slate-400">
                    Domain / Target yang Diperiksa ({u.domainsTargeted.length}):
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {u.domainsTargeted.slice(0, 8).map((d) => (
                      <span
                        key={d}
                        className="inline-flex items-center gap-1 rounded-md bg-black/40 border border-white/10 px-2 py-0.5 font-mono text-[11px] text-slate-200"
                      >
                        <Globe className="h-3 w-3 text-purple-400" />
                        {d}
                      </span>
                    ))}
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="text-[11px] font-mono text-slate-400">
                    Modul yang Digunakan ({u.modulesUsed.length}):
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {u.modulesUsed.map((m) => (
                      <span
                        key={m}
                        className="rounded-md bg-purple-500/10 border border-purple-500/25 px-2 py-0.5 font-mono text-[10px] text-purple-200"
                      >
                        {m}
                      </span>
                    ))}
                  </div>
                </div>
              </div>

              <div className="pt-3 border-t border-white/[0.06] flex items-center justify-between text-[11px] font-mono text-slate-400">
                <span className="flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  Terakhir aktif: {relTime(u.lastActive)}
                </span>
                <button
                  type="button"
                  onClick={() => {
                    setSearch(u.userId);
                    setSubTab("feed");
                  }}
                  className="text-purple-300 hover:text-white underline cursor-pointer"
                >
                  Lihat Semua Log User Ini →
                </button>
              </div>
            </div>
          ))}

          {filteredUsers.length === 0 && (
            <div className="col-span-full rounded-2xl border border-white/10 bg-[#120d1d] p-10 text-center font-mono text-xs text-slate-400">
              Belum ada data profil user yang tercatat.
            </div>
          )}
        </div>
      )}

      {/* SubTab 4: All Full Scans & QC Runs */}
      {subTab === "scans" && (
        <div className="space-y-6">
          <div className="rounded-2xl border border-white/10 bg-[#120d1d] overflow-hidden">
            <div className="px-4 py-3 border-b border-white/10 flex items-center justify-between">
              <h2 className="text-sm font-bold text-white">
                Semua Sesi Full Passive Scan ({scans.length})
              </h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-white/10 bg-black/30 font-mono uppercase text-[11px] text-slate-400">
                  <tr>
                    <th className="p-3.5">Scan ID</th>
                    <th className="p-3.5">Domain</th>
                    <th className="p-3.5">Waktu</th>
                    <th className="p-3.5">Status</th>
                    <th className="p-3.5">Halaman</th>
                    <th className="p-3.5">Temuan (CRIT / HIGH / Total)</th>
                    <th className="p-3.5 text-right">Buka</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.06]">
                  {scans.map((s) => (
                    <tr key={s.id} className="hover:bg-white/[0.03]">
                      <td className="p-3.5 font-mono text-purple-300">{s.id}</td>
                      <td className="p-3.5 font-mono font-bold text-white">{s.domain}</td>
                      <td className="p-3.5 font-mono text-slate-400">{fmtDate(s.createdAt)}</td>
                      <td className="p-3.5 font-mono uppercase">{s.status}</td>
                      <td className="p-3.5 font-mono">{s.pagesCount}</td>
                      <td className="p-3.5 font-mono">
                        <span className="text-red-400 font-bold">{s.severityCounts?.CRITICAL ?? 0} CRIT</span>
                        {" · "}
                        <span className="text-amber-400 font-bold">{s.severityCounts?.HIGH ?? 0} HIGH</span>
                        {" · "}
                        <span className="text-slate-300">{s.findingsCount} total</span>
                      </td>
                      <td className="p-3.5 text-right space-x-2">
                        <Link
                          href={`/scan/${s.id}`}
                          className="inline-flex items-center gap-1 rounded-lg border border-purple-500/30 bg-purple-500/15 px-3 py-1 font-mono text-[11px] text-purple-200 hover:bg-purple-500/25"
                        >
                          <span>Dashboard</span>
                          <ExternalLink className="h-3 w-3" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                  {scans.length === 0 && (
                    <tr>
                      <td colSpan={7} className="p-8 text-center font-mono text-slate-400">
                        Belum ada sesi Full Scan.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className="rounded-2xl border border-white/10 bg-[#120d1d] overflow-hidden">
            <div className="px-4 py-3 border-b border-white/10 flex items-center justify-between">
              <h2 className="text-sm font-bold text-white">
                Semua Sesi QC Otomatis SEO/Perf/Content ({qcs.length})
              </h2>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="border-b border-white/10 bg-black/30 font-mono uppercase text-[11px] text-slate-400">
                  <tr>
                    <th className="p-3.5">QC ID</th>
                    <th className="p-3.5">Domain</th>
                    <th className="p-3.5">Waktu</th>
                    <th className="p-3.5">Status</th>
                    <th className="p-3.5">Skor Overall</th>
                    <th className="p-3.5 text-right">Buka</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-white/[0.06]">
                  {qcs.map((q) => (
                    <tr key={q.id} className="hover:bg-white/[0.03]">
                      <td className="p-3.5 font-mono text-purple-300">{q.id}</td>
                      <td className="p-3.5 font-mono font-bold text-white">{q.domain}</td>
                      <td className="p-3.5 font-mono text-slate-400">{fmtDate(q.createdAt)}</td>
                      <td className="p-3.5 font-mono uppercase">{q.status}</td>
                      <td className="p-3.5 font-mono font-bold text-emerald-400">
                        {q.overallScore ?? "—"}
                      </td>
                      <td className="p-3.5 text-right">
                        <Link
                          href={`/qc/${q.id}`}
                          className="inline-flex items-center gap-1 rounded-lg border border-purple-500/30 bg-purple-500/15 px-3 py-1 font-mono text-[11px] text-purple-200 hover:bg-purple-500/25"
                        >
                          <span>Buka QC</span>
                          <ExternalLink className="h-3 w-3" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                  {qcs.length === 0 && (
                    <tr>
                      <td colSpan={6} className="p-8 text-center font-mono text-slate-400">
                        Belum ada sesi QC Otomatis.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Activity & Git JSON Inspector Modal */}
      {selectedActivity && (
        <div
          role="dialog"
          aria-modal="true"
          className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-xs p-4"
          onClick={() => setSelectedActivity(null)}
        >
          <div
            className="w-full max-w-2xl max-h-[88vh] overflow-y-auto rounded-2xl border border-purple-500/35 bg-[#120d1e] p-6 text-slate-100 shadow-2xl space-y-4 thin-scroll"
            onClick={(e) => e.stopPropagation()}
          >
            <div className="flex items-start justify-between gap-3 border-b border-white/10 pb-3">
              <div>
                <div className="text-[11px] font-mono text-purple-300 uppercase">
                  JSON Inspector — Detail Aktivitas &amp; Git Intelligence
                </div>
                <h3 className="text-base font-extrabold text-white mt-0.5">
                  {selectedActivity.action} ({selectedActivity.target})
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setSelectedActivity(null)}
                className="h-8 w-8 grid place-items-center rounded-full bg-white/5 text-slate-400 hover:text-white"
              >
                <X className="h-4 w-4" />
              </button>
            </div>

            {typeof selectedActivity.meta?.gitRepoUrl === "string" && (
              <div className="rounded-xl border border-emerald-500/35 bg-emerald-500/10 p-3.5 flex flex-wrap items-center justify-between gap-2">
                <div className="text-xs font-mono">
                  <span className="text-emerald-300 font-bold block">
                    ✓ Repository GitHub / GitLab Teridentifikasi:
                  </span>
                  <a
                    href={selectedActivity.meta.gitRepoUrl}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-white underline font-bold break-all"
                  >
                    {selectedActivity.meta.gitRepoUrl}
                  </a>
                </div>
                <a
                  href={selectedActivity.meta.gitRepoUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 rounded-lg bg-emerald-600 px-3 py-1.5 text-xs font-mono font-bold text-white"
                >
                  <span>Buka Repo</span>
                  <ExternalLink className="h-3.5 w-3.5" />
                </a>
              </div>
            )}

            <div className="space-y-2">
              <div className="flex items-center justify-between text-xs font-mono text-slate-400">
                <span> OUTPUT JSON TERSTRUKTUR</span>
                <button
                  type="button"
                  onClick={() =>
                    copyJson(
                      "modal_json",
                      parseGitIntelFromActivity(selectedActivity) ?? selectedActivity
                    )
                  }
                  className="inline-flex items-center gap-1 text-emerald-400 hover:text-emerald-300 cursor-pointer"
                >
                  {copiedId === "modal_json" ? <Check className="h-3.5 w-3.5" /> : <Copy className="h-3.5 w-3.5" />}
                  <span>{copiedId === "modal_json" ? "Tersalin!" : "Salin JSON"}</span>
                </button>
              </div>
              <pre className="rounded-xl bg-[#08060e] border border-white/10 p-4 font-mono text-xs text-emerald-300 whitespace-pre-wrap break-all max-h-96 overflow-y-auto thin-scroll">
                {JSON.stringify(
                  parseGitIntelFromActivity(selectedActivity) ?? selectedActivity,
                  null,
                  2
                )}
              </pre>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              {selectedActivity.meta?.scanId && selectedActivity.module === "FULL_SCAN" && (
                <Link
                  href={`/scan/${selectedActivity.meta.scanId}`}
                  className="inline-flex items-center gap-1.5 rounded-xl bg-purple-600 px-4 py-2 text-xs font-bold text-white"
                >
                  <span>Buka Dashboard Scan</span>
                  <ExternalLink className="h-3.5 w-3.5" />
                </Link>
              )}
              <button
                type="button"
                onClick={() => setSelectedActivity(null)}
                className="rounded-xl border border-white/15 bg-white/5 px-4 py-2 text-xs font-semibold text-slate-200 hover:bg-white/10"
              >
                Tutup
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
