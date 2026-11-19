/**
 * Audit dependensi: parse lockfile → cocokkan ke OSV.dev (agregator GitHub Advisory,
 * PyPA, RustSec, Go vulndb, NVD). Hanya nama paket + versi yang dikirim ke OSV;
 * kode sumber tidak pernah meninggalkan server.
 */
import type { Severity } from "@/lib/types";
import { cvss3Score, sevFromScore } from "@/lib/vuln/cve-intel";
import type { DependencyVuln, VulnerableDependency } from "./types";

export type Ecosystem = "npm" | "PyPI" | "Packagist" | "Go" | "RubyGems" | "crates.io";

export interface Dep {
  name: string;
  version: string;
  ecosystem: Ecosystem;
  source: string;
}

const MAX_DEPS = 1500;
const MAX_VULN_DETAILS = 80;
const TIMEOUT = 9000;
const UA = "Sentinel-ID Source-Audit/1.0 (+https://www.sentinel-id.net)";
const VERSION = /^v?\d+(\.\d+){0,3}([-.+][\w.]+)?$/;

function clean(v: string): string {
  return v.trim().replace(/^[v=]/, "");
}

export function parseLockfiles(files: { path: string; text: string }[]): Dep[] {
  const out = new Map<string, Dep>();
  const add = (d: Dep) => {
    const version = clean(d.version);
    if (!d.name || !VERSION.test(version)) return;
    const key = `${d.ecosystem}:${d.name}@${version}`;
    if (!out.has(key) && out.size < MAX_DEPS) out.set(key, { ...d, version });
  };

  for (const { path, text } of files) {
    const base = path.split("/").pop()!.toLowerCase();
    try {
      if (base === "package-lock.json" || base === "npm-shrinkwrap.json") {
        const j = JSON.parse(text);
        if (j.packages) {
          for (const [k, v] of Object.entries<{ version?: string; name?: string; link?: boolean }>(j.packages)) {
            if (!k || v.link || !v.version) continue;
            const name = v.name ?? k.slice(k.lastIndexOf("node_modules/") + 13);
            add({ name, version: v.version, ecosystem: "npm", source: path });
          }
        } else if (j.dependencies) {
          const walk = (deps: Record<string, { version?: string; dependencies?: object }>) => {
            for (const [name, v] of Object.entries(deps)) {
              if (v.version) add({ name, version: v.version, ecosystem: "npm", source: path });
              if (v.dependencies) walk(v.dependencies as Record<string, { version?: string }>);
            }
          };
          walk(j.dependencies);
        }
      } else if (base === "yarn.lock") {
        const re = /^"?(@?[^@\s"]+)@[^\n]*:\n\s+version:?\s+"?([^"\n]+)"?/gm;
        for (const m of text.matchAll(re)) add({ name: m[1], version: m[2], ecosystem: "npm", source: path });
      } else if (base === "pnpm-lock.yaml") {
        const re = /^\s{2}['"]?\/?(@?[^@\s'"(]+)@(\d[^:'"(\s]*)/gm;
        for (const m of text.matchAll(re)) add({ name: m[1], version: m[2], ecosystem: "npm", source: path });
      } else if (base === "requirements.txt" || /requirements[-\w]*\.txt$/.test(base)) {
        for (const m of text.matchAll(/^\s*([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*==\s*([\w.\-+]+)/gm))
          add({ name: m[1].toLowerCase(), version: m[3], ecosystem: "PyPI", source: path });
      } else if (base === "poetry.lock") {
        for (const m of text.matchAll(/\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"/g))
          add({ name: m[1].toLowerCase(), version: m[2], ecosystem: "PyPI", source: path });
      } else if (base === "pipfile.lock") {
        const j = JSON.parse(text);
        for (const sect of ["default", "develop"])
          for (const [name, v] of Object.entries<{ version?: string }>(j[sect] ?? {}))
            if (v.version) add({ name: name.toLowerCase(), version: v.version.replace(/^==/, ""), ecosystem: "PyPI", source: path });
      } else if (base === "composer.lock") {
        const j = JSON.parse(text);
        for (const p of [...(j.packages ?? []), ...(j["packages-dev"] ?? [])])
          if (p.name && p.version) add({ name: p.name, version: p.version, ecosystem: "Packagist", source: path });
      } else if (base === "go.sum") {
        for (const m of text.matchAll(/^(\S+)\s+(v[\w.\-+]+?)(\/go\.mod)?\s+h1:/gm))
          add({ name: m[1], version: m[2].replace(/\+incompatible$/, ""), ecosystem: "Go", source: path });
      } else if (base === "gemfile.lock") {
        for (const m of text.matchAll(/^ {4}([a-zA-Z0-9_.\-]+) \(([\d.]+)\)$/gm))
          add({ name: m[1], version: m[2], ecosystem: "RubyGems", source: path });
      } else if (base === "cargo.lock") {
        for (const m of text.matchAll(/\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"\s*\nsource\s*=\s*"registry/g))
          add({ name: m[1], version: m[2], ecosystem: "crates.io", source: path });
      }
    } catch {
      /* lockfile rusak: lewati */
    }
  }
  return Array.from(out.values());
}

async function postJson<T>(url: string, body: unknown): Promise<T> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": UA },
      body: JSON.stringify(body),
      signal: ctrl.signal,
    });
    if (!res.ok) throw new Error(`OSV HTTP ${res.status}`);
    return (await res.json()) as T;
  } finally {
    clearTimeout(t);
  }
}

async function getJson<T>(url: string): Promise<T | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT);
  try {
    const res = await fetch(url, { headers: { "User-Agent": UA }, signal: ctrl.signal });
    return res.ok ? ((await res.json()) as T) : null;
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

interface OsvVuln {
  id: string;
  aliases?: string[];
  summary?: string;
  details?: string;
  severity?: { type: string; score: string }[];
  database_specific?: { severity?: string };
  affected?: { package?: { name?: string; ecosystem?: string }; ranges?: { events?: { introduced?: string; fixed?: string }[] }[] }[];
}

function osvSeverity(v: OsvVuln): { severity: Severity; cvss?: number } {
  for (const s of v.severity ?? []) {
    if (s.type === "CVSS_V3") {
      const score = cvss3Score(s.score);
      if (score !== undefined) return { severity: sevFromScore(score), cvss: score };
    }
  }
  const db = (v.database_specific?.severity ?? "").toUpperCase();
  if (db === "CRITICAL") return { severity: "CRITICAL" };
  if (db === "HIGH") return { severity: "HIGH" };
  if (db === "MODERATE" || db === "MEDIUM") return { severity: "MEDIUM" };
  if (db === "LOW") return { severity: "LOW" };
  return { severity: "MEDIUM" };
}

function fixedVersion(v: OsvVuln, dep: Dep): string | undefined {
  for (const a of v.affected ?? []) {
    if (a.package?.name && a.package.name.toLowerCase() !== dep.name.toLowerCase()) continue;
    for (const r of a.ranges ?? []) for (const e of r.events ?? []) if (e.fixed) return e.fixed;
  }
  return undefined;
}

export async function auditDependencies(deps: Dep[]): Promise<{ vulnerable: VulnerableDependency[]; error?: string }> {
  if (deps.length === 0) return { vulnerable: [] };
  try {
    const hits: { dep: Dep; ids: string[] }[] = [];
    for (let i = 0; i < deps.length; i += 500) {
      const chunk = deps.slice(i, i + 500);
      const r = await postJson<{ results: { vulns?: { id: string }[] }[] }>("https://api.osv.dev/v1/querybatch", {
        queries: chunk.map((d) => ({ package: { name: d.name, ecosystem: d.ecosystem }, version: d.version })),
      });
      r.results.forEach((res, idx) => {
        const ids = (res.vulns ?? []).map((v) => v.id);
        if (ids.length) hits.push({ dep: chunk[idx], ids });
      });
    }

    // Detail kerentanan (severity, ringkasan, versi perbaikan), dibatasi & paralel 8.
    const uniqueIds = Array.from(new Set(hits.flatMap((h) => h.ids))).slice(0, MAX_VULN_DETAILS);
    const details = new Map<string, OsvVuln>();
    for (let i = 0; i < uniqueIds.length; i += 8) {
      const batch = await Promise.all(uniqueIds.slice(i, i + 8).map((id) => getJson<OsvVuln>(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`)));
      batch.forEach((v) => v && details.set(v.id, v));
    }

    const vulnerable: VulnerableDependency[] = hits.map(({ dep, ids }) => {
      const vulns: DependencyVuln[] = ids.map((id) => {
        const v = details.get(id);
        const sev = v ? osvSeverity(v) : { severity: "MEDIUM" as Severity };
        return {
          id,
          aliases: v?.aliases ?? [],
          summary: (v?.summary || v?.details || "Detail tersedia di OSV.dev").replace(/\s+/g, " ").slice(0, 240),
          severity: sev.severity,
          cvss: sev.cvss,
          fixed: v ? fixedVersion(v, dep) : undefined,
          url: `https://osv.dev/vulnerability/${encodeURIComponent(id)}`,
        };
      });
      return { ...dep, vulns };
    });
    const rank: Record<Severity, number> = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0 };
    vulnerable.sort(
      (a, b) => Math.max(...b.vulns.map((v) => rank[v.severity])) - Math.max(...a.vulns.map((v) => rank[v.severity]))
    );
    return { vulnerable };
  } catch (e) {
    return { vulnerable: [], error: `Database OSV tidak dapat dihubungi (${(e as Error).message}). Hasil dependensi tidak lengkap.` };
  }
}
