import type { MapCrawledPage } from "./crawl";
import type { ApiCallMatch } from "./extract-endpoints";
import type { AttackMapEdge, AttackMapNode, AttackMapNodeType, AttackMapReport, AttackMapStats } from "./types";

const MAX_NODES = 50;
const MAX_EDGES_PER_API = 3;
const ADMIN_PATH_RE = /\b(admin|dashboard|wp-admin|manage|internal|debug|config|superuser)\b/i;
const AUTH_INPUT_RE = /pass(word)?|token|secret/i;

export interface JsFinding {
  assetUrl: string;
  apiCalls: ApiCallMatch[];
}

interface BuildInput {
  origin: string;
  hostname: string;
  pages: MapCrawledPage[];
  jsFindings: JsFinding[];
  maxPages: number;
}

function pathOf(url: string): string {
  try {
    const u = new URL(url);
    return u.pathname || "/";
  } catch {
    return url;
  }
}

function deriveFormLabel(action: string, inputs: string[]): string {
  const hasAuthField = inputs.some((i) => AUTH_INPUT_RE.test(i));
  if (hasAuthField) return "Login/Auth Form";
  const path = pathOf(action);
  return path === "/" ? "Form" : `Form: ${path}`;
}

export function buildAttackMapGraph(input: BuildInput): AttackMapReport {
  const { origin, hostname, pages, jsFindings, maxPages } = input;

  const nodes = new Map<string, AttackMapNode>();
  const edges: AttackMapEdge[] = [];
  const edgeSeen = new Set<string>();

  function addNode(node: AttackMapNode) {
    if (!nodes.has(node.id)) nodes.set(node.id, node);
  }
  function addEdge(source: string, target: string, animated = false) {
    if (source === target) return;
    const key = `${source}->${target}`;
    if (edgeSeen.has(key)) return;
    edgeSeen.add(key);
    edges.push({ id: key, source, target, animated });
  }

  addNode({ id: "root", type: "ROOT", label: hostname, url: origin, depth: 0 });

  const sourceIdOf = (url: string) => (url === origin ? "root" : `page:${url}`);
  const assetToSources = new Map<string, Set<string>>();
  const apiAgg = new Map<
    string,
    { methods: Set<string>; sampleUrl: string; sourceIds: Set<string>; depth: number }
  >();

  function registerApi(pathname: string, sampleUrl: string, method: string, sourceId: string, sourceDepth: number) {
    let entry = apiAgg.get(pathname);
    if (!entry) {
      entry = { methods: new Set(), sampleUrl, sourceIds: new Set(), depth: sourceDepth + 1 };
      apiAgg.set(pathname, entry);
    }
    entry.methods.add(method);
    entry.sourceIds.add(sourceId);
    entry.depth = Math.min(entry.depth, sourceDepth + 1);
  }

  // Pass 1: pages, forms, assets, external links.
  for (const page of pages) {
    const pageId = sourceIdOf(page.url);
    const pageDepth = page.url === origin ? 0 : page.depth;

    if (page.url !== origin) {
      addNode({ id: pageId, type: "PAGE", label: pathOf(page.url) || "/", url: page.url, depth: page.depth });
      const parentId = page.parentUrl ? sourceIdOf(page.parentUrl) : "root";
      addEdge(parentId, pageId, false);
    }

    for (const scriptUrl of page.scripts) {
      const assetId = `asset:${scriptUrl}`;
      addNode({ id: assetId, type: "ASSET", label: pathOf(scriptUrl), url: scriptUrl, depth: pageDepth + 1 });
      addEdge(pageId, assetId, false);
      if (!assetToSources.has(scriptUrl)) assetToSources.set(scriptUrl, new Set());
      assetToSources.get(scriptUrl)!.add(pageId);
    }

    for (const extHost of page.externalLinks) {
      const extId = `external:${extHost}`;
      addNode({ id: extId, type: "EXTERNAL", label: extHost, url: `https://${extHost}`, depth: pageDepth + 1 });
      addEdge(pageId, extId, false);
    }

    page.forms.forEach((form, i) => {
      const formId = `form:${page.url}:${i}`;
      addNode({
        id: formId,
        type: "FORM",
        label: deriveFormLabel(form.action, form.inputs),
        url: form.action,
        depth: pageDepth + 1,
        formMethod: form.method,
        inputs: form.inputs,
      });
      addEdge(pageId, formId, false);

      // Kalau form submit ke path /api/*, gabung juga ke agregasi API node
      // (form POST ke /api dianggap bagian dari attack surface API).
      const actionPath = pathOf(form.action);
      if (actionPath.startsWith("/api")) {
        registerApi(actionPath, form.action, form.method || "POST", pageId, pageDepth);
      }
    });
  }

  // Pass 2: API calls ditemukan dari isi JS same-origin.
  for (const finding of jsFindings) {
    const sourceIds = assetToSources.get(finding.assetUrl) ?? new Set<string>(["root"]);
    const sourceIdArr = Array.from(sourceIds);
    for (const call of finding.apiCalls) {
      let resolved: URL;
      try {
        resolved = new URL(call.url, origin);
      } catch {
        continue;
      }

      if (resolved.hostname !== hostname) {
        // Endpoint eksternal yang dipanggil dari JS — tetap dicatat sebagai node EXTERNAL,
        // bukan API (attack surface milik pihak ketiga, bukan same-origin).
        const extId = `external:${resolved.hostname}`;
        addNode({ id: extId, type: "EXTERNAL", label: resolved.hostname, url: resolved.origin, depth: 2 });
        for (const sid of sourceIdArr.slice(0, MAX_EDGES_PER_API)) addEdge(sid, extId, false);
        continue;
      }

      const pathname = resolved.pathname || "/";
      for (const sid of sourceIdArr.slice(0, MAX_EDGES_PER_API)) {
        const srcNode = nodes.get(sid);
        registerApi(pathname, resolved.toString(), call.method, sid, srcNode?.depth ?? 1);
      }
    }
  }

  for (const [pathname, entry] of apiAgg) {
    const apiId = `api:${pathname}`;
    addNode({
      id: apiId,
      type: "API",
      label: pathname,
      url: entry.sampleUrl,
      depth: entry.depth,
      methods: Array.from(entry.methods),
    });
    for (const sid of Array.from(entry.sourceIds).slice(0, MAX_EDGES_PER_API)) {
      addEdge(sid, apiId, true);
    }
  }

  // --- Cap total node ke MAX_NODES, trim leaf node prioritas terendah dulu ---
  const REMOVE_PRIORITY: Record<AttackMapNodeType, number> = {
    ASSET: 1,
    EXTERNAL: 2,
    FORM: 3,
    API: 4,
    PAGE: 5,
    ROOT: 99,
  };
  let truncated = false;
  while (nodes.size > MAX_NODES) {
    const outDegree = new Map<string, number>();
    for (const n of nodes.keys()) outDegree.set(n, 0);
    for (const e of edges) outDegree.set(e.source, (outDegree.get(e.source) ?? 0) + 1);

    const leaves = Array.from(nodes.values()).filter((n) => n.type !== "ROOT" && (outDegree.get(n.id) ?? 0) === 0);
    if (leaves.length === 0) break;
    leaves.sort((a, b) => REMOVE_PRIORITY[a.type] - REMOVE_PRIORITY[b.type]);
    const victim = leaves[0];
    nodes.delete(victim.id);
    for (let i = edges.length - 1; i >= 0; i--) {
      if (edges[i].target === victim.id || edges[i].source === victim.id) edges.splice(i, 1);
    }
    truncated = true;
  }

  const finalNodes = Array.from(nodes.values());
  const stats: AttackMapStats = {
    totalNodes: finalNodes.length,
    pageCount: finalNodes.filter((n) => n.type === "PAGE").length,
    apiCount: finalNodes.filter((n) => n.type === "API").length,
    formCount: finalNodes.filter((n) => n.type === "FORM").length,
    externalCount: finalNodes.filter((n) => n.type === "EXTERNAL").length,
    assetCount: finalNodes.filter((n) => n.type === "ASSET").length,
  };

  const riskHighlights: string[] = [];
  if (stats.apiCount > 0) {
    riskHighlights.push(`Ditemukan ${stats.apiCount} API endpoint yang ter-expose ke client.`);
  }
  const adminNodes = finalNodes.filter((n) => (n.type === "PAGE" || n.type === "API") && ADMIN_PATH_RE.test(n.label));
  if (adminNodes.length > 0) {
    const sample = adminNodes.slice(0, 3).map((n) => n.label).join(", ");
    riskHighlights.push(`${adminNodes.length} path admin/internal-looking terdeteksi: ${sample}${adminNodes.length > 3 ? ", ..." : ""}.`);
  }
  const authForms = finalNodes.filter((n) => n.type === "FORM" && n.label === "Login/Auth Form");
  if (authForms.length > 0) {
    riskHighlights.push(`${authForms.length} form login/auth ditemukan — pastikan submit lewat HTTPS & ada rate-limit.`);
  }
  if (stats.externalCount >= 5) {
    riskHighlights.push(`${stats.externalCount} domain eksternal dimuat oleh halaman ini — cek supply-chain risk (third-party script).`);
  }
  if (riskHighlights.length === 0) {
    riskHighlights.push("Tidak ada API/form/admin-path mencurigakan yang terdeteksi pada crawl ini.");
  }

  return {
    id: cryptoRandomId(),
    createdAt: Date.now(),
    targetUrl: origin,
    hostname,
    nodes: finalNodes,
    edges,
    stats,
    riskHighlights,
    truncated: truncated || pages.length >= maxPages,
    pagesCrawled: pages.length,
    filesAnalyzed: jsFindings.length,
  };
}

function cryptoRandomId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}
