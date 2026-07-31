import { crawlSite, endpointNodeId, jsNodeId } from "./site-crawler";
import { analyzeJsSource, analyzeInlineScripts, fetchJsFiles } from "./js-analyzer";
import { scanSecrets } from "./secret-scanner";
import { fingerprintLibraries, libraryDetectionsToFindings, detectNextJs } from "./library-fingerprint";
import { testResponseLeakage, testAntiAutomation, testExposedFiles, testSecurityHeaders } from "./tester";
import { RequestBudget, sleep } from "./rate-limit";
import {
  addFinding,
  bumpRequestCount,
  bumpJsFilesScanned,
  log,
  markBlocked,
  markDone,
  markError,
  setDiscoveredEndpoints,
  setEndpointsDiscovered,
  setGraph,
  setLibrariesDetected,
  setPages,
  setPagesCrawled,
  setStatus,
} from "./scan-store";
import type { DiscoveredEndpoint, FormInfo, GraphData, LibraryDetection } from "./types";

const CF_MESSAGE =
  "Domain dilindungi Cloudflare Challenge. Nonaktifkan Bot Fight Mode sementara untuk audit, atau masukkan CF Clearance Token manual di settings.";

export async function runScan(scanId: string, origin: string) {
  const budget = new RequestBudget(100, 500);

  try {
    await setStatus(scanId, "crawling");
    await log(scanId, `Crawling ${origin} (multi-level, same-origin, max 50 URL, depth 3)...`);

    const crawl = await crawlSite(origin, budget, (msg) => log(scanId, msg));
    await bumpRequestCount(scanId, crawl.pages.length);
    await setPagesCrawled(scanId, crawl.pages.length);
    await setPages(scanId, crawl.pages);

    if (crawl.pages.length === 0 && crawl.cloudflare) {
      await log(scanId, `Cloudflare challenge terdeteksi: ${crawl.cloudflare.reason}`);
      await markBlocked(scanId, CF_MESSAGE);
      return;
    }

    await log(
      scanId,
      `Crawl selesai: ${crawl.pages.length} halaman di-crawl, ${crawl.allInternalLinks.length} link internal unik, ${crawl.allScripts.length} file JS unik, ${crawl.allForms.length} form.`
    );

    if (crawl.cloudflare) {
      await log(scanId, `Cloudflare challenge terdeteksi di tengah crawl (data sebagian tetap dipakai): ${crawl.cloudflare.reason}`);
    }

    // --- Analisis JS: endpoint + secret + library fingerprint ---
    await setStatus(scanId, "analyzing_js");
    await log(scanId, `Mengunduh hingga ${Math.min(crawl.allScripts.length, 20)} file JS eksternal...`);
    const jsFiles = await fetchJsFiles(crawl.allScripts, (msg) => log(scanId, msg));
    await bumpRequestCount(scanId, jsFiles.length);
    await bumpJsFilesScanned(scanId, jsFiles.length);

    // [PERBAIKAN] Pastikan graph & edges di-generate dengan aman (Fallback otomatis jika crawler kosong)
    const initialNodes: GraphData["nodes"] = crawl.graph?.nodes?.length ? [...crawl.graph.nodes] : [];
    const initialEdges: GraphData["edges"] = crawl.graph?.edges?.length ? [...crawl.graph.edges] : [];

    if (initialNodes.length === 0) {
      for (const page of crawl.pages) {
        const pageId = `page:${page.url}`;
        initialNodes.push({ id: pageId, type: "page", label: page.url, depth: page.depth });
        
        for (const scriptUrl of page.scripts) {
          const jsId = jsNodeId ? jsNodeId(scriptUrl) : `js:${scriptUrl}`;
          if (!initialNodes.some(n => n.id === jsId)) {
            initialNodes.push({ id: jsId, type: "js", label: scriptUrl });
          }
          initialEdges.push({ from: pageId, to: jsId });
        }
      }
    }

    const graph: GraphData = { nodes: initialNodes, edges: initialEdges };
    const jsEndpoints: DiscoveredEndpoint[] = [];
    const allLibraryDetections: LibraryDetection[] = [];

    await setStatus(scanId, "scanning_secrets");
    for (const file of jsFiles) {
      const { endpoints } = analyzeJsSource(file.text, file.label);
      jsEndpoints.push(...endpoints);
      for (const ep of endpoints) {
        const epId = endpointNodeId ? endpointNodeId(ep.url) : `endpoint:${ep.url}`;
        if (!graph.nodes.some(n => n.id === epId)) {
          graph.nodes.push({ id: epId, type: "endpoint", label: ep.url });
        }
        const scriptId = jsNodeId ? jsNodeId(file.url) : `js:${file.url}`;
        graph.edges.push({ from: scriptId, to: epId });
      }
      if (endpoints.length > 0) {
        await log(scanId, `Parsed ${file.label} — ${endpoints.length} endpoint ditemukan`);
      }

      const secretFindings = scanSecrets(file.text, file.label);
      for (const f of secretFindings) {
        await addFinding(scanId, f);
        await log(scanId, `[SECRET] ${f.severity} — ${f.title} (${f.endpoint})`);
      }

      const libs = fingerprintLibraries(file.text, file.label);
      allLibraryDetections.push(...libs);
    }

    await setStatus(scanId, "fingerprinting_libraries");
    const homepage = crawl.pages.find((p) => p.depth === 0);
    if (homepage) {
      const usesNext = detectNextJs(homepage.scripts);
      if (usesNext) log(scanId, "Next.js terdeteksi dari path /_next/static/.");
    }
    const libFindings = libraryDetectionsToFindings(allLibraryDetections);
    for (const f of libFindings) {
      await addFinding(scanId, f);
      await log(scanId, `[LIBRARY] ${f.severity} — ${f.title}`);
    }
    await setLibrariesDetected(scanId, allLibraryDetections);
    await log(scanId, `Fingerprint library selesai: ${allLibraryDetections.length} versi terdeteksi, ${libFindings.length} CVE cocok.`);

    // --- Inline scripts ---
    const allInline = crawl.allInlineScripts.flatMap((p) => p.scripts);
    await log(scanId, `Menganalisis ${allInline.length} inline script (semua halaman)...`);
    const inlineResult = analyzeInlineScripts(allInline, (msg) => log(scanId, msg));
    for (const ep of inlineResult.endpoints) {
      jsEndpoints.push(ep);
    }
    for (const p of crawl.allInlineScripts) {
      for (const src of p.scripts) {
        const secretFindings = scanSecrets(src, `inline-script@${p.pageUrl}`);
        for (const f of secretFindings) {
          await addFinding(scanId, f);
          await log(scanId, `[SECRET] ${f.severity} — ${f.title} (${f.endpoint})`);
        }
      }
    }

    await setGraph(scanId, graph);

    const discoveredForDisplay = buildDiscoveredList(origin, crawl.allInternalLinks, crawl.allForms, jsEndpoints);
    await setDiscoveredEndpoints(scanId, discoveredForDisplay);
    const postCount = discoveredForDisplay.filter((e) => e.method === "POST").length;
    await log(scanId, `Total ${discoveredForDisplay.length} link/endpoint ditemukan (${postCount} bermetode POST).`);

    const testTargets = buildTestTargets(origin, crawl.allInternalLinks, crawl.allForms, jsEndpoints);
    await setEndpointsDiscovered(scanId, testTargets.length);
    await log(scanId, `Total ${testTargets.length} target akan diuji secara pasif (GET only).`);

    await setStatus(scanId, "testing");

    await log(scanId, "Mengecek file sensitif (robots.txt, .env, .git/HEAD)...");
    const exposedFindings = await testExposedFiles(origin, budget);
    for (const f of exposedFindings) addFinding(scanId, f);
    await bumpRequestCount(scanId, 3);

    await log(scanId, "Mengecek security headers...");
    const headerFindings = await budget.spend(() => testSecurityHeaders(origin));
    await bumpRequestCount(scanId);
    if (headerFindings) for (const f of headerFindings) addFinding(scanId, f);

    for (const target of testTargets) {
      if (!budget.canSpend(2)) {
        await log(scanId, "Request budget (max 100) tercapai, menghentikan pengujian.");
        break;
      }

      await log(scanId, `Menguji: ${target.method} ${target.url}`);

      const leakFinding = await budget.spend(() => testResponseLeakage(target.url));
      await bumpRequestCount(scanId);
      if (leakFinding) addFinding(scanId, leakFinding);

      const autoFinding = await budget.spend(() => testAntiAutomation(target.url));
      await bumpRequestCount(scanId);
      if (autoFinding) addFinding(scanId, autoFinding);

      await sleep(50);
    }

    await log(scanId, "Semua pengujian pasif selesai.");
    await setStatus(scanId, "done");
    await markDone(scanId);
  } catch (err) {
    await markError(scanId, `Scan gagal: ${(err as Error).message}`);
  }
}

function buildDiscoveredList(
  origin: string,
  internalLinks: string[],
  forms: FormInfo[],
  jsEndpoints: DiscoveredEndpoint[]
): DiscoveredEndpoint[] {
  const out: DiscoveredEndpoint[] = [];

  function add(ep: DiscoveredEndpoint) {
    let normalized: string;
    try {
      normalized = new URL(ep.url, origin).toString();
    } catch {
      return;
    }
    const key = `${ep.method} ${normalized}`;
    const existingIdx = out.findIndex((e) => `${e.method} ${e.url}` === key);
    if (existingIdx !== -1) {
      if (!out[existingIdx].payload && ep.payload) {
        out[existingIdx] = { ...ep, url: normalized };
      }
      return;
    }
    out.push({ ...ep, url: normalized });
  }

  for (const link of internalLinks) {
    add({ url: link, method: "GET", source: "crawler:link" });
  }
  for (const form of forms) {
    const method = form.method.toUpperCase() === "POST" ? "POST" : "GET";
    add({
      url: form.action,
      method,
      source: "crawler:form",
      ...(form.inputs.length > 0 ? { payload: form.inputs } : {}),
    });
  }
  for (const ep of jsEndpoints) {
    add(ep);
  }

  return out;
}

function buildTestTargets(
  origin: string,
  internalLinks: string[],
  forms: FormInfo[],
  jsEndpoints: DiscoveredEndpoint[]
): { url: string; method: "GET" }[] {
  const seen = new Set<string>();
  const out: { url: string; method: "GET" }[] = [];

  function add(url: string, payloadFields?: string[]) {
    let normalized: string;
    try {
      const u = new URL(url, origin);
      for (const field of payloadFields ?? []) {
        if (field === "...spread" || u.searchParams.has(field)) continue;
        u.searchParams.set(field, "test");
      }
      normalized = u.toString();
    } catch {
      return;
    }
    const key = `GET ${normalized}`;
    if (seen.has(key)) return;
    seen.add(key);
    out.push({ url: normalized, method: "GET" });
  }

  for (const link of internalLinks) add(link);
  for (const form of forms) add(form.action, form.inputs);
  for (const ep of jsEndpoints) add(ep.url, ep.payload);

  return out;
}