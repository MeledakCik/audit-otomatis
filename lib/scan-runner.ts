import { crawlSite, endpointNodeId, jsNodeId } from "./site-crawler";
import { analyzeJsSource, analyzeInlineScripts, fetchJsFiles } from "./js-analyzer";
import { scanSecrets } from "./secret-scanner";
import { fingerprintLibraries, libraryDetectionsToFindings, detectNextJs } from "./library-fingerprint";
import { testResponseLeakage, testAntiAutomation, testExposedFiles, testSecurityHeaders, type ExposedHit } from "./tester";
import { publishScanCriticals, publishDossier, dossierPublicFindings } from "./sentinel/publish";
import { collectComponents, runCveIntel, cveHitsToFindings, emptyIntel, type CveIntelResult } from "./vuln/cve-intel";
import { checkRceSurface, RCE_SURFACE_PATH_COUNT } from "./vuln/rce-surface";
import { buildDossier, type RceSurfaceEvidence } from "./sentinel/dossier";
import { auditDomain } from "./sentinel/audit";
import type { GitIntelReport } from "./sentinel/git-intel";
import { logUserActivity } from "./activity-store";
import { RequestBudget, sleep } from "./rate-limit";
import { discoverFilesDetailed } from "./discovery/passiveDiscovery";
import { checkVulnerableLibs } from "./vuln/jsLibChecker";
import { findDomSinks } from "./vuln/domSink";
import { detectRedirectParams } from "./vuln/redirectChecker";
import { generateIdorCases } from "./vuln/idorDetector";
import { checkAuthBypass } from "./vuln/authChecker";
import {
  vulnLibsToFindings,
  domSinksToFindings,
  redirectCasesToFindings,
  idorCasesToFindings,
  authCheckToFindings,
  passiveDiscoveryToFindings,
} from "./vuln/toFindings";

const MAX_SINK_FINDINGS_PER_FILE = 12;
import {
  addFinding,
  bumpRequestCount,
  bumpJsFilesScanned,
  getScan,
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

export async function runScan(
  scanId: string,
  origin: string,
  identity?: { ip?: string; userAgent?: string; userId?: string }
) {
  const budget = new RequestBudget(130, 500);
  const domainHost = new URL(origin).hostname.toLowerCase();

  try {
    await setStatus(scanId, "crawling");
    await log(scanId, `Crawling ${origin} (multi-level, same-origin, max 50 URL, depth 3 — Verified by Google Developer Bandung)...`);

    const crawl = await crawlSite(origin, budget, (msg) => log(scanId, msg));
    await bumpRequestCount(scanId, crawl.pages.length);
    await setPagesCrawled(scanId, crawl.pages.length);
    await setPages(scanId, crawl.pages);

    if (crawl.pages.length === 0 && crawl.cloudflare) {
      await log(scanId, `Cloudflare challenge terdeteksi: ${crawl.cloudflare.reason}`);
      await markBlocked(scanId, CF_MESSAGE);
      await logUserActivity({
        ip: identity?.ip,
        userAgent: identity?.userAgent,
        userId: identity?.userId,
        module: "FULL_SCAN",
        action: "Full Scan Dihentikan (Cloudflare Challenge)",
        target: domainHost,
        status: "BLOCKED",
        summary: `Scan ${scanId} terhenti oleh proteksi Cloudflare`,
        meta: { scanId },
      });
      return;
    }

    await log(
      scanId,
      `Crawl selesai: ${crawl.pages.length} halaman di-crawl, ${crawl.allInternalLinks.length} link internal unik, ${crawl.allScripts.length} file JS unik, ${crawl.allForms.length} form.`
    );

    if (crawl.cloudflare) {
      await log(scanId, `Cloudflare challenge terdeteksi di tengah crawl (data sebagian tetap dipakai): ${crawl.cloudflare.reason}`);
    }

    await setStatus(scanId, "analyzing_js");
    await log(scanId, `Mengunduh hingga ${Math.min(crawl.allScripts.length, 20)} file JS eksternal...`);
    const jsFiles = await fetchJsFiles(crawl.allScripts, (msg) => log(scanId, msg));
    await bumpRequestCount(scanId, jsFiles.length);
    await bumpJsFilesScanned(scanId, jsFiles.length);

    const initialNodes: GraphData["nodes"] = crawl.graph?.nodes?.length ? [...crawl.graph.nodes] : [];
    const initialEdges: GraphData["edges"] = crawl.graph?.edges?.length ? [...crawl.graph.edges] : [];

    if (initialNodes.length === 0) {
      for (const page of crawl.pages) {
        const pageId = `page:${page.url}`;
        initialNodes.push({ id: pageId, type: "page", label: page.url, depth: page.depth });

        for (const scriptUrl of page.scripts) {
          const jsId = jsNodeId ? jsNodeId(scriptUrl) : `js:${scriptUrl}`;
          if (!initialNodes.some((n) => n.id === jsId)) {
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
        if (!graph.nodes.some((n) => n.id === epId)) {
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

      const vulnLibFindings = vulnLibsToFindings(checkVulnerableLibs(file.text), file.label);
      for (const f of vulnLibFindings) {
        await addFinding(scanId, f);
        await log(scanId, `[VULN-LIB] ${f.severity} — ${f.title}`);
      }

      const sinks = findDomSinks(file.text).slice(0, MAX_SINK_FINDINGS_PER_FILE);
      if (sinks.length > 0) {
        for (const f of domSinksToFindings(sinks, file.label)) {
          await addFinding(scanId, f);
        }
        await log(
          scanId,
          `[DEEP-SINK] ${sinks.length} pola sink (DOM XSS / node2shell / Node Out-of-Bounds / wp2shell) ditemukan di ${file.label}.`
        );
      }
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

    // ---- CVE/CWE intel (pasif: versi terdeteksi → OSV/NVD). Tidak ada request ke target. ----
    let cveIntel: CveIntelResult = emptyIntel();
    try {
      const comps = collectComponents(allLibraryDetections, crawl.pages);
      await log(scanId, `[CVE-INTEL] ${comps.length} komponen bervers terdeteksi, mencocokkan ke OSV/NVD...`);
      cveIntel = await runCveIntel(comps, (m) => log(scanId, String(m)));
      const known = new Set(allLibraryDetections.map((d) => d.cve).filter(Boolean) as string[]);
      for (const f of cveHitsToFindings(cveIntel.hits.filter((h) => !known.has(h.id)), 12)) {
        await addFinding(scanId, f);
        await log(scanId, `[CVE] ${f.severity} — ${f.title}`);
      }
    } catch (e) {
      await log(scanId, `[CVE-INTEL] dilewati: ${(e as Error).message}`);
    }

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

        const inlineSinks = findDomSinks(src).slice(0, MAX_SINK_FINDINGS_PER_FILE);
        if (inlineSinks.length > 0) {
          const label = `inline-script@${p.pageUrl}`;
          for (const f of domSinksToFindings(inlineSinks, label)) {
            await addFinding(scanId, f);
          }
          await log(scanId, `[DEEP-SINK] ${inlineSinks.length} sink pattern ditemukan di ${label}.`);
        }
      }
    }

    await setGraph(scanId, graph);

    await setStatus(scanId, "deep_audit");
    await log(
      scanId,
      "Mencari well-known file & menjalankan Deep Passive Git Intelligence (/.git/config, /.git/config/.git, /logs/HEAD, /.git/refs/heads/main)..."
    );
    const discoveredFiles = await discoverFilesDetailed(origin);
    await bumpRequestCount(scanId, discoveredFiles.length);

    const discoveryFindings = passiveDiscoveryToFindings(origin, discoveredFiles);
    for (const f of discoveryFindings) {
      await addFinding(scanId, f);
      await log(scanId, `[DISCOVERY] ${f.severity} — ${f.title}`);
    }

    const extraPaths = new Set<string>();
    for (const r of discoveredFiles) {
      if (r.found) extraPaths.add(r.path);
      for (const p of r.extractedPaths) extraPaths.add(p);
    }
    for (const p of extraPaths) {
      jsEndpoints.push({ url: p, method: "GET", source: "passive-discovery:well-known" });
    }
    if (extraPaths.size > 0) {
      await log(scanId, `Passive discovery menambahkan ${extraPaths.size} path baru ke daftar endpoint.`);
    }

    const discoveredForDisplay = buildDiscoveredList(origin, crawl.allInternalLinks, crawl.allForms, jsEndpoints);
    await setDiscoveredEndpoints(scanId, discoveredForDisplay);
    const postCount = discoveredForDisplay.filter((e) => e.method === "POST").length;
    await log(scanId, `Total ${discoveredForDisplay.length} link/endpoint ditemukan (${postCount} bermetode POST).`);

    const testTargets = buildTestTargets(origin, crawl.allInternalLinks, crawl.allForms, jsEndpoints);
    await setEndpointsDiscovered(scanId, testTargets.length);
    await log(scanId, `Total ${testTargets.length} target akan diuji secara pasif (GET only).`);

    await log(
      scanId,
      "Menganalisis kandidat Open Redirect, SSRF, Node Out-of-Band (OOB), Shell Surface & IDOR dari pola URL (pasif, tanpa payload)..."
    );
    const allTargetUrls = testTargets.map((t) => t.url);

    const redirectFindings = redirectCasesToFindings(allTargetUrls.flatMap((u) => detectRedirectParams(u)));
    for (const f of redirectFindings) {
      await addFinding(scanId, f);
      await log(scanId, `[PARAM-AUDIT] ${f.severity} — ${f.title}`);
    }

    const idorFindings = idorCasesToFindings(generateIdorCases(allTargetUrls));
    for (const f of idorFindings) {
      await addFinding(scanId, f);
      await log(scanId, `[IDOR] ${f.severity} — ${f.title}`);
    }

    await setStatus(scanId, "testing");

    await log(
      scanId,
      "Menjalankan Audit File Sensitif & Brankas Bukti Terenkripsi (AES-256-GCM): .env, .git/HEAD, backup.zip, wp-config.php.bak, AWS keys, dump.sql..."
    );
    const exposedHits: ExposedHit[] = [];
    const exposedFindings = await testExposedFiles(origin, budget, (h) => exposedHits.push(h));
    for (const f of exposedFindings) await addFinding(scanId, f);
    await bumpRequestCount(scanId, 16);

    let detectedGitIntel: GitIntelReport | undefined;

    try {
      const sentinelRes = await auditDomain(domainHost);
      detectedGitIntel = sentinelRes.gitIntel;

      if (detectedGitIntel?.primaryRepository?.detected && detectedGitIntel.primaryRepository.webUrl) {
        await log(
          scanId,
          `[GIT-INTEL] Repository ${detectedGitIntel.primaryRepository.provider.toUpperCase()} ditemukan: ${detectedGitIntel.primaryRepository.webUrl} (branch: ${detectedGitIntel.head.activeBranch ?? "-"}, commit: ${detectedGitIntel.commits.latestSha?.slice(0, 10) ?? "-"})`
        );
        await addFinding(scanId, {
          id: `git_repo_${Date.now()}`,
          severity: "CRITICAL",
          title: `Git Remote Repository Teridentifikasi (${detectedGitIntel.primaryRepository.provider.toUpperCase()}: ${detectedGitIntel.primaryRepository.repoFullName})`,
          endpoint: `${origin}/.git/config`,
          evidence: `Remote origin mengarah ke ${detectedGitIntel.primaryRepository.provider.toUpperCase()} (${detectedGitIntel.primaryRepository.repoFullName}) · Branch aktif: ${detectedGitIntel.head.activeBranch ?? "main"} · JSON tersimpan di Admin Console`,
          impact:
            "Eksposur .git/config dan logs/HEAD mengungkap lokasi repository GitHub/GitLab, riwayat commit, email developer, serta berpotensi membocorkan seluruh source code.",
          fix: "Blokir akses ke /.git/ dan /logs/HEAD di web server, hapus direktori .git dari folder publik produksi, dan rotasi kredensial/token.",
          category: "sensitive-file",
          confidence: "verified",
        });
      }

      for (const r of sentinelRes.raw) {
        if (!exposedHits.some((h) => h.raw.path === r.path)) {
          const matchingFinding = sentinelRes.findings.find((f) => f.finding.includes(r.path)) ?? {
            domain: domainHost,
            severity: "CRITICAL" as const,
            finding: `Exposed sensitive path (${r.path})`,
            evidence_public: `200 OK, marker "${r.marker}" terdeteksi`,
            fix: "Hapus file dari webroot dan rotasi kredensial.",
          };
          exposedHits.push({ finding: matchingFinding, raw: r });
          if (r.path !== "/__git-intelligence.json") {
            await addFinding(scanId, {
              id: `sentinel_${Date.now()}_${Math.random().toString(36).slice(2, 6)}`,
              severity: "CRITICAL",
              title: `[Sentinel Vault] ${matchingFinding.finding}`,
              endpoint: new URL(r.path, origin).toString(),
              evidence: matchingFinding.evidence_public,
              impact: "File sensitif dapat diakses publik dan berisiko membocorkan kredensial/konfigurasi produksi.",
              fix: matchingFinding.fix,
              category: "sensitive-file",
              confidence: "verified",
            });
          }
        }
      }

      if (sentinelRes.findings.length > 0 || exposedHits.length > 0) {
        await publishScanCriticals(
          domainHost,
          [...exposedHits.map((h) => h.finding), ...sentinelRes.findings],
          exposedHits.map((h) => h.raw)
        );
      }
    } catch {
      if (exposedHits.length) {
        await publishScanCriticals(
          domainHost,
          exposedHits.map((h) => h.finding),
          exposedHits.map((h) => h.raw)
        );
      }
    }

    if (exposedHits.length) {
      await log(
        scanId,
        `${exposedHits.length} temuan CRITICAL & JSON Git Intel terverifikasi → disimpan terenkripsi (AES-256-GCM) di Sentinel Vault Admin.`
      );
    }

    // ---- Permukaan RCE, Shell-Escalation (wp2shell, php2shell, node2shell, go2shell, py2shell) & Node Out-of-Bounds pasif ----
    let rceEvidence: RceSurfaceEvidence[] = [];
    try {
      await log(
        scanId,
        "[DEEP-SHELL & OOB] Mengecek permukaan wp2shell, php2shell, node2shell, go2shell, py2shell & Node Out-of-Bounds (GET-only, tanpa payload)..."
      );
      const rce = await checkRceSurface(origin, budget);
      rceEvidence = rce.evidence;
      for (const f of rce.findings) {
        await addFinding(scanId, f);
        await log(scanId, `[${(f.category ?? "RCE-SURFACE").toUpperCase()}] ${f.severity} — ${f.title}`);
      }
      await bumpRequestCount(scanId, RCE_SURFACE_PATH_COUNT);
    } catch (e) {
      await log(scanId, `[DEEP-SHELL & OOB] dilewati: ${(e as Error).message}`);
    }

    await log(scanId, "Mengecek security headers...");
    const headerFindings = await budget.spend(() => testSecurityHeaders(origin));
    await bumpRequestCount(scanId);
    if (headerFindings) for (const f of headerFindings) await addFinding(scanId, f);

    for (const target of testTargets) {
      if (!budget.canSpend(3)) {
        await log(scanId, "Request budget tercapai, menghentikan pengujian.");
        break;
      }

      await log(scanId, `Menguji: ${target.method} ${target.url}`);

      const leakFinding = await budget.spend(() => testResponseLeakage(target.url));
      await bumpRequestCount(scanId);
      if (leakFinding) await addFinding(scanId, leakFinding);

      const autoFinding = await budget.spend(() => testAntiAutomation(target.url));
      await bumpRequestCount(scanId);
      if (autoFinding) await addFinding(scanId, autoFinding);

      const authResult = await budget.spend(() => checkAuthBypass(target.url));
      await bumpRequestCount(scanId);
      if (authResult) {
        for (const f of authCheckToFindings([authResult])) {
          await addFinding(scanId, f);
          await log(scanId, `[AUTH] ${f.severity} — ${f.title} (${f.endpoint})`);
        }
      }

      await sleep(50);
    }

    // ---- Dossier lengkap untuk ADMIN (vault terenkripsi); user hanya melihat temuan ringkas di atas ----
    try {
      const st = await getScan(scanId);
      const dossier = buildDossier({
        domain: domainHost,
        origin,
        components: cveIntel.components,
        hits: cveIntel.hits,
        rceSurface: rceEvidence,
        findings: (st?.findings ?? []).map((f) => ({ severity: f.severity, title: f.title, endpoint: f.endpoint, cwe: f.cwe })),
      });
      if (dossier.summary.cveTotal > 0 || dossier.summary.rceSurface > 0) {
        await publishDossier(domainHost, dossier, dossierPublicFindings(dossier));
        await log(
          scanId,
          `[ADMIN] Dossier CVE/CWE/RCE (${dossier.summary.cveTotal} CVE, ${dossier.summary.rcePotential} potensi RCE, ${dossier.summary.rceSurface} endpoint rawan) tersimpan terenkripsi di Sentinel Vault.`
        );
      }
    } catch (e) {
      await log(scanId, `[ADMIN] dossier gagal disimpan: ${(e as Error).message}`);
    }

    await log(scanId, "Semua pengujian pasif, Deep Shell/OOB Audit & Enkripsi Vault selesai.");
    await setStatus(scanId, "done");
    await markDone(scanId);

    const finalScan = await getScan(scanId);
    const totalFindings = finalScan?.findings?.length ?? 0;
    const critCount = finalScan?.findings?.filter((f) => f.severity === "CRITICAL").length ?? 0;
    const highCount = finalScan?.findings?.filter((f) => f.severity === "HIGH").length ?? 0;
    const repoUrl = detectedGitIntel?.primaryRepository?.webUrl ?? null;

    await logUserActivity({
      ip: identity?.ip,
      userAgent: identity?.userAgent,
      userId: identity?.userId,
      module: "FULL_SCAN",
      action: repoUrl
        ? `Full Scan + Git Repo Terdeteksi (${detectedGitIntel?.primaryRepository?.provider.toUpperCase()})`
        : "Full Passive Scan + Deep Shell/OOB + Sentinel Audit Selesai",
      target: domainHost,
      status: critCount > 0 ? "CRITICAL" : highCount > 0 ? "WARNING" : "SUCCESS",
      summary: repoUrl
        ? `Repo: ${repoUrl} · ${totalFindings} temuan (${critCount} CRITICAL, ${highCount} HIGH)`
        : `Selesai: ${crawl.pages.length} halaman, ${totalFindings} temuan (${critCount} CRITICAL, ${highCount} HIGH)`,
      meta: {
        scanId,
        pagesCount: crawl.pages.length,
        findingsCount: totalFindings,
        criticalCount: critCount,
        highCount,
        vaultHits: exposedHits.length,
        gitExposed: Boolean(detectedGitIntel?.exposed),
        gitProvider: detectedGitIntel?.primaryRepository?.provider ?? null,
        gitRepoUrl: repoUrl,
        gitBranch: detectedGitIntel?.head?.activeBranch ?? null,
        gitLatestSha: detectedGitIntel?.commits?.latestSha ?? null,
        gitIntelJson: detectedGitIntel ? JSON.stringify(detectedGitIntel) : null,
      },
    });
  } catch (err) {
    await markError(scanId, `Scan gagal: ${(err as Error).message}`);
    await logUserActivity({
      ip: identity?.ip,
      userAgent: identity?.userAgent,
      userId: identity?.userId,
      module: "FULL_SCAN",
      action: "Full Scan Gagal",
      target: domainHost,
      status: "ERROR",
      summary: (err as Error).message,
      meta: { scanId },
    });
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