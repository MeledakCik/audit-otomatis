import { NextResponse } from "next/server";
import { auditDomain } from "@/lib/sentinel/audit";
import { clientIp, rateLimit } from "@/lib/sentinel/redis";
import { getPublic, savePublic, saveVault } from "@/lib/sentinel/store";
import { SsrfBlockedError } from "@/lib/ssrf-guard";
import { logUserActivity } from "@/lib/activity-store";

export const runtime = "nodejs";
export const maxDuration = 60;

const FRESH_MS = 10 * 60 * 1000;

export async function POST(req: Request) {
  const body = await req.json().catch(() => null);
  const input = typeof body?.domain === "string" ? body.domain : "";
  if (!input) return NextResponse.json({ error: "domain wajib diisi" }, { status: 400 });

  if (!(await rateLimit("audit", clientIp(req), 10, 3600)))
    return NextResponse.json({ error: "Rate limit: maks 10 audit/jam." }, { status: 429 });

  try {
    const result = await auditDomain(input);
    const cached = await getPublic(result.domain);
    const critCount = result.findings.filter((f) => f.severity === "CRITICAL").length;
    const highCount = result.findings.filter((f) => f.severity === "HIGH").length;

    const repoDetected = result.gitIntel?.primaryRepository?.webUrl ?? null;
    const repoProvider = result.gitIntel?.primaryRepository?.provider ?? null;

    await logUserActivity({
      req,
      module: "SENTINEL_AUDIT",
      action: repoDetected
        ? `Sentinel Audit — Git Repo Terdeteksi (${repoProvider?.toUpperCase()})`
        : "Menjalankan Sentinel Passive Vault & Git Audit",
      target: result.domain,
      status: critCount > 0 ? "CRITICAL" : highCount > 0 ? "WARNING" : "SUCCESS",
      summary: repoDetected
        ? `${critCount} CRITICAL · Repo: ${repoDetected} · Branch: ${result.gitIntel?.head?.activeBranch ?? "-"}`
        : `${result.findings.length} temuan (${critCount} CRITICAL masuk Vault, ${highCount} HIGH)`,
      meta: {
        findingsCount: result.findings.length,
        criticalCount: critCount,
        highCount,
        vaultItemsSaved: result.raw.length,
        gitExposed: Boolean(result.gitIntel?.exposed),
        gitProvider: repoProvider,
        gitRepoUrl: repoDetected,
        gitBranch: result.gitIntel?.head?.activeBranch ?? null,
        gitLatestSha: result.gitIntel?.commits?.latestSha ?? null,
        gitIntelJson: result.gitIntel ? JSON.stringify(result.gitIntel) : null,
      },
    });

    if (cached && Date.now() - cached.scannedAt < FRESH_MS) return NextResponse.json(cached);

    await saveVault(result.raw);
    const pub = await savePublic(result);
    return NextResponse.json(pub);
  } catch (e) {
    const status = e instanceof SsrfBlockedError ? 403 : 400;
    await logUserActivity({
      req,
      module: "SENTINEL_AUDIT",
      action: "Sentinel Audit Gagal / Diblokir",
      target: input,
      status: status === 403 ? "BLOCKED" : "ERROR",
      summary: e instanceof Error ? e.message : "Audit gagal",
    });
    return NextResponse.json({ error: e instanceof Error ? e.message : "Audit gagal" }, { status });
  }
}
