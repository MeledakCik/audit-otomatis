import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";

export interface TargetConfig {
  host: string;
  url: string;
  protocol: "http" | "https";
  port: number;
  path: string;
}

export interface DomainStatusResult {
  domain: string;
  isGuarded: boolean;
  httpStatus: number | null;
  responseTimeMs: number;
  serverHeader: string;
  error?: string;
  scannedAt: string;
}

export interface BatchStatusResult {
  results: DomainStatusResult[];
  totalTargets: number;
  successCount: number;
  failedCount: number;
  threads: number;
  durationMs: number;
  summary: {
    avgLatency: number | null;
    targetsWithGuard: string[];
    targetsWithoutGuard: string[];
  };
}

// In-Memory Storage Target Sederhana untuk Sesi Aktif
let globalTargets: TargetConfig[] = [];
let globalConfig = {
  threads: 10,
  timeout: 8000,
  useProxy: false,
};

function parseDomainToTarget(domainStr: string): TargetConfig | null {
  try {
    const raw = String(domainStr).trim();
    if (!raw) return null;

    const cleanDomain = raw.replace(/^https?:\/\//, "").replace(/\/.*$/, "");
    if (!cleanDomain) return null;

    const url = raw.startsWith("http") ? raw : `https://${cleanDomain}`;
    const parsed = new URL(url);

    return {
      host: parsed.hostname,
      url: parsed.toString(),
      protocol: parsed.protocol.replace(":", "") as "http" | "https",
      port: parseInt(parsed.port) || (parsed.protocol === "https:" ? 443 : 80),
      path: parsed.pathname || "/",
    };
  } catch {
    return null;
  }
}

async function checkTarget(
  target: TargetConfig,
  timeoutMs: number = 8000
): Promise<DomainStatusResult> {
  const start = performance.now();
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), timeoutMs);

  try {
    const response = await fetch(target.url, {
      method: "GET",
      cache: "no-store",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "User-Agent":
          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
        Accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
      },
    });

    clearTimeout(timeout);
    const responseTimeMs = Math.round(performance.now() - start);
    const serverHeader = response.headers.get("server") || "Unknown";
    const status = response.status;

    // Indikator Guard / Protection (307, 429, 403, atau Server WAF Header)
    const isGuarded =
      status === 307 ||
      status === 429 ||
      status === 403 ||
      /cloudflare|cloudfront|incapsula|sucuri|akamai/i.test(serverHeader);

    return {
      domain: target.host,
      isGuarded,
      httpStatus: status,
      responseTimeMs,
      serverHeader,
      scannedAt: new Date().toISOString(),
    };
  } catch (error) {
    clearTimeout(timeout);
    const responseTimeMs = Math.round(performance.now() - start);
    const aborted = error instanceof Error && error.name === "AbortError";

    return {
      domain: target.host,
      isGuarded: false,
      httpStatus: null,
      responseTimeMs,
      serverHeader: "Unknown",
      error: aborted ? "Timeout" : "Failed to connect",
      scannedAt: new Date().toISOString(),
    };
  }
}

async function checkMultipleTargets(
  targets: TargetConfig[],
  timeoutMs: number = 8000,
  concurrency: number = 10
): Promise<BatchStatusResult> {
  const startTime = Date.now();
  const results: DomainStatusResult[] = [];
  const limit = Math.max(1, Math.min(concurrency, 20));

  for (let i = 0; i < targets.length; i += limit) {
    const chunk = targets.slice(i, i + limit);
    const chunkPromises = chunk.map((target) => checkTarget(target, timeoutMs));
    const chunkResults = await Promise.all(chunkPromises);
    results.push(...chunkResults);
  }

  const durationMs = Date.now() - startTime;
  const successCount = results.filter((r) => !r.error && r.httpStatus !== null).length;
  const failedCount = results.length - successCount;

  const latencies = results.map((r) => r.responseTimeMs);
  const avgLatency =
    latencies.length > 0
      ? Math.round(latencies.reduce((a, b) => a + b, 0) / latencies.length)
      : null;

  const targetsWithGuard = results.filter((r) => r.isGuarded).map((r) => r.domain);
  const targetsWithoutGuard = results.filter((r) => !r.isGuarded).map((r) => r.domain);

  return {
    results,
    totalTargets: targets.length,
    successCount,
    failedCount,
    threads: limit,
    durationMs,
    summary: {
      avgLatency,
      targetsWithGuard,
      targetsWithoutGuard,
    },
  };
}

// GET Handler
export async function GET(request: NextRequest) {
  const searchParams = request.nextUrl.searchParams;
  const action = searchParams.get("action");

  // Response untuk action=config
  if (action === "config") {
    return NextResponse.json({
      config: {
        ...globalConfig,
        targetCount: globalTargets.length,
      },
    });
  }

  // Response untuk action=check (polling status)
  if (action === "check") {
    const timeout = parseInt(searchParams.get("timeout") || String(globalConfig.timeout));
    const threads = parseInt(searchParams.get("threads") || String(globalConfig.threads));

    const result = await checkMultipleTargets(globalTargets, timeout, threads);
    return NextResponse.json(result);
  }

  return NextResponse.json({
    message: "Endpoint pemindaian shield status aktif.",
    status: "idle",
  });
}

// POST Handler
export async function POST(request: NextRequest) {
  try {
    const body = await request.json();

    // 1. Tangani request clearTargets
    if (body.clearTargets) {
      globalTargets = [];
      return NextResponse.json({
        success: true,
        message: "Target berhasil dikosongkan",
        config: { targetCount: 0 },
      });
    }

    // 2. Validasi field domains jika bukan request clearTargets
    if (!body.domains) {
      return NextResponse.json(
        { error: "Field 'domains' wajib diisi (string dipisah koma atau array)" },
        { status: 400 }
      );
    }

    const domainInput = Array.isArray(body.domains)
      ? body.domains
      : String(body.domains).split(",");

    const parsedTargets = domainInput
      .map((d: string) => parseDomainToTarget(d))
      .filter((t: TargetConfig | null): t is TargetConfig => t !== null);

    if (parsedTargets.length === 0) {
      return NextResponse.json(
        { error: "Tidak ada domain target yang valid" },
        { status: 400 }
      );
    }

    globalTargets = parsedTargets;
    globalConfig = {
      threads: Number(body.threads) || 10,
      timeout: Number(body.timeout) || 8000,
      useProxy: Boolean(body.useProxy),
    };

    return NextResponse.json({
      success: true,
      message: "Target berhasil diperbarui",
      config: {
        targetCount: globalTargets.length,
        threads: globalConfig.threads,
        timeout: globalConfig.timeout,
        useProxy: globalConfig.useProxy,
      },
    });
  } catch (error) {
    return NextResponse.json(
      { error: "Format request body tidak valid", details: String(error) },
      { status: 400 }
    );
  }
}