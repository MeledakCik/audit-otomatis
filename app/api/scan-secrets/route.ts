import * as cheerio from "cheerio";
import { validateDomainInput } from "@/lib/validate-domain";
import { chromeHeaders } from "@/lib/crawler";
import { RequestBudget } from "@/lib/rate-limit";
import { scanSourceForSecrets, riskLevelFromFindings } from "@/lib/secret-hunter/rules";
import type { SecretFinding } from "@/lib/secret-hunter/types";

const MAX_JS_FILES = 20;
const MAX_FILE_BYTES = 3 * 1024 * 1024; // 3MB per file, cukup untuk bundle JS pada umumnya
const MAX_TOTAL_FINDINGS = 150;
const FETCH_TIMEOUT_MS = 10_000;

interface ScanBody {
  domain?: string;
}

function withTimeout(url: string, init: RequestInit, ms: number): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), ms);
  return fetch(url, { ...init, signal: controller.signal }).finally(() => clearTimeout(timer));
}

export async function POST(req: Request) {
  let body: ScanBody;
  try {
    body = (await req.json()) as ScanBody;
  } catch {
    return Response.json({ ok: false, error: "Body request tidak valid (harus JSON)." }, { status: 400 });
  }

  const raw = (body.domain ?? "").toString();
  const validation = validateDomainInput(raw);
  if (!validation.ok || !validation.normalizedUrl || !validation.hostname) {
    return Response.json({ ok: false, error: validation.error ?? "Domain tidak valid." }, { status: 400 });
  }

  const origin = validation.normalizedUrl;
  const hostname = validation.hostname;
  const budget = new RequestBudget(MAX_JS_FILES + 5, 250);

  // 1) Ambil HTML homepage (satu request GET, pasif).
  let html = "";
  try {
    const homeRes = await withTimeout(origin, { method: "GET", headers: chromeHeaders(), redirect: "follow" }, FETCH_TIMEOUT_MS);
    html = await homeRes.text();
  } catch {
    return Response.json(
      { ok: false, error: "Gagal menghubungi target. Pastikan domain aktif dan dapat diakses publik." },
      { status: 502 }
    );
  }

  // 2) Ekstrak <script src> same-origin saja (termasuk /_next/static/*.js),
  //    plus inline JSON hydration data (__NEXT_DATA__) kalau ada — semuanya
  //    sudah didapat dari response GET yang sama, tanpa request tambahan.
  const $ = cheerio.load(html);
  const scriptUrls = new Set<string>();
  $("script[src]").each((_, el) => {
    const src = $(el).attr("src");
    if (!src) return;
    try {
      const resolved = new URL(src, origin);
      if (resolved.hostname !== hostname) return; // same-origin only
      if (!/\.(js|mjs|json)(\?|$)/i.test(resolved.pathname)) return;
      scriptUrls.add(resolved.toString());
    } catch {
      // ignore url invalid
    }
  });

  const allFindings: SecretFinding[] = [];
  const scannedFiles: string[] = [];
  let filesSkipped = 0;

  const nextDataRaw = $("#__NEXT_DATA__").html();
  if (nextDataRaw && nextDataRaw.trim()) {
    const label = "__NEXT_DATA__ (inline JSON)";
    scannedFiles.push(label);
    allFindings.push(...scanSourceForSecrets(nextDataRaw, label));
  }

  const urls = Array.from(scriptUrls).slice(0, MAX_JS_FILES);
  filesSkipped += Math.max(0, scriptUrls.size - urls.length);

  for (const url of urls) {
    if (!budget.canSpend()) {
      filesSkipped += 1;
      continue;
    }
    const pathname = (() => {
      try {
        return new URL(url).pathname;
      } catch {
        return url;
      }
    })();

    const result = await budget.spend(async () => {
      try {
        const res = await withTimeout(url, { method: "GET", headers: chromeHeaders(origin) }, FETCH_TIMEOUT_MS);
        if (!res.ok) return null;
        const contentLength = Number(res.headers.get("content-length") ?? "0");
        if (contentLength && contentLength > MAX_FILE_BYTES) return "skip";
        const text = await res.text();
        if (text.length > MAX_FILE_BYTES) return text.slice(0, MAX_FILE_BYTES);
        return text;
      } catch {
        return null;
      }
    });

    if (result === "skip" || result === null) {
      filesSkipped += 1;
      continue;
    }

    scannedFiles.push(pathname);
    const findings = scanSourceForSecrets(result, pathname);
    allFindings.push(...findings);
    if (allFindings.length >= MAX_TOTAL_FINDINGS) break;
  }

  const findings = allFindings.slice(0, MAX_TOTAL_FINDINGS);
  const envVarNamesFound = Array.from(
    new Set(
      findings
        .filter((f) => f.ruleId === "public-env-secretish")
        .map((f) => f.redactedSnippet.split(" = ")[0])
    )
  );

  const report = {
    id: cryptoRandomId(),
    createdAt: Date.now(),
    targetUrl: origin,
    hostname,
    filesScanned: scannedFiles.length,
    filesSkipped,
    scannedFiles,
    findings,
    riskLevel: riskLevelFromFindings(findings),
    envVarNamesFound,
  };

  return Response.json({ ok: true, report });
}

function cryptoRandomId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}
