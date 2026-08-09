import { NextRequest } from "next/server";

// Sentinel-ID Breach Peek (Free) — server-side proxy for the XposedOrNot
// free public OSINT API. Proxying here means the browser never talks to
// api.xposedornot.com directly, which sidesteps CORS entirely and keeps
// the free-tier rate limit (2 req/sec/IP) applied to our server, not the
// user's browser.

const XON_BASE = "https://api.xposedornot.com/v1";
const FETCH_TIMEOUT_MS = 10_000;
const USER_AGENT = "Sentinel-ID-BreachPeek/1.0 (+https://www.sentinel-id.net)";

interface XonCheckEmailResponse {
  breaches?: string[][];
  email?: string | null;
  status?: string;
  Error?: string;
}

interface XonBreachDetail {
  breach: string;
  details: string;
  domain: string;
  industry: string;
  logo: string;
  password_risk: string;
  references: string;
  searchable: string;
  verified: string;
  xposed_data: string;
  xposed_date: string;
  xposed_records: number;
}

interface XonAnalyticsResponse {
  BreachMetrics: {
    risk?: { risk_label: string; risk_score: number }[];
    passwords_strength?: {
      EasyToCrack: number;
      PlainText: number;
      StrongHash: number;
      Unknown: number;
    }[];
    yearwise_details?: Record<string, number>[];
  } | null;
  BreachesSummary: { site: string } | null;
  ExposedBreaches: { breaches_details: XonBreachDetail[] } | null;
  ExposedPastes: unknown;
  PasteMetrics: unknown;
  PastesSummary: { cnt: number; domain: string; tmpstmp: string } | null;
}

function isValidEmail(value: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

async function fetchJson(url: string): Promise<{ status: number; json: unknown }> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "GET",
      signal: controller.signal,
      headers: { "User-Agent": USER_AGENT, Accept: "application/json" },
      cache: "no-store",
    });
    clearTimeout(timeout);
    let json: unknown = null;
    try {
      json = await res.json();
    } catch {
      json = null;
    }
    return { status: res.status, json };
  } catch (err) {
    clearTimeout(timeout);
    const aborted = err instanceof Error && err.name === "AbortError";
    return { status: aborted ? 408 : 502, json: null };
  }
}

export async function GET(req: NextRequest) {
  const email = (req.nextUrl.searchParams.get("email") ?? "").trim().toLowerCase();

  if (!email || !isValidEmail(email)) {
    return Response.json({ ok: false, error: "A valid email address is required." }, { status: 400 });
  }

  const [checkRes, analyticsRes] = await Promise.all([
    fetchJson(`${XON_BASE}/check-email/${encodeURIComponent(email)}`),
    fetchJson(`${XON_BASE}/breach-analytics?email=${encodeURIComponent(email)}`),
  ]);

  if (checkRes.status === 429 || analyticsRes.status === 429) {
    return Response.json(
      {
        ok: false,
        rateLimited: true,
        error: "XposedOrNot free tier rate limit hit (2 req/sec). Wait a few seconds and retry.",
      },
      { status: 429 }
    );
  }

  // check-email only ever legitimately returns 200 (found) or 404 (not found).
  // breach-analytics only ever legitimately returns 200 (its "not found" case is
  // an all-null 200 body, not a 404). Anything else — 5xx, timeouts, or a
  // network/firewall block upstream of the API itself — is a real failure and
  // must not be silently reported as "0 breaches found".
  const checkFailed = checkRes.status !== 200 && checkRes.status !== 404;
  const analyticsFailed = analyticsRes.status !== 200;
  if (checkFailed || analyticsFailed) {
    return Response.json(
      { ok: false, error: "XposedOrNot is unreachable or returned an unexpected response. Try again shortly." },
      { status: 502 }
    );
  }

  const checkJson = (checkRes.json ?? {}) as XonCheckEmailResponse;
  const analytics = (analyticsRes.json ?? {}) as Partial<XonAnalyticsResponse>;

  const notFound = checkRes.status === 404 || checkJson.Error === "Not found";
  const breachNames: string[] = Array.isArray(checkJson.breaches?.[0]) ? (checkJson.breaches![0] as string[]) : [];

  const details = analytics.ExposedBreaches?.breaches_details ?? [];
  const clean = notFound && details.length === 0;

  const breaches = details.map((b) => ({
    name: b.breach,
    domain: b.domain,
    date: b.xposed_date,
    description: b.details,
    logo: b.logo,
    passwordRisk: b.password_risk,
    dataExposed: typeof b.xposed_data === "string" ? b.xposed_data.split(";").filter(Boolean) : [],
    records: b.xposed_records ?? 0,
    verified: b.verified === "Yes",
  }));

  const metrics = analytics.BreachMetrics ?? null;
  const riskLabel = metrics?.risk?.[0]?.risk_label ?? null;
  const riskScore = metrics?.risk?.[0]?.risk_score ?? null;
  const passwordStrength = metrics?.passwords_strength?.[0] ?? null;
  const yearwise = metrics?.yearwise_details?.[0] ?? {};

  const years = Object.entries(yearwise)
    .filter(([, count]) => (count as number) > 0)
    .map(([key]) => parseInt(key.replace(/^y/, ""), 10))
    .filter((n) => !Number.isNaN(n));

  const breachYears = breaches.map((b) => parseInt(b.date, 10)).filter((n) => !Number.isNaN(n));
  const allYears = [...years, ...breachYears];
  const firstBreachYear = allYears.length ? Math.min(...allYears) : null;

  const dataTypesLeaked = Array.from(new Set(breaches.flatMap((b) => b.dataExposed)));
  const passwordExposedCount = breaches.filter((b) => b.dataExposed.some((d) => /password/i.test(d))).length;

  return Response.json({
    ok: true,
    email,
    clean,
    breachCount: clean ? 0 : Math.max(breachNames.length, breaches.length),
    breachNames,
    breaches,
    dataTypesLeaked,
    passwordExposedCount,
    firstBreachYear,
    riskLabel,
    riskScore,
    passwordStrength,
    pastesCount: analytics.PastesSummary?.cnt ?? 0,
  });
}
