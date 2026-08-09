import type { BreachDetail, DomainBreachReport, DomainProbeResult, EmailBreachResult } from "./types";

const COMMON_PREFIXES = ["admin", "info", "contact", "support", "hello"];

// XposedOrNot's free tier caps at 2 req/sec per IP, per endpoint. Each probe
// fires 2 upstream requests (check-email + breach-analytics), so we stagger
// the 5 probes ~550ms apart. They're still all in flight together and
// resolved with a single Promise.all — just started on a slight delay so we
// don't trip 429s.
const STAGGER_MS = 550;

export function commonEmailsForDomain(domain: string): string[] {
  const clean = domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/\/.*$/, "");
  return COMMON_PREFIXES.map((prefix) => `${prefix}@${clean}`);
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function probeEmail(email: string, staggerIndex: number): Promise<DomainProbeResult> {
  if (staggerIndex > 0) await delay(staggerIndex * STAGGER_MS);
  try {
    const res = await fetch(`/api/breach-free?email=${encodeURIComponent(email)}`);
    const json = (await res.json()) as EmailBreachResult;
    return { email, result: json };
  } catch {
    return { email, result: { ok: false, error: "Network error while checking this address." } };
  }
}

export async function scanDomain(domain: string): Promise<DomainBreachReport> {
  const emails = commonEmailsForDomain(domain);
  const probes = await Promise.all(emails.map((email, i) => probeEmail(email, i)));

  const hits = probes.filter((p) => p.result.ok && !p.result.clean);
  const hitCount = hits.length;

  const combinedMap = new Map<string, BreachDetail>();
  const dataTypes = new Set<string>();
  let firstBreachYear: number | null = null;

  for (const probe of hits) {
    if (!probe.result.ok) continue;
    for (const b of probe.result.breaches) {
      if (!combinedMap.has(b.name)) combinedMap.set(b.name, b);
      b.dataExposed.forEach((d) => dataTypes.add(d));
    }
    if (probe.result.firstBreachYear !== null) {
      firstBreachYear =
        firstBreachYear === null ? probe.result.firstBreachYear : Math.min(firstBreachYear, probe.result.firstBreachYear);
    }
  }

  return {
    mode: "domain",
    domain,
    probes,
    hitCount,
    totalProbed: emails.length,
    combinedBreaches: Array.from(combinedMap.values()).sort((a, b) => b.records - a.records),
    dataTypesLeaked: Array.from(dataTypes),
    firstBreachYear,
  };
}
