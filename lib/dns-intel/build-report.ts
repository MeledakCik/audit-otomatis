import { resolveAllRecords } from "./resolve";
import { analyzeSpf, analyzeDmarc, analyzeDkimHint, detectMxProvider, detectTakeoverHints } from "./analyze";
import type { DnsIntelReport } from "./types";

function newId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

export async function buildDnsIntelReport(domain: string): Promise<DnsIntelReport> {
  const start = performance.now();

  const { records, recordRows, queryErrors, dmarcTxt } = await resolveAllRecords(domain);

  const spf = analyzeSpf(records.TXT);
  const dmarc = analyzeDmarc(dmarcTxt);
  const dkimHint = analyzeDkimHint(records.TXT);
  const mxProvider = detectMxProvider(records.MX);
  const takeoverHints = detectTakeoverHints(records.CNAME);

  const scanDurationMs = Math.round(performance.now() - start);

  return {
    id: newId(),
    createdAt: Date.now(),
    domain,
    scanDurationMs,
    records,
    recordRows,
    security: { spf, dmarc, dkimHint, mxProvider, takeoverHints },
    queryErrors,
  };
}
