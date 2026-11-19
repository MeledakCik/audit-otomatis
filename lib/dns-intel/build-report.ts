import { registrableDomain } from "@/lib/registrable-domain";
import { resolveAllRecords } from "./resolve";
import { analyzeSpf, analyzeDmarc, analyzeDkimHint, detectMxProvider, detectTakeoverHints } from "./analyze";
import type { DnsIntelReport } from "./types";

function newId(): string {
  return Math.random().toString(36).slice(2) + Date.now().toString(36);
}

export async function buildDnsIntelReport(domain: string): Promise<DnsIntelReport> {
  const start = performance.now();

  const { records, recordRows, queryErrors, dmarcTxt } = await resolveAllRecords(domain);

  // SPF/DMARC/DKIM/MX berlaku di domain induk (www.kasyaf.id → kasyaf.id).
  const mailDomain = registrableDomain(domain);
  const mail = mailDomain === domain ? { records, dmarcTxt } : await resolveAllRecords(mailDomain);

  const spf = analyzeSpf(mail.records.TXT);
  const dmarc = analyzeDmarc(mail.dmarcTxt);
  const dkimHint = analyzeDkimHint(mail.records.TXT);
  const mxProvider = detectMxProvider(mail.records.MX);
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
