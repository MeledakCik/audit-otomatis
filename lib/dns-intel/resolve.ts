import { dohQuery, stripTrailingDot, unquoteTxt, type DohAnswer } from "./doh-client";
import type { DnsRecordRow, DnsRecords, MxRecord, SoaRecord } from "./types";

const DNS_TYPE_CODE: Record<string, number> = {
  A: 1,
  NS: 2,
  CNAME: 5,
  SOA: 6,
  MX: 15,
  TXT: 16,
  AAAA: 28,
};

function answersOfType(answers: DohAnswer[] | undefined, type: string): DohAnswer[] {
  const code = DNS_TYPE_CODE[type];
  return (answers ?? []).filter((a) => a.type === code);
}

function parseMx(data: string): MxRecord {
  const [prio, ...rest] = data.trim().split(/\s+/);
  return { priority: Number(prio) || 0, exchange: stripTrailingDot(rest.join(" ")) };
}

function parseSoa(data: string): SoaRecord {
  const parts = data.trim().split(/\s+/);
  const [mname, rname, serial, refresh, retry, expire, minimum] = parts;
  return {
    mname: stripTrailingDot(mname ?? ""),
    rname: stripTrailingDot(rname ?? ""),
    serial: serial ?? "—",
    refresh: refresh ?? "—",
    retry: retry ?? "—",
    expire: expire ?? "—",
    minimum: minimum ?? "—",
  };
}

export interface ResolveResult {
  records: DnsRecords;
  recordRows: DnsRecordRow[];
  queryErrors: string[];
  dmarcTxt: string[]; // TXT record dari _dmarc.{domain}, dipakai analyze.ts
}

/**
 * Resolve A, AAAA, NS, MX, TXT, CNAME, SOA + _dmarc TXT secara paralel.
 * 100% pasif — masing-masing cuma satu standard DNS query lewat DoH, tidak
 * ada bruteforce subdomain, tidak ada zone transfer.
 */
export async function resolveAllRecords(domain: string): Promise<ResolveResult> {
  const types = ["A", "AAAA", "NS", "MX", "TXT", "CNAME", "SOA"] as const;

  const [aRes, aaaaRes, nsRes, mxRes, txtRes, cnameRes, soaRes, dmarcRes] = await Promise.all([
    dohQuery(domain, "A"),
    dohQuery(domain, "AAAA"),
    dohQuery(domain, "NS"),
    dohQuery(domain, "MX"),
    dohQuery(domain, "TXT"),
    dohQuery(domain, "CNAME"),
    dohQuery(domain, "SOA"),
    dohQuery(`_dmarc.${domain}`, "TXT"),
  ]);

  const queryErrors: string[] = [];
  const responses: Record<(typeof types)[number], Awaited<ReturnType<typeof dohQuery>>> = {
    A: aRes,
    AAAA: aaaaRes,
    NS: nsRes,
    MX: mxRes,
    TXT: txtRes,
    CNAME: cnameRes,
    SOA: soaRes,
  };
  for (const t of types) {
    if (responses[t] === null) queryErrors.push(t);
  }
  if (dmarcRes === null) queryErrors.push("DMARC(TXT)");

  const A = answersOfType(aRes?.Answer, "A").map((a) => a.data);
  const AAAA = answersOfType(aaaaRes?.Answer, "AAAA").map((a) => a.data);
  const NS = answersOfType(nsRes?.Answer, "NS").map((a) => stripTrailingDot(a.data));
  const MX = answersOfType(mxRes?.Answer, "MX").map((a) => parseMx(a.data));
  const TXT = answersOfType(txtRes?.Answer, "TXT").map((a) => unquoteTxt(a.data));
  const CNAME = answersOfType(cnameRes?.Answer, "CNAME").map((a) => stripTrailingDot(a.data));
  const soaAnswers = answersOfType(soaRes?.Answer, "SOA");
  const SOA = soaAnswers.length > 0 ? parseSoa(soaAnswers[0].data) : null;

  const dmarcTxt = answersOfType(dmarcRes?.Answer, "TXT").map((a) => unquoteTxt(a.data));

  const recordRows: DnsRecordRow[] = [];
  answersOfType(aRes?.Answer, "A").forEach((a) => recordRows.push({ type: "A", value: a.data, ttl: a.TTL }));
  answersOfType(aaaaRes?.Answer, "AAAA").forEach((a) => recordRows.push({ type: "AAAA", value: a.data, ttl: a.TTL }));
  answersOfType(nsRes?.Answer, "NS").forEach((a) => recordRows.push({ type: "NS", value: stripTrailingDot(a.data), ttl: a.TTL }));
  answersOfType(mxRes?.Answer, "MX").forEach((a) => {
    const mx = parseMx(a.data);
    recordRows.push({ type: "MX", value: `${mx.priority} ${mx.exchange}`, ttl: a.TTL });
  });
  answersOfType(txtRes?.Answer, "TXT").forEach((a) => recordRows.push({ type: "TXT", value: unquoteTxt(a.data), ttl: a.TTL }));
  answersOfType(cnameRes?.Answer, "CNAME").forEach((a) => recordRows.push({ type: "CNAME", value: stripTrailingDot(a.data), ttl: a.TTL }));
  if (SOA) {
    recordRows.push({
      type: "SOA",
      value: `${SOA.mname} ${SOA.rname} (serial ${SOA.serial})`,
      ttl: soaAnswers[0]?.TTL ?? null,
    });
  }

  return {
    records: { A, AAAA, NS, MX, TXT, CNAME, SOA },
    recordRows,
    queryErrors,
    dmarcTxt,
  };
}
