import type { Severity } from "@/lib/types";

export interface DnsRecordRow {
  type: string;
  value: string;
  ttl: number | null;
}

export interface MxRecord {
  priority: number;
  exchange: string;
}

export interface SoaRecord {
  mname: string;
  rname: string;
  serial: string;
  refresh: string;
  retry: string;
  expire: string;
  minimum: string;
}

export interface DnsRecords {
  A: string[];
  AAAA: string[];
  NS: string[];
  MX: MxRecord[];
  TXT: string[];
  CNAME: string[];
  SOA: SoaRecord | null;
}

export interface SpfResult {
  found: boolean;
  value: string | null;
  risk: Severity;
  note: string;
}

export interface DmarcResult {
  found: boolean;
  value: string | null;
  policy: "reject" | "quarantine" | "none" | null;
  risk: Severity;
  note: string;
}

export interface DkimHint {
  found: boolean;
  matchedRecords: string[];
  note: string;
}

export interface MxProvider {
  provider: string;
  confidence: "HIGH" | "MEDIUM" | "LOW";
}

export interface TakeoverHint {
  cname: string;
  matchedService: string;
  risk: Severity;
  note: string;
}

export interface DnsSecurity {
  spf: SpfResult;
  dmarc: DmarcResult;
  dkimHint: DkimHint;
  mxProvider: MxProvider | null;
  takeoverHints: TakeoverHint[];
}

export interface DnsIntelReport {
  id: string;
  createdAt: number;
  domain: string;
  scanDurationMs: number;
  records: DnsRecords;
  recordRows: DnsRecordRow[];
  security: DnsSecurity;
  queryErrors: string[]; // tipe record yang gagal di-resolve (timeout/error), bukan berarti kosong
}

export interface DnsIntelLogEntry {
  id: string;
  createdAt: number;
  domain: string;
  riskCount: number;
  report: DnsIntelReport;
}
