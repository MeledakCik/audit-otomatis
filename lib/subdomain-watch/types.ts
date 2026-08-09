export type TakeoverRisk = "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export type CheckStatus = "pending" | "checking" | "checked" | "error";

export interface SubdomainRow {
  subdomain: string;
  status: CheckStatus;
  cname: string | null;
  httpStatus: number | null;
  risk: TakeoverRisk;
  service: string | null;
  reason: string | null;
  fix: string | null;
  errorMessage?: string | null;
}

export interface SubdomainWatchReport {
  id: string;
  createdAt: number;
  domain: string;
  totalFound: number;
  truncated: boolean;
  rows: SubdomainRow[];
}

export interface SubdomainWatchLogEntry {
  id: string;
  createdAt: number;
  domain: string;
  totalFound: number;
  highCount: number;
  report: SubdomainWatchReport;
}
