import type { Severity } from "@/lib/types";

export type HeaderCheckKey =
  | "hsts"
  | "csp"
  | "frame-protection"
  | "x-content-type-options"
  | "referrer-policy"
  | "permissions-policy"
  | "coop";

export interface HeaderCheckResult {
  key: HeaderCheckKey;
  headerName: string;
  weight: number;
  pass: boolean;
  value: string | null;
  severity: Severity;
  risk: string;
  fixNextConfig: string;
  fixSnippetKey: string;
  fixSnippetValue: string;
}

export type Grade = "A+" | "A" | "B" | "C" | "D" | "F";

export interface HeaderScanReport {
  id: string;
  createdAt: number;
  targetUrl: string;
  hostname: string;
  finalUrl: string;
  statusCode: number;
  score: number;
  grade: Grade;
  checks: HeaderCheckResult[];
  rawHeaders: Record<string, string>;
}

export interface HeaderScanLogEntry {
  id: string;
  createdAt: number;
  hostname: string;
  grade: Grade;
  score: number;
  report: HeaderScanReport;
}
