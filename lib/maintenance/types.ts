import type { Severity } from "@/lib/types";

export type InputKind =
  | "npm-audit-json"
  | "next-build-log"
  | "access-log"
  | "cloudflare-log"
  | "har"
  | "source-code"
  | "stack-trace"
  | "unknown";

export type VulnerabilityType =
  | "XSS"
  | "SQLi"
  | "Path Traversal"
  | "SSRF"
  | "RCE"
  | "Info Disclosure"
  | "Insecure Deserialization"
  | "DoS / Unpredictable Behavior"
  | "Dependency Vulnerability"
  | "Broken Access Control"
  | "Misconfiguration"
  | "Unknown";

export interface LeakLocation {
  file?: string;
  line?: number;
  column?: number;
  endpoint?: string;
}

export interface RemediationStep {
  step: string;
  codeBefore?: string;
  codeAfter?: string;
  done?: boolean;
}

export interface TimelineEvent {
  label: "Detected" | "Patched" | "Verified";
  timestamp: number;
}

export interface SecurityFinding {
  id: string;
  severity: Severity;
  title: string;
  leakLocation: LeakLocation;
  vulnerabilityType: VulnerabilityType;
  owaspCategory: string;
  attackVector: string;
  payloadExample?: string;
  codeSnippet?: string;
  remediationSteps: RemediationStep[];
  prevention: string;
}

export interface SecurityReport {
  id: string;
  createdAt: number;
  sourceName: string;
  inputKind: InputKind;
  overallSeverity: Severity;
  summary: string;
  findings: SecurityFinding[];
  timeline: TimelineEvent[];
  aiEnriched: boolean;
}

export interface MaintenanceLogEntry {
  id: string;
  createdAt: number;
  sourceName: string;
  overallSeverity: Severity;
  summary: string;
  report: SecurityReport;
}
