import type { Severity } from "@/lib/types";

export type RiskLevel = "HIGH" | "MEDIUM" | "LOW" | "CLEAN";

export interface SecretFinding {
  id: string;
  ruleId: string;
  type: string;
  severity: Severity;
  file: string;
  line: number;
  redactedSnippet: string;
  risk: string;
}

export interface SecretHuntReport {
  id: string;
  createdAt: number;
  targetUrl: string;
  hostname: string;
  filesScanned: number;
  filesSkipped: number;
  scannedFiles: string[];
  findings: SecretFinding[];
  riskLevel: RiskLevel;
  envVarNamesFound: string[];
}

export interface SecretHuntLogEntry {
  id: string;
  createdAt: number;
  hostname: string;
  riskLevel: RiskLevel;
  findingsCount: number;
  report: SecretHuntReport;
}
