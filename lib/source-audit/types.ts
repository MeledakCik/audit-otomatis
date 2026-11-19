import type { Severity } from "@/lib/types";

export type SourceCategory =
  | "secret"
  | "sensitive-file"
  | "injection"
  | "xss"
  | "crypto"
  | "auth"
  | "config"
  | "deserialization"
  | "ssrf"
  | "path-traversal"
  | "supply-chain"
  | "ci-cd"
  | "container"
  | "access-control"
  | "dependency";

export type Confidence = "verified" | "likely" | "pattern-only" | "version-based";

export interface SourceFinding {
  id: string;
  ruleId: string;
  severity: Severity;
  title: string;
  category: SourceCategory;
  cwe?: string;
  owasp?: string;
  file: string;
  line?: number;
  /** Cuplikan baris; secret selalu diredaksi. */
  snippet?: string;
  impact: string;
  fix: string;
  confidence: Confidence;
}

export interface DependencyVuln {
  id: string;
  aliases: string[];
  summary: string;
  severity: Severity;
  cvss?: number;
  fixed?: string;
  url: string;
}

export interface VulnerableDependency {
  name: string;
  version: string;
  ecosystem: string;
  source: string;
  vulns: DependencyVuln[];
}

export interface SourceAuditReport {
  id: string;
  createdAt: number;
  fileName: string;
  durationMs: number;
  score: number;
  grade: "A" | "B" | "C" | "D" | "F";
  counts: Record<Severity, number>;
  stats: {
    filesScanned: number;
    bytesScanned: number;
    totalEntries: number;
    languages: Record<string, number>;
    frameworks: string[];
  };
  findings: SourceFinding[];
  dependencies: {
    scanned: number;
    ecosystems: Record<string, number>;
    vulnerable: VulnerableDependency[];
    error?: string;
  };
  skipped: { path: string; reason: string }[];
  notes: string[];
}
