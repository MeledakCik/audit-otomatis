export type StackCategory =
  | "Frontend"
  | "CMS"
  | "Backend"
  | "BaaS"
  | "CDN"
  | "Hosting"
  | "Analytics"
  | "Payments"
  | "Auth";

export type EvidenceTier = "header" | "html" | "jsHint";

export interface Evidence {
  tier: EvidenceTier;
  label: string;
}

export interface DetectedStack {
  id: string;
  name: string;
  icon: string;
  category: StackCategory;
  confidence: number;
  evidence: Evidence[];
  version: string | null;
}

export interface StackFingerprintReport {
  id: string;
  createdAt: number;
  domain: string;
  targetUrl: string;
  finalUrl: string;
  statusCode: number;
  stacks: DetectedStack[];
}

export interface StackFingerprintLogEntry {
  id: string;
  createdAt: number;
  domain: string;
  stackCount: number;
  report: StackFingerprintReport;
}
