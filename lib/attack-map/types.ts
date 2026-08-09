export type AttackMapNodeType = "ROOT" | "PAGE" | "API" | "FORM" | "EXTERNAL" | "ASSET";

export interface AttackMapNode {
  id: string;
  type: AttackMapNodeType;
  label: string;
  url: string;
  depth: number;
  methods?: string[];
  formMethod?: string;
  inputs?: string[];
}

export interface AttackMapEdge {
  id: string;
  source: string;
  target: string;
  animated?: boolean;
}

export interface AttackMapStats {
  totalNodes: number;
  pageCount: number;
  apiCount: number;
  formCount: number;
  externalCount: number;
  assetCount: number;
}

export interface AttackMapReport {
  id: string;
  createdAt: number;
  targetUrl: string;
  hostname: string;
  nodes: AttackMapNode[];
  edges: AttackMapEdge[];
  stats: AttackMapStats;
  riskHighlights: string[];
  truncated: boolean;
  pagesCrawled: number;
  filesAnalyzed: number;
}

export interface AttackMapLogEntry {
  id: string;
  createdAt: number;
  hostname: string;
  totalNodes: number;
  apiCount: number;
  report: AttackMapReport;
}
