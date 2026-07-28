export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface DiscoveredEndpoint {
  url: string;
  method: "GET" | "POST" | "PUT" | "DELETE" | "PATCH";
  source: string; // e.g. "/static/chunk.js:42" or "crawler:<a href>"
  payload?: string[]; // nama field body/payload, kalau bisa dideteksi statis (mis. dari JSON.stringify({...}) atau form input)
}

export interface FormInfo {
  action: string;
  method: string;
  inputs: string[];
}

export interface CrawlResult {
  origin: string;
  internalLinks: string[];
  scripts: string[];
  forms: FormInfo[];
  inlineScripts: string[];
}

export interface Finding {
  id: string;
  severity: Severity;
  title: string;
  endpoint: string;
  evidence: string; // status code + <=100 char snippet, never full body
  impact: string;
  fix: string;
  cvss?: number; // estimasi CVSS 0-10, hanya untuk temuan gaya pentest (secret/CVE)
  cwe?: string; // referensi CWE-xxx kalau relevan
  poc?: string; // contoh request non-destruktif (curl), hanya ilustrasi
  category?: "secret" | "outdated-library" | "generic";
}

// --- Deep crawl: peta relasi page -> js -> endpoint ---
export type GraphNodeType = "page" | "js" | "endpoint";

export interface GraphNode {
  id: string; // biasanya URL/path, dibuat unik per type dengan prefix
  type: GraphNodeType;
  label: string;
  depth?: number; // hanya untuk node type "page"
}

export interface GraphEdge {
  from: string; // GraphNode.id
  to: string; // GraphNode.id
}

export interface GraphData {
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface CrawledPage {
  url: string;
  depth: number;
  scripts: string[];
  status: number;
}

export interface LibraryDetection {
  name: string;
  version: string;
  source: string; // file/halaman tempat versi terdeteksi
  cve?: string;
  cveSeverity?: Severity;
  cveUrl?: string;
}

export type ScanStatus =
  | "queued"
  | "crawling"
  | "analyzing_js"
  | "scanning_secrets"
  | "fingerprinting_libraries"
  | "testing"
  | "blocked_cloudflare"
  | "done"
  | "error";

export interface ScanLogEvent {
  type: "log" | "status" | "finding" | "done" | "error" | "blocked" | "endpoints";
  message?: string;
  status?: ScanStatus;
  finding?: Finding;
  endpoints?: DiscoveredEndpoint[];
  timestamp: number;
}

export interface ScanState {
  id: string;
  domain: string;
  origin: string;
  status: ScanStatus;
  createdAt: number;
  logs: ScanLogEvent[];
  findings: Finding[];
  endpoints: DiscoveredEndpoint[];
  endpointsDiscovered: number;
  requestsMade: number;
  blockedReason?: string;
  graph: GraphData;
  pagesCrawled: number;
  jsFilesScanned: number;
  librariesDetected: LibraryDetection[];
}
