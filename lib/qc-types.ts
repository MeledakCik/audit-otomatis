export type QcIssueLevel = "critical" | "warning" | "info";

export interface QcIssue {
  level: QcIssueLevel;
  msg: string;
}

// --- Modul 1: SEO ---
export interface QcSeoResult {
  score: number; // 0-100
  issues: QcIssue[];
  meta: {
    title: string | null;
    titleLength: number;
    metaDescription: string | null;
    metaDescriptionLength: number;
    h1Count: number;
    imgTotal: number;
    imgWithoutAlt: number;
    canonical: string | null;
    ogTagsFound: string[];
  };
}

// --- Modul 2: Performance ---
export interface QcPerfMetrics {
  lcp: string | null; // e.g. "2.4 s"
  cls: string | null; // e.g. "0.05"
  fcp: string | null;
  tbt: string | null;
  sizeBytes: number | null;
  modernImageFormat: boolean | null; // true kalau webp/avif terdeteksi
  cacheHeaders: boolean | null; // true kalau Cache-Control terdeteksi masuk akal
  lazyLoading: boolean | null;
  source: "pagespeed" | "fallback";
  lcpElement: {
    snippet: string | null; // cuplikan HTML elemen LCP (mis. <img src="...">)
    selector: string | null; // CSS selector elemen tsb di halaman
    isLazyLoaded: boolean | null; // true = gambar LCP-nya kena lazy-load (biasanya kontraproduktif)
  } | null;
}

export interface QcPerfResult {
  score: number; // 0-100
  issues: QcIssue[];
  metrics: QcPerfMetrics;
}

// --- Modul 3: Content / Link ---
export interface QcContentResult {
  score: number; // 0-100
  brokenLinks: string[];
  a11yIssues: QcIssue[];
  checked: {
    linksChecked: number;
    formsChecked: number;
    anchorsChecked: number;
  };
}

export type QcModuleKey = "seo" | "perf" | "content";

export interface QcModulesSelection {
  seo: boolean;
  perf: boolean;
  content: boolean;
}

export type QcStatus =
  | "queued"
  | "crawling"
  | "running_seo"
  | "running_perf"
  | "running_content"
  | "done"
  | "error";

export interface QcResult {
  seo?: QcSeoResult;
  perf?: QcPerfResult;
  content?: QcContentResult;
  overallScore?: number;
}

export interface QcLogEvent {
  type: "log" | "status" | "module_done" | "done" | "error";
  message?: string;
  status?: QcStatus;
  module?: QcModuleKey;
  timestamp: number;
}

export interface QcState {
  id: string;
  domain: string;
  origin: string;
  modules: QcModulesSelection;
  status: QcStatus;
  createdAt: number;
  logs: QcLogEvent[];
  result: QcResult;
  requestsMade: number;
  error?: string;
}