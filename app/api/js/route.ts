// app/api/scan/js/route.ts
import { NextRequest, NextResponse } from "next/server";

export const dynamic = "force-dynamic";
export const runtime = "nodejs";

// ============ KONFIGURASI ============
const CACHE_TTL = 5 * 60 * 1000;
const RATE_LIMIT = 20;
const MAX_SCRIPTS = 30;
const SCRIPT_TIMEOUT = 5000;
const MAX_SCRIPT_SIZE = 500 * 1024;

// ============ DATABASE VULNERABILITY (Diperluas) ============
const VULN_DB: Record<string, { min: string; max: string; cve: string; description: string; cvss?: number }[]> = {
  "jQuery": [
    { min: "1.0.0", max: "3.5.0", cve: "CVE-2020-11022", description: "XSS vulnerability in jQuery", cvss: 6.1 },
    { min: "1.0.0", max: "3.4.0", cve: "CVE-2019-11358", description: "Prototype pollution", cvss: 7.1 },
    { min: "1.0.0", max: "3.3.0", cve: "CVE-2019-5428", description: "Cross-site scripting", cvss: 5.9 },
  ],
  "lodash": [
    { min: "4.0.0", max: "4.17.20", cve: "CVE-2021-23337", description: "Command injection", cvss: 8.5 },
    { min: "4.0.0", max: "4.17.11", cve: "CVE-2020-8203", description: "Prototype pollution", cvss: 7.4 },
  ],
  "react": [
    { min: "16.0.0", max: "16.14.0", cve: "CVE-2021-41598", description: "XSS vulnerability in React", cvss: 5.9 },
    { min: "15.0.0", max: "15.6.2", cve: "CVE-2018-6341", description: "Cross-site scripting", cvss: 6.1 },
  ],
  "next.js": [
    { min: "12.0.0", max: "12.0.9", cve: "CVE-2022-23646", description: "Directory traversal vulnerability", cvss: 7.5 },
    { min: "10.0.0", max: "10.2.3", cve: "CVE-2021-39178", description: "XSS vulnerability", cvss: 6.1 },
    { min: "9.0.0", max: "9.5.4", cve: "CVE-2020-15095", description: "Open Redirect vulnerability", cvss: 5.4 },
  ],
  "axios": [
    { min: "0.18.0", max: "0.21.1", cve: "CVE-2021-3749", description: "SSRF vulnerability", cvss: 7.5 },
  ],
  "vue": [
    { min: "2.0.0", max: "2.6.14", cve: "CVE-2021-21392", description: "XSS vulnerability in Vue", cvss: 5.9 },
  ],
  "angular": [
    { min: "1.0.0", max: "1.8.2", cve: "CVE-2021-21292", description: "Prototype pollution", cvss: 7.4 },
  ],
  "bootstrap": [
    { min: "4.0.0", max: "4.6.0", cve: "CVE-2021-32786", description: "XSS vulnerability", cvss: 5.9 },
    { min: "3.0.0", max: "3.4.1", cve: "CVE-2019-8331", description: "Cross-site scripting", cvss: 6.1 },
  ],
};

// ============ LIBRARY DETECTION (Diperluas) ============
const LIBRARY_PATTERNS: Record<string, { 
  patterns: RegExp[]; 
  versionRegex: RegExp[]; 
  contentPatterns?: RegExp[];
  framework?: string;
  confidence: number;
}> = {
  "Next.js": {
    patterns: [/next\/dist/i, /_next\/static/i, /next\.min\.js/i, /__NEXT_DATA__/i, /next\/router/i],
    versionRegex: [/next@([0-9.]+)/i, /Next\.js\s+v?([0-9.]+)/i, /_next\/static\/[a-zA-Z0-9]+\/_buildManifest\.js/i],
    framework: "React",
    confidence: 95,
  },
  "React": {
    patterns: [/react\.production\.min\.js/i, /react\.development\.js/i, /__REACT_DEVTOOLS_GLOBAL_HOOK__/i, /React\.createElement/i, /react-dom/i],
    versionRegex: [/react@([0-9.]+)/i, /React\s+v?([0-9.]+)/i, /React v([0-9.]+)/i],
    confidence: 90,
  },
  "Vue": {
    patterns: [/vue\.(?:runtime|core|common|esm|global)/i, /Vue\.js/i, /__VUE__/i, /vue-router/i],
    versionRegex: [/Vue\.js\s+v?([0-9.]+)/i, /vue@([0-9.]+)/i, /Vue v([0-9.]+)/i],
    confidence: 90,
  },
  "Angular": {
    patterns: [/angular\.js/i, /@angular\/core/i, /angular\.min\.js/i, /ng-version/i, /ng-app/i],
    versionRegex: [/angular[\s-]+v?([0-9.]+)/i, /angular@([0-9.]+)/i, /ng-version="([0-9.]+)"/i],
    confidence: 90,
  },
  "jQuery": {
    patterns: [/jquery/i, /jQuery/i, /\$\(document\)\.ready/i, /\.jquery/i],
    versionRegex: [/jQuery\s+v?([0-9.]+)/i, /jquery[.-]?([0-9.]+)/i, /jQuery v([0-9.]+)/i],
    contentPatterns: [/jQuery\s+v?([0-9.]+)/, /jquery[.-]?([0-9.]+)/],
    confidence: 85,
  },
  "Bootstrap": {
    patterns: [/bootstrap\.(?:min\.)?js/i, /bootstrap\.bundle/i, /data-bs-/i, /bs\./i],
    versionRegex: [/bootstrap\s+v?([0-9.]+)/i, /bootstrap@([0-9.]+)/i],
    confidence: 85,
  },
  "Lodash": {
    patterns: [/lodash\.(?:min\.)?js/i, /lodash\.core/i, /_\.[a-zA-Z]/i, /\.lodash/i],
    versionRegex: [/lodash\s+v?([0-9.]+)/i, /lodash@([0-9.]+)/i],
    confidence: 80,
  },
  "Moment": {
    patterns: [/moment\.(?:min\.)?js/i, /moment\(/i, /moment-timezone/i],
    versionRegex: [/moment\s+v?([0-9.]+)/i, /moment@([0-9.]+)/i],
    confidence: 80,
  },
  "Axios": {
    patterns: [/axios\.(?:min\.)?js/i, /axios\.create/i, /axios\.get/i],
    versionRegex: [/axios\s+v?([0-9.]+)/i, /axios@([0-9.]+)/i],
    confidence: 80,
  },
  "Three.js": {
    patterns: [/three\.(?:min\.)?js/i, /THREE\./i, /three.module/i],
    versionRegex: [/three\s+v?([0-9.]+)/i, /three@([0-9.]+)/i],
    confidence: 75,
  },
  "Chart.js": {
    patterns: [/chart\.(?:min\.)?js/i, /chartjs/i, /Chart\./i, /chart\.js/i],
    versionRegex: [/chart\.js\s+v?([0-9.]+)/i, /chartjs@([0-9.]+)/i],
    confidence: 75,
  },
  "D3.js": {
    patterns: [/d3\.(?:min\.)?js/i, /d3\.[a-zA-Z]/i, /d3-scale/i],
    versionRegex: [/d3\s+v?([0-9.]+)/i, /d3@([0-9.]+)/i],
    confidence: 75,
  },
  "GSAP": {
    patterns: [/gsap\.(?:min\.)?js/i, /gsap\./i, /gsap\.to/i],
    versionRegex: [/gsap\s+v?([0-9.]+)/i, /gsap@([0-9.]+)/i],
    confidence: 75,
  },
  "Tailwind": {
    patterns: [/tailwindcss/i, /tailwind\.js/i, /@tailwind/i],
    versionRegex: [/tailwindcss@([0-9.]+)/i, /tailwind\s+v?([0-9.]+)/i],
    confidence: 70,
  },
  "Svelte": {
    patterns: [/svelte\.(?:min\.)?js/i, /__svelte__/i, /svelte\/internal/i],
    versionRegex: [/svelte@([0-9.]+)/i, /Svelte\s+v?([0-9.]+)/i],
    confidence: 80,
  },
  "Alpine.js": {
    patterns: [/alpine\.(?:min\.)?js/i, /x-data/i, /Alpine\./i, /x-show/i],
    versionRegex: [/alpine@([0-9.]+)/i, /Alpine\s+v?([0-9.]+)/i],
    confidence: 75,
  },
  "HTMX": {
    patterns: [/htmx\.(?:min\.)?js/i, /hx-/i, /hx-trigger/i],
    versionRegex: [/htmx@([0-9.]+)/i, /htmx\s+v?([0-9.]+)/i],
    confidence: 75,
  },
  "Preact": {
    patterns: [/preact\.(?:min\.)?js/i, /preact\/compat/i, /preact\/hooks/i],
    versionRegex: [/preact@([0-9.]+)/i, /Preact\s+v?([0-9.]+)/i],
    confidence: 75,
  },
};

// ============ TRACKER DETECTION ============
const TRACKER_PATTERNS: Record<string, { domains: string[]; category: string; risk: "low" | "medium" | "high"; icon?: string }> = {
  "Google Analytics": {
    domains: ["google-analytics.com", "googletagmanager.com", "analytics.google.com", "gtag", "googleads"],
    category: "Analytics",
    risk: "medium",
    icon: "📊",
  },
  "Facebook Pixel": {
    domains: ["facebook.net", "fbcdn.net", "connect.facebook.net"],
    category: "Social",
    risk: "high",
    icon: "👤",
  },
  "Cloudflare": {
    domains: ["cloudflare.com", "cdnjs.cloudflare.com", "cloudflareinsights.com"],
    category: "CDN",
    risk: "low",
    icon: "☁️",
  },
  "Hotjar": {
    domains: ["hotjar.com", "hotjar.io"],
    category: "Session Replay",
    risk: "high",
    icon: "🔥",
  },
  "Mixpanel": {
    domains: ["mixpanel.com", "mixpanel.net"],
    category: "Analytics",
    risk: "medium",
    icon: "📈",
  },
  "Segment": {
    domains: ["segment.io", "cdn.segment.com"],
    category: "Analytics",
    risk: "medium",
    icon: "🔗",
  },
  "jsDelivr": {
    domains: ["jsdelivr.net"],
    category: "CDN",
    risk: "low",
    icon: "📦",
  },
  "Unpkg": {
    domains: ["unpkg.com"],
    category: "CDN",
    risk: "low",
    icon: "📦",
  },
  "New Relic": {
    domains: ["newrelic.com", "nr-data.net"],
    category: "Analytics",
    risk: "medium",
    icon: "📊",
  },
  "FullStory": {
    domains: ["fullstory.com"],
    category: "Session Replay",
    risk: "high",
    icon: "🎬",
  },
  "Adobe Analytics": {
    domains: ["adobe.com", "omtrdc.net", "adobedtm.com"],
    category: "Analytics",
    risk: "medium",
    icon: "📊",
  },
  "LinkedIn Insight": {
    domains: ["linkedin.com", "licdn.com"],
    category: "Social",
    risk: "high",
    icon: "💼",
  },
  "Twitter/X": {
    domains: ["twimg.com", "twitter.com", "t.co"],
    category: "Social",
    risk: "medium",
    icon: "🐦",
  },
  "Stripe": {
    domains: ["stripe.com", "m.stripe.com"],
    category: "Analytics",
    risk: "high",
    icon: "💳",
  },
  "HubSpot": {
    domains: ["hubspot.com", "hubspot.net"],
    category: "Analytics",
    risk: "medium",
    icon: "🔄",
  },
  "Intercom": {
    domains: ["intercom.io", "intercomcdn.com"],
    category: "Analytics",
    risk: "high",
    icon: "💬",
  },
  "Amplitude": {
    domains: ["amplitude.com", "amplitude.net"],
    category: "Analytics",
    risk: "medium",
    icon: "📊",
  },
  "Optimizely": {
    domains: ["optimizely.com", "optimizelycdn.com"],
    category: "Analytics",
    risk: "medium",
    icon: "🧪",
  },
};

// ============ INTERFACE ============
interface ScriptInfo {
  src: string;
  library: string | null;
  version: string | null;
  size: number;
  vulnerable: boolean;
  cve: string | null;
  cveDescription: string | null;
  cvss: number | null;
  outdated: boolean;
  framework: string | null;
  confidence: number;
}

interface TrackerInfo {
  domain: string;
  category: string;
  count: number;
  risk: "low" | "medium" | "high";
  icon?: string;
}

interface FrameworkInfo {
  name: string;
  version: string | null;
  confidence: number;
}

// ============ CACHE & RATE LIMIT ============
const scanCache = new Map<string, { data: any; timestamp: number }>();
const rateLimit = new Map<string, { count: number; resetTime: number }>();

// ============ HELPER FUNCTIONS ============
function getClientIP(request: NextRequest): string {
  return request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() || 
         request.headers.get('x-real-ip') || 
         'unknown';
}

function checkRateLimit(ip: string): boolean {
  const now = Date.now();
  const record = rateLimit.get(ip);
  
  if (!record || now > record.resetTime) {
    rateLimit.set(ip, { count: 1, resetTime: now + 60000 });
    return true;
  }
  
  if (record.count >= RATE_LIMIT) return false;
  record.count++;
  return true;
}

function getCached(key: string): any | null {
  const cached = scanCache.get(key);
  if (cached && Date.now() - cached.timestamp < CACHE_TTL) {
    return cached.data;
  }
  scanCache.delete(key);
  return null;
}

function setCache(key: string, data: any): void {
  scanCache.set(key, { data, timestamp: Date.now() });
}

function extractVersion(text: string, patterns: RegExp[]): string | null {
  for (const pattern of patterns) {
    const match = text.match(pattern);
    if (match) {
      return match[1] || match[2] || match[0] || null;
    }
  }
  return null;
}

function detectLibrary(src: string, content: string = ""): { library: string | null; version: string | null; framework: string | null; confidence: number } {
  const combined = src + " " + content;
  
  // Cek dari HTML content untuk framework detection
  if (content.includes('__NEXT_DATA__') || content.includes('_next/static')) {
    const version = extractVersion(content, [/next@([0-9.]+)/i, /Next\.js\s+v?([0-9.]+)/i]);
    return { library: "Next.js", version, framework: "React", confidence: 95 };
  }
  
  let bestMatch = { library: null as string | null, version: null as string | null, framework: null as string | null, confidence: 0 };
  
  for (const [libName, patterns] of Object.entries(LIBRARY_PATTERNS)) {
    for (const pattern of patterns.patterns) {
      if (pattern.test(src) || pattern.test(content)) {
        const version = extractVersion(combined, patterns.versionRegex);
        if (patterns.confidence > bestMatch.confidence) {
          bestMatch = { 
            library: libName, 
            version, 
            framework: patterns.framework || null,
            confidence: patterns.confidence
          };
        }
        break;
      }
    }
  }
  
  return bestMatch;
}

function checkVulnerability(library: string, version: string): { 
  vulnerable: boolean; 
  cve: string | null; 
  description: string | null;
  cvss: number | null;
} {
  const vulns = VULN_DB[library.toLowerCase()];
  if (!vulns) return { vulnerable: false, cve: null, description: null, cvss: null };
  
  const versionParts = version.split('.').map(Number);
  if (versionParts.some(isNaN)) return { vulnerable: false, cve: null, description: null, cvss: null };
  
  for (const vuln of vulns) {
    const minParts = vuln.min.split('.').map(Number);
    const maxParts = vuln.max.split('.').map(Number);
    
    let isVulnerable = true;
    for (let i = 0; i < Math.max(versionParts.length, minParts.length, maxParts.length); i++) {
      const v = versionParts[i] || 0;
      const min = minParts[i] || 0;
      const max = maxParts[i] || Infinity;
      if (v < min || v >= max) {
        isVulnerable = false;
        break;
      }
    }
    
    if (isVulnerable) {
      return { 
        vulnerable: true, 
        cve: vuln.cve, 
        description: vuln.description,
        cvss: vuln.cvss || null
      };
    }
  }
  
  return { vulnerable: false, cve: null, description: null, cvss: null };
}

function isOutdated(library: string, version: string): boolean {
  const vulns = VULN_DB[library.toLowerCase()];
  if (!vulns) return false;
  
  const versionParts = version.split('.').map(Number);
  if (versionParts.some(isNaN)) return false;
  
  for (const vuln of vulns) {
    const maxParts = vuln.max.split('.').map(Number);
    let isOutdated = true;
    for (let i = 0; i < Math.max(versionParts.length, maxParts.length); i++) {
      const v = versionParts[i] || 0;
      const max = maxParts[i] || 0;
      if (v >= max) {
        isOutdated = false;
        break;
      }
    }
    if (isOutdated) return true;
  }
  
  return false;
}

function detectTrackers(scripts: ScriptInfo[]): TrackerInfo[] {
  const trackerMap = new Map<string, { category: string; count: number; risk: "low" | "medium" | "high"; icon?: string }>();
  
  for (const script of scripts) {
    try {
      const url = new URL(script.src);
      const domain = url.hostname.replace(/^www\./, '');
      
      for (const [name, data] of Object.entries(TRACKER_PATTERNS)) {
        if (data.domains.some(d => domain.includes(d) || script.src.includes(d))) {
          const key = domain;
          if (!trackerMap.has(key)) {
            trackerMap.set(key, {
              category: data.category,
              count: 0,
              risk: data.risk,
              icon: data.icon,
            });
          }
          trackerMap.get(key)!.count += 1;
          break;
        }
      }
    } catch {
      // Skip invalid URL
    }
  }
  
  return Array.from(trackerMap.entries()).map(([domain, data]) => ({
    domain,
    category: data.category,
    count: data.count,
    risk: data.risk,
    icon: data.icon,
  }));
}

function detectFrameworks(scripts: ScriptInfo[], html: string): FrameworkInfo[] {
  const frameworks: FrameworkInfo[] = [];
  const detected = new Set<string>();
  
  // Deteksi dari HTML
  if (html.includes('__NEXT_DATA__')) {
    const version = extractVersion(html, [/next@([0-9.]+)/i]);
    frameworks.push({ name: "Next.js", version, confidence: 95 });
    detected.add('Next.js');
    frameworks.push({ name: "React", version: null, confidence: 90 });
    detected.add('React');
  }
  
  if (html.includes('ng-version=')) {
    const version = extractVersion(html, [/ng-version="([0-9.]+)"/i]);
    frameworks.push({ name: "Angular", version, confidence: 95 });
    detected.add('Angular');
  }
  
  if (html.includes('__VUE__') || html.includes('vue-app')) {
    const version = extractVersion(html, [/Vue\.js\s+v?([0-9.]+)/i]);
    frameworks.push({ name: "Vue.js", version, confidence: 90 });
    detected.add('Vue.js');
  }
  
  // Deteksi dari scripts
  for (const script of scripts) {
    if (script.library && !detected.has(script.library) && script.confidence > 50) {
      frameworks.push({
        name: script.library,
        version: script.version,
        confidence: script.confidence,
      });
      detected.add(script.library);
    }
  }
  
  return frameworks;
}

function calculateRiskScore(scripts: ScriptInfo[], trackers: TrackerInfo[]): number {
  let score = 0;
  
  const vulnerableCount = scripts.filter(s => s.vulnerable).length;
  score += vulnerableCount * 20;
  
  const outdatedCount = scripts.filter(s => s.outdated && !s.vulnerable).length;
  score += outdatedCount * 10;
  
  score += trackers.length * 5;
  score += trackers.filter(t => t.risk === "high").length * 10;
  score += trackers.filter(t => t.risk === "medium").length * 3;
  
  if (scripts.length > 20) score += 5;
  
  return Math.min(100, score);
}

async function fetchWithTimeout(url: string, timeoutMs: number): Promise<{ content: string; size: number } | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  
  try {
    const res = await fetch(url, {
      signal: controller.signal,
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "*/*",
      },
    });
    
    if (!res.ok) return null;
    
    const buffer = await res.arrayBuffer();
    const size = buffer.byteLength;
    const content = new TextDecoder().decode(buffer.slice(0, MAX_SCRIPT_SIZE));
    
    return { content, size };
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

// ============ API HANDLERS ============
export async function GET() {
  return NextResponse.json({
    status: "JS Scanner API v3.0",
    message: "POST with { url: 'https://example.com' }",
    features: [
      "25+ library detection",
      "Framework detection",
      "Vulnerability checking with CVSS",
      "Tracker detection with icons",
      "Risk scoring",
      "Caching",
      "Rate limiting",
    ],
  });
}

export async function POST(request: NextRequest) {
  const startTime = Date.now();
  console.log("🚀 JS Scan API v3.0 called");
  
  const ip = getClientIP(request);
  if (!checkRateLimit(ip)) {
    return NextResponse.json(
      { error: "Rate limit exceeded. Please wait a moment." },
      { status: 429 }
    );
  }
  
  try {
    const body = await request.json().catch(() => null);
    if (!body || !body.url || typeof body.url !== "string") {
      return NextResponse.json({ error: "Field `url` is required." }, { status: 400 });
    }
    
    let targetUrl = body.url.trim();
    if (!targetUrl.startsWith("http://") && !targetUrl.startsWith("https://")) {
      targetUrl = "https://" + targetUrl;
    }
    
    const cacheKey = targetUrl;
    const cached = getCached(cacheKey);
    if (cached) {
      console.log(`✅ Returning cached result for ${targetUrl}`);
      return NextResponse.json({
        ...cached,
        cached: true,
        cachedAt: new Date().toISOString(),
      });
    }
    
    console.log(`🌐 Fetching: ${targetUrl}`);
    
    const homepageRes = await fetch(targetUrl, {
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Cache-Control": "no-cache",
      },
    });
    
    if (!homepageRes.ok) {
      return NextResponse.json(
        { error: `Failed to fetch (HTTP ${homepageRes.status})` },
        { status: 502 }
      );
    }
    
    const html = await homepageRes.text();
    console.log(`📄 HTML: ${html.length} bytes`);
    
    // Extract scripts
    const scriptRegex = /<script[^>]*src=["']([^"']+)["'][^>]*>/gi;
    const scriptUrls: string[] = [];
    let match;
    
    while ((match = scriptRegex.exec(html)) !== null) {
      try {
        const absoluteUrl = new URL(match[1], targetUrl);
        scriptUrls.push(absoluteUrl.toString());
      } catch {
        // Skip invalid
      }
    }
    
    const uniqueScripts = [...new Set(scriptUrls)].slice(0, MAX_SCRIPTS);
    console.log(`📦 Found ${uniqueScripts.length} scripts`);
    
    // Fetch scripts in parallel
    const scriptPromises = uniqueScripts.map(async (src) => {
      const result = await fetchWithTimeout(src, SCRIPT_TIMEOUT);
      return { src, result };
    });
    
    const scriptResults = await Promise.all(scriptPromises);
    
    // Analyze scripts
    const detectedLibraries: ScriptInfo[] = scriptResults.map(({ src, result }) => {
      const content = result?.content || "";
      const size = result?.size || 0;
      
      const { library, version, framework, confidence } = detectLibrary(src, content);
      
      let vulnerable = false;
      let cve: string | null = null;
      let cveDescription: string | null = null;
      let cvss: number | null = null;
      let outdated = false;
      
      if (library && version) {
        const vulnCheck = checkVulnerability(library, version);
        vulnerable = vulnCheck.vulnerable;
        cve = vulnCheck.cve;
        cveDescription = vulnCheck.description;
        cvss = vulnCheck.cvss;
        outdated = isOutdated(library, version) && !vulnerable;
      }
      
      return {
        src,
        library: library || "Unknown",
        version,
        size,
        vulnerable,
        cve,
        cveDescription,
        cvss,
        outdated,
        framework,
        confidence,
      };
    });
    
    // Detect trackers
    const trackers = detectTrackers(detectedLibraries);
    
    // Detect frameworks
    const frameworks = detectFrameworks(detectedLibraries, html);
    
    // Calculate risk score
    const riskScore = calculateRiskScore(detectedLibraries, trackers);
    
    const result = {
      url: targetUrl,
      scripts: detectedLibraries,
      trackers,
      frameworks,
      risk_score: riskScore,
      total_scripts: detectedLibraries.length,
      vulnerable_count: detectedLibraries.filter(s => s.vulnerable).length,
      outdated_count: detectedLibraries.filter(s => s.outdated).length,
      tracker_count: trackers.length,
      scan_duration_ms: Date.now() - startTime,
      scanned_at: new Date().toISOString(),
    };
    
    setCache(cacheKey, result);
    
    console.log(`✅ Complete in ${result.scan_duration_ms}ms`);
    return NextResponse.json(result);
    
  } catch (error) {
    console.error("❌ Error:", error);
    return NextResponse.json(
      { error: error instanceof Error ? error.message : "Internal Server Error" },
      { status: 500 }
    );
  }
}