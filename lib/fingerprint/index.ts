/**
 * lib/fingerprint/index.ts
 *
 * Pure TS tech-stack fingerprinting dari response headers + HTML body.
 * Tidak melakukan fetch apapun (headers/html dikasih dari luar oleh
 * pemanggil, mis. hasil crawl yang sudah ada) — 100% pure function.
 */

export interface TechStack {
  name: string;
  category: "framework" | "cms" | "server" | "language" | "library" | "cdn" | "other";
  evidence: string;
  confidence: "low" | "medium" | "high";
}

interface HeaderRule {
  header: string;
  /** kalau di-set, value header harus match regex ini; kalau tidak, cukup "header exists" */
  valueRegex?: RegExp;
  name: string;
  category: TechStack["category"];
  confidence: TechStack["confidence"];
}

interface HtmlRule {
  needle: string | RegExp;
  name: string;
  category: TechStack["category"];
  confidence: TechStack["confidence"];
}

const HEADER_RULES: HeaderRule[] = [
  { header: "x-powered-by", valueRegex: /express/i, name: "Express.js", category: "framework", confidence: "high" },
  { header: "x-powered-by", valueRegex: /next\.js/i, name: "Next.js", category: "framework", confidence: "high" },
  { header: "x-powered-by", valueRegex: /php/i, name: "PHP", category: "language", confidence: "high" },
  { header: "x-powered-by", valueRegex: /asp\.net/i, name: "ASP.NET", category: "framework", confidence: "high" },
  // fallback generik kalau x-powered-by ada tapi ga cocok pattern spesifik di atas
  { header: "x-powered-by", name: "Unknown (x-powered-by present)", category: "other", confidence: "low" },
  { header: "server", valueRegex: /nginx/i, name: "Nginx", category: "server", confidence: "high" },
  { header: "server", valueRegex: /apache/i, name: "Apache", category: "server", confidence: "high" },
  { header: "server", valueRegex: /cloudflare/i, name: "Cloudflare", category: "cdn", confidence: "high" },
  { header: "x-vercel-id", name: "Vercel", category: "cdn", confidence: "high" },
  { header: "x-generator", valueRegex: /drupal/i, name: "Drupal", category: "cms", confidence: "high" },
];

const COOKIE_RULES: { pattern: RegExp; name: string; category: TechStack["category"]; confidence: TechStack["confidence"] }[] = [
  { pattern: /\bPHPSESSID=/i, name: "PHP", category: "language", confidence: "medium" },
  { pattern: /\bJSESSIONID=/i, name: "Java (Servlet/JSP)", category: "language", confidence: "medium" },
  { pattern: /\bASP\.NET_SessionId=/i, name: "ASP.NET", category: "framework", confidence: "medium" },
  { pattern: /\bcsrftoken=/i, name: "Django", category: "framework", confidence: "low" },
  { pattern: /\blaravel_session=/i, name: "Laravel", category: "framework", confidence: "high" },
  { pattern: /\b_shopify_/i, name: "Shopify", category: "cms", confidence: "high" },
];

const HTML_RULES: HtmlRule[] = [
  { needle: "wp-content", name: "WordPress", category: "cms", confidence: "high" },
  { needle: "wp-includes", name: "WordPress", category: "cms", confidence: "high" },
  { needle: "__NEXT_DATA__", name: "Next.js", category: "framework", confidence: "high" },
  { needle: "data-reactroot", name: "React", category: "framework", confidence: "medium" },
  { needle: /id="__next"/i, name: "Next.js", category: "framework", confidence: "medium" },
  { needle: "ng-version", name: "Angular", category: "framework", confidence: "high" },
  { needle: /data-v-app|__VUE__/i, name: "Vue.js", category: "framework", confidence: "medium" },
  { needle: "cdn.shopify.com", name: "Shopify", category: "cms", confidence: "high" },
  { needle: "/wp-json/", name: "WordPress (REST API)", category: "cms", confidence: "high" },
  { needle: "csrf-token", name: "Laravel (likely)", category: "framework", confidence: "low" },
];

function dedupe(stacks: TechStack[]): TechStack[] {
  const byName = new Map<string, TechStack>();
  for (const s of stacks) {
    const existing = byName.get(s.name);
    // kalau ada 2 evidence utk nama yang sama, keep yang confidence-nya lebih tinggi
    const rank = { low: 0, medium: 1, high: 2 } as const;
    if (!existing || rank[s.confidence] > rank[existing.confidence]) {
      byName.set(s.name, s);
    }
  }
  return Array.from(byName.values());
}

/**
 * Fingerprint tech stack dari response headers + HTML body.
 * Pure function — tidak melakukan network request sendiri.
 */
export function fingerprint(headers: Headers, html: string): TechStack[] {
  const found: TechStack[] = [];

  for (const rule of HEADER_RULES) {
    const value = headers.get(rule.header);
    if (value === null) continue;
    if (rule.valueRegex && !rule.valueRegex.test(value)) continue;
    found.push({
      name: rule.name,
      category: rule.category,
      confidence: rule.confidence,
      evidence: `header ${rule.header}: ${value}`,
    });
  }

  // NOTE: di browser, Fetch API menyembunyikan header "set-cookie" dari response
  // cross-origin (forbidden response-header) untuk alasan keamanan — jadi field ini
  // sering kosong kalau `headers` datang dari fetch() beneran di client. Tetap
  // dicek di sini supaya fungsi tetap berguna kalau `headers` datang dari sumber
  // lain (mis. proxy internal / same-origin fetch / testing).
  const setCookie = headers.get("set-cookie") ?? "";
  if (setCookie) {
    for (const rule of COOKIE_RULES) {
      if (rule.pattern.test(setCookie)) {
        found.push({
          name: rule.name,
          category: rule.category,
          confidence: rule.confidence,
          evidence: `set-cookie matched ${rule.pattern}`,
        });
      }
    }
  }

  if (html) {
    for (const rule of HTML_RULES) {
      const matched = typeof rule.needle === "string" ? html.includes(rule.needle) : rule.needle.test(html);
      if (matched) {
        found.push({
          name: rule.name,
          category: rule.category,
          confidence: rule.confidence,
          evidence: `html contains ${typeof rule.needle === "string" ? `"${rule.needle}"` : rule.needle.toString()}`,
        });
      }
    }
  }

  return dedupe(found);
}
