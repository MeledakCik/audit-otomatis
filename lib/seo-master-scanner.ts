// lib/seo-master-scanner.ts
import { chromeHeaders, detectCloudflareChallenge } from "./crawler";
import { analyzeSeo } from "./qc-seo";
import type { QcSeoResult } from "./qc-types";

export interface SeoMasterTargetAudit {
  domain: string;
  origin: string;
  scannedAt: number;
  responseTimeMs: number;
  statusCode: number;
  seo: QcSeoResult;
  crawlability: {
    robotsTxtPresent: boolean;
    robotsTxtAllowsRoot: boolean;
    robotsTxtHasSitemap: boolean;
    robotsTxtSnippet: string | null;
    sitemapXmlPresent: boolean;
    sitemapUrlCount: number;
  };
  securitySeoTrust: {
    hasHsts: boolean;
    hasCsp: boolean;
    hasXFrameOptions: boolean;
    hasXContentTypeOptions: boolean;
    hasReferrerPolicy: boolean;
    serverHeader: string | null;
    xRobotsTagHeader: string | null;
    trustScore: number; // 0-100
  };
  generatedSnippets: {
    htmlHeadTags: string;
    nextJsMetadataCode: string;
    jsonLdSchemaCode: string;
    robotsTxtRecommended: string;
  };
  overallMasterScore: number; // 0-100
  rankReadinessGrade: "A+" | "A" | "B" | "C" | "D";
}

function computeGrade(score: number): "A+" | "A" | "B" | "C" | "D" {
  if (score >= 92) return "A+";
  if (score >= 82) return "A";
  if (score >= 70) return "B";
  if (score >= 55) return "C";
  return "D";
}

function buildGeneratedSnippets(
  origin: string,
  domain: string,
  seo: QcSeoResult,
  targetKeyword?: string
) {
  const title =
    seo.meta.title ||
    `${domain} — ${targetKeyword || "Official Platform & Global Solutions"}`;
  const desc =
    seo.meta.metaDescription ||
    `Discover ${domain}: trusted global platform for ${targetKeyword || "high-performance digital services"}. Fast, secure, and verified.`;
  const keywords =
    targetKeyword ||
    (seo.meta.topKeywords.length > 0
      ? seo.meta.topKeywords.slice(0, 8).map((k) => k.word).join(", ")
      : `${domain}, global platform, official website`);

  const htmlHeadTags = `<!-- SEO Master & International Rank #1 Head Tags for ${domain} -->
<title>${title}</title>
<meta name="description" content="${desc}" />
<meta name="keywords" content="${keywords}" />
<meta name="robots" content="index, follow, max-image-preview:large, max-snippet:-1, max-video-preview:-1" />
<link rel="canonical" href="${origin}" />

<!-- International Hreflang Multi-Region Tags (Global Google SERP) -->
<link rel="alternate" hreflang="x-default" href="${origin}" />
<link rel="alternate" hreflang="id-ID" href="${origin}" />
<link rel="alternate" hreflang="en-US" href="${origin}?hl=en" />
<link rel="alternate" hreflang="en-GB" href="${origin}?hl=en-gb" />
<link rel="alternate" hreflang="en-SG" href="${origin}?hl=en-sg" />
<link rel="alternate" hreflang="en-AU" href="${origin}?hl=en-au" />
<link rel="alternate" hreflang="ms-MY" href="${origin}?hl=ms" />
<link rel="alternate" hreflang="ja-JP" href="${origin}?hl=ja" />
<link rel="alternate" hreflang="de-DE" href="${origin}?hl=de" />

<!-- Open Graph & Multi-Locale Social Tags -->
<meta property="og:type" content="website" />
<meta property="og:site_name" content="${domain}" />
<meta property="og:title" content="${title}" />
<meta property="og:description" content="${desc}" />
<meta property="og:url" content="${origin}" />
<meta property="og:image" content="${origin}/og-image.png" />
<meta property="og:locale" content="en_US" />
<meta property="og:locale:alternate" content="id_ID" />
<meta property="og:locale:alternate" content="en_GB" />
<meta property="og:locale:alternate" content="en_SG" />

<!-- Twitter / X Large Summary Card -->
<meta name="twitter:card" content="summary_large_image" />
<meta name="twitter:title" content="${title}" />
<meta name="twitter:description" content="${desc}" />
<meta name="twitter:image" content="${origin}/og-image.png" />`;

  const jsonLdObj = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "Organization",
        "@id": `${origin}/#organization`,
        name: domain,
        url: origin,
        logo: `${origin}/logo.png`,
        areaServed: "Worldwide",
        knowsLanguage: ["id-ID", "en-US", "en-GB", "en-SG"],
      },
      {
        "@type": "WebSite",
        "@id": `${origin}/#website`,
        url: origin,
        name: title,
        description: desc,
        publisher: { "@id": `${origin}/#organization` },
        inLanguage: ["id-ID", "en-US"],
        potentialAction: {
          "@type": "SearchAction",
          target: `${origin}/search?q={search_term_string}`,
          "query-input": "required name=search_term_string",
        },
      },
    ],
  };

  const jsonLdSchemaCode = `<script type="application/ld+json">\n${JSON.stringify(
    jsonLdObj,
    null,
    2
  )}\n</script>`;

  const nextJsMetadataCode = `// app/layout.tsx — Next.js App Router International SEO Master Config
import type { Metadata } from "next";

export const metadata: Metadata = {
  metadataBase: new URL("${origin}"),
  title: {
    default: ${JSON.stringify(title)},
    template: "%s | ${domain}",
  },
  description: ${JSON.stringify(desc)},
  keywords: ${JSON.stringify(keywords.split(",").map((s) => s.trim()))},
  alternates: {
    canonical: "${origin}",
    languages: {
      "x-default": "${origin}",
      "id-ID": "${origin}",
      "en-US": "${origin}?hl=en",
      "en-GB": "${origin}?hl=en-gb",
      "en-SG": "${origin}?hl=en-sg",
      "en-AU": "${origin}?hl=en-au",
      "ms-MY": "${origin}?hl=ms",
      "ja-JP": "${origin}?hl=ja",
      "de-DE": "${origin}?hl=de",
    },
  },
  openGraph: {
    title: ${JSON.stringify(title)},
    description: ${JSON.stringify(desc)},
    url: "${origin}",
    siteName: "${domain}",
    locale: "en_US",
    alternateLocale: ["id_ID", "en_GB", "en_SG", "en_AU"],
    type: "website",
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-image-preview": "large",
      "max-snippet": -1,
      "max-video-preview": -1,
    },
  },
};`;

  const robotsTxtRecommended = `User-agent: *
Allow: /
Disallow: /admin/
Disallow: /api/

User-agent: Googlebot
Allow: /

User-agent: Bingbot
Allow: /

User-agent: OAI-SearchBot
Allow: /

User-agent: PerplexityBot
Allow: /

Host: ${origin}
Sitemap: ${origin}/sitemap.xml`;

  return {
    htmlHeadTags,
    nextJsMetadataCode,
    jsonLdSchemaCode,
    robotsTxtRecommended,
  };
}

export async function runSeoMasterAudit(
  origin: string,
  hostname: string,
  targetKeyword?: string
): Promise<SeoMasterTargetAudit> {
  const start = Date.now();

  const homeRes = await fetch(origin, {
    method: "GET",
    headers: chromeHeaders(),
    redirect: "follow",
    signal: AbortSignal.timeout(15000),
  });

  const responseTimeMs = Date.now() - start;
  const html = await homeRes.text();
  const cf = detectCloudflareChallenge(homeRes.status, homeRes.headers, html.slice(0, 2000));
  if (cf) {
    throw new Error(
      `Domain ${hostname} dilindungi Cloudflare Challenge (${cf.reason}) sehingga HTML tidak dapat dianalisis secara pasif.`
    );
  }

  const seo = analyzeSeo(html, origin);

  // Security-SEO Trust Signals from response headers
  const hasHsts = Boolean(homeRes.headers.get("strict-transport-security"));
  const hasCsp = Boolean(homeRes.headers.get("content-security-policy"));
  const hasXFrameOptions = Boolean(homeRes.headers.get("x-frame-options"));
  const hasXContentTypeOptions = Boolean(homeRes.headers.get("x-content-type-options"));
  const hasReferrerPolicy = Boolean(homeRes.headers.get("referrer-policy"));
  const serverHeader = homeRes.headers.get("server");
  const xRobotsTagHeader = homeRes.headers.get("x-robots-tag");

  let trustScore = 40; // HTTPS base
  if (hasHsts) trustScore += 20;
  if (hasCsp) trustScore += 15;
  if (hasXContentTypeOptions) trustScore += 10;
  if (hasReferrerPolicy) trustScore += 10;
  if (hasXFrameOptions) trustScore += 5;
  if (xRobotsTagHeader && /noindex/i.test(xRobotsTagHeader)) {
    trustScore = Math.max(0, trustScore - 50);
    seo.issues.unshift({
      level: "critical",
      msg: `HTTP Header X-Robots-Tag bernilai "${xRobotsTagHeader}" (memblokir Googlebot di level HTTP header!).`,
    });
  }

  // Parallel passive check for /robots.txt and /sitemap.xml
  const [robotsCheck, sitemapCheck] = await Promise.allSettled([
    fetch(`${origin}/robots.txt`, {
      method: "GET",
      headers: chromeHeaders(),
      redirect: "follow",
      signal: AbortSignal.timeout(6000),
    }),
    fetch(`${origin}/sitemap.xml`, {
      method: "GET",
      headers: chromeHeaders(),
      redirect: "follow",
      signal: AbortSignal.timeout(6000),
    }),
  ]);

  let robotsTxtPresent = false;
  let robotsTxtAllowsRoot = true;
  let robotsTxtHasSitemap = false;
  let robotsTxtSnippet: string | null = null;

  if (robotsCheck.status === "fulfilled" && robotsCheck.value.ok) {
    const rText = await robotsCheck.value.text();
    if (rText && /user-agent/i.test(rText)) {
      robotsTxtPresent = true;
      robotsTxtSnippet = rText.slice(0, 700);
      robotsTxtHasSitemap = /sitemap:/i.test(rText);
      if (/Disallow:\s*\/\s*$/im.test(rText)) {
        robotsTxtAllowsRoot = false;
      }
    }
  }

  let sitemapXmlPresent = false;
  let sitemapUrlCount = 0;

  if (sitemapCheck.status === "fulfilled" && sitemapCheck.value.ok) {
    const sText = await sitemapCheck.value.text();
    if (sText && (sText.includes("<urlset") || sText.includes("<sitemapindex"))) {
      sitemapXmlPresent = true;
      const matches = sText.match(/<loc>/gi);
      sitemapUrlCount = matches ? matches.length : 0;
    }
  }

  if (!robotsTxtPresent) {
    seo.issues.push({
      level: "warning",
      msg: "File /robots.txt tidak ditemukan atau tidak valid.",
    });
    seo.recommendations.push("Buat /robots.txt yang mengizinkan Googlebot dan mencantumkan Sitemap: https://domain/sitemap.xml.");
  }
  if (!sitemapXmlPresent) {
    seo.issues.push({
      level: "warning",
      msg: "File /sitemap.xml tidak ditemukan — menghambat penemuan halaman baru oleh Googlebot.",
    });
    seo.recommendations.push("Aktifkan /sitemap.xml dinamis lengkap dengan atribut xhtml:link hreflang.");
  }

  const crawlScore =
    (robotsTxtPresent ? 40 : 0) +
    (robotsTxtAllowsRoot ? 20 : 0) +
    (sitemapXmlPresent ? 40 : 0);

  const overallMasterScore = Math.max(
    0,
    Math.min(
      100,
      Math.round(seo.score * 0.65 + crawlScore * 0.2 + trustScore * 0.15)
    )
  );

  const generatedSnippets = buildGeneratedSnippets(origin, hostname, seo, targetKeyword);

  return {
    domain: hostname,
    origin,
    scannedAt: Date.now(),
    responseTimeMs,
    statusCode: homeRes.status,
    seo,
    crawlability: {
      robotsTxtPresent,
      robotsTxtAllowsRoot,
      robotsTxtHasSitemap,
      robotsTxtSnippet,
      sitemapXmlPresent,
      sitemapUrlCount,
    },
    securitySeoTrust: {
      hasHsts,
      hasCsp,
      hasXFrameOptions,
      hasXContentTypeOptions,
      hasReferrerPolicy,
      serverHeader,
      xRobotsTagHeader,
      trustScore,
    },
    generatedSnippets,
    overallMasterScore,
    rankReadinessGrade: computeGrade(overallMasterScore),
  };
}
