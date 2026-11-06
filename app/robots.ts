import type { MetadataRoute } from "next";
import { SITE_URL } from "@/lib/seo-master";

export default function robots(): MetadataRoute.Robots {
  return {
    rules: [
      {
        userAgent: "*",
        allow: [
          "/",
          "/scan/seo-master",
          "/scan/sentinel",
          "/scan/headers",
          "/scan/secrets",
          "/scan/exposure",
          "/scan/js",
          "/scan/ssl",
          "/scan/map",
          "/scan/subdomain",
          "/scan/dns",
          "/scan/stack",
          "/scan/breach",
          "/scan/osint",
          "/scan/shield-status",
          "/qc",
          "/docs",
          "/api-docs",
          "/history",
          "/maintenance-log",
        ],
        disallow: [
          "/api/",
          "/admin/",
          "/requests/",
          "/_next/",
        ],
      },
      {
        userAgent: [
          "Googlebot",
          "Googlebot-Image",
          "Bingbot",
          "Applebot",
          "DuckDuckBot",
          "OAI-SearchBot",
          "ChatGPT-User",
          "PerplexityBot",
          "ClaudeBot",
        ],
        allow: ["/"],
        disallow: ["/api/", "/admin/", "/requests/"],
      },
    ],
    host: SITE_URL,
    sitemap: `${SITE_URL}/sitemap.xml`,
  };
}