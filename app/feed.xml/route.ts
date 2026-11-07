// app/feed.xml/route.ts
import { NextResponse } from "next/server";
import { SITE_URL, SITE_BRAND, SEO_ROUTES_REGISTRY } from "@/lib/seo-master";

function escapeXml(str: string): string {
  return str
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

export async function GET() {
  const now = new Date().toUTCString();
  const items = Object.values(SEO_ROUTES_REGISTRY)
    .map((route) => {
      const url = `${SITE_URL}${route.path}`;
      return `    <item>
      <title>${escapeXml(route.titleEn)}</title>
      <link>${escapeXml(url)}</link>
      <guid isPermaLink="true">${escapeXml(url)}</guid>
      <pubDate>${now}</pubDate>
      <category>${escapeXml(route.category)}</category>
      <description>${escapeXml(`${route.descriptionEn} — ${route.description}`)}</description>
    </item>`;
    })
    .join("\n");

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>${escapeXml(SITE_BRAND)}</title>
    <link>${SITE_URL}</link>
    <atom:link href="${SITE_URL}/feed.xml" rel="self" type="application/rss+xml" />
    <description>Global Passive Website Security Auditor, RCE Shell Surface Scanner, AES-256-GCM Sensitive File Vault &amp; International Google Rank #1 SEO Master.</description>
    <language>en-us</language>
    <lastBuildDate>${now}</lastBuildDate>
    <generator>Sentinel-ID SEO Master Engine v3.6</generator>
${items}
  </channel>
</rss>`;

  return new NextResponse(xml, {
    status: 200,
    headers: {
      "Content-Type": "application/rss+xml; charset=utf-8",
      "Cache-Control": "public, s-maxage=3600, stale-while-revalidate=86400",
    },
  });
}
