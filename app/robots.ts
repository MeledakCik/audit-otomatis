import type { MetadataRoute } from "next";

export default function robots(): MetadataRoute.Robots {
  const baseUrl = "https://www.sentinel-id.net";

  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
        disallow: [
          "/api/",      // Blokir endpoint API internal dari crawling
          "/scan/",    // Blokir panel admin jika ada
          "/requests/", // Blokir halaman permintaan jika ada
          "/_next/",   // Blokir file internal Next.js
        ],
      },
    ],
    sitemap: `${baseUrl}/sitemap.xml`,
  };
}