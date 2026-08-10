// app/sitemap.ts
import type { MetadataRoute } from "next";

export default function sitemap(): MetadataRoute.Sitemap {
  const baseUrl = "https://www.sentinel-id.net";
  const lastModified = new Date();
  
  const routes = [
    "",
    "/qc",
    "/history",
    "/requests",
    "/maintenance-log",
    "/docs",
    "/api-docs",
    "/scan/headers",
    "/scan/secrets",
    "/scan/map",
    "/scan/breach",
    "/scan/subdomain",
    "/scan/stack",
    "/scan/shield-status",
    "/scan/dns",
    "/scan/exposure",
    "/scan/js",
    "/scan/ssl",
  ];

  return routes.map((route) => ({
    url: `${baseUrl}${route}`,
    lastModified,
    changeFrequency: route === "" ? "daily" : "weekly",
    priority: route === "" ? 1.0 : 0.8,
  }));
}