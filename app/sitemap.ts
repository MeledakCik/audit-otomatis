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
  ];

  return routes.map((route) => ({
    url: `${baseUrl}${route}`,
    lastModified,
    changeFrequency: route === "" ? "daily" : "weekly",
    priority: route === "" ? 1.0 : 0.8,
  }));
}