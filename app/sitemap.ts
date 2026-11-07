// app/sitemap.ts
import type { MetadataRoute } from "next";
import {
  SITE_URL,
  SEO_ROUTES_REGISTRY,
  buildLanguageAlternates,
} from "@/lib/seo-master";

export default function sitemap(): MetadataRoute.Sitemap {
  const lastModified = new Date();

  return Object.values(SEO_ROUTES_REGISTRY).map((route) => {
    const fullUrl = `${SITE_URL}${route.path}`;
    return {
      url: fullUrl,
      lastModified,
      changeFrequency: route.changeFrequency,
      priority: route.priority,
      alternates: {
        languages: buildLanguageAlternates(route.path),
      },
    };
  });
}