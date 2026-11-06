import type { MetadataRoute } from "next";

export default function manifest(): MetadataRoute.Manifest {
  return {
    name: "Sentinel-ID — Global Passive Website Security Auditor & SEO Master",
    short_name: "Sentinel-ID",
    description:
      "#1 Passive Website Security Auditor (GET-only, zero-exploit), AES-256-GCM Sensitive File Vault, Deep RCE Shell Surface Engine & International Google Rank #1 SEO Master.",
    start_url: "/",
    display: "standalone",
    background_color: "#090610",
    theme_color: "#a855f7",
    orientation: "any",
    lang: "id-ID",
    dir: "ltr",
    categories: ["security", "developer tools", "seo", "utilities", "productivity"],
    icons: [
      {
        src: "/favicon.ico",
        sizes: "any",
        type: "image/x-icon",
      },
      {
        src: "/image/image.png",
        sizes: "192x192",
        type: "image/png",
        purpose: "maskable",
      },
      {
        src: "/image/image.png",
        sizes: "512x512",
        type: "image/png",
        purpose: "any",
      },
    ],
  };
}
