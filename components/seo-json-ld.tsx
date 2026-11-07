// components/seo-json-ld.tsx
import { buildMasterJsonLdGraph } from "@/lib/seo-master";

export function SeoJsonLd() {
  const jsonLd = buildMasterJsonLdGraph();

  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{
        __html: JSON.stringify(jsonLd).replace(/</g, "\\u003c"),
      }}
    />
  );
}
