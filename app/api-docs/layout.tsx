import { buildPageMetadata } from "@/lib/seo-master";

export const metadata = buildPageMetadata("/api-docs");

export default function ApiDocsLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
