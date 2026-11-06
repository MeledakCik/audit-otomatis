import { buildPageMetadata } from "@/lib/seo-master";

export const metadata = buildPageMetadata("/docs");

export default function DocsLayout({ children }: { children: React.ReactNode }) {
  return <>{children}</>;
}
