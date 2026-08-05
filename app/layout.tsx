import type { Metadata } from "next";
import { GeistMono } from "geist/font/mono";
import { ThemeProvider } from "@/components/theme-provider";
import { AppShell } from "@/components/app-shell";
import "./globals.css";

export const metadata: Metadata = {
  metadataBase: new URL("https://www.sentinel-id.net"),
  title: {
    default: "Sentinel-ID.net — Passive-Only Security Auditor",
    template: "%s | Sentinel-ID.net",
  },
  description:
    "100% passive, GET-only security auditor for your own domain. Same-origin, non-destructive, no exploit, no payload. Built for website owners.",
  keywords: [
    "security auditor",
    "passive scanner",
    "Next.js",
    "ethical hacking",
    "Sentinel-ID",
    "vulnerability scanner",
  ],
  authors: [{ name: "Kasyaf", url: "https://www.sentinel-id.net" }],
  creator: "Kasyaf",
  verification: {
    google: "SgwdHR7nkAHjCTR-2VgSjZ6YRh5w8jIc0NBQtDjnyxg",
  },
  alternates: {
    canonical: "https://www.sentinel-id.net",
  },
  openGraph: {
    title: "Sentinel-ID.net — Passive-Only Security Auditor",
    description:
      "Audit keamanan pasif untuk domain sendiri. 100% aman, tanpa payload berbahaya.",
    url: "https://www.sentinel-id.net",
    siteName: "Sentinel-ID.net",
    type: "website",
    locale: "id_ID",
  },
  twitter: {
    card: "summary_large_image",
    title: "Sentinel-ID.net — Passive-Only Security Auditor",
    description: "Passive-only security auditor, same-origin & GET-only.",
  },
  robots: {
    index: true,
    follow: true,
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html
      lang="id"
      className={`${GeistMono.variable} h-full`}
      suppressHydrationWarning
    >
      <body className="h-full antialiased bg-background text-foreground select-none">
        <ThemeProvider
          attribute="class"
          defaultTheme="dark"
          enableSystem={false}
        >
          <AppShell>{children}</AppShell>
        </ThemeProvider>
      </body>
    </html>
  );
}
