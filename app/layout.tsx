import type { Metadata, Viewport } from "next";
import { GeistMono } from "geist/font/mono";
import { ThemeProvider } from "@/components/theme-provider";
import { AppShell } from "@/components/app-shell";
import { SeoJsonLd } from "@/components/seo-json-ld";
import {
  SITE_URL,
  SITE_NAME,
  GOOGLE_VERIFICATION_CODE,
  MASTER_GLOBAL_KEYWORDS,
  buildLanguageAlternates,
} from "@/lib/seo-master";
import "./globals.css";

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
  themeColor: "#0a0710",
  colorScheme: "dark",
};

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  applicationName: SITE_NAME,
  category: "Security & SEO Auditing Platform",
  classification: "Cybersecurity, Web Vulnerability Scanner, Technical & International SEO Auditor",
  title: {
    default:
      "Sentinel-ID — #1 Passive Website Security Auditor, Vulnerability Scanner & Global SEO Master",
    template: "%s | Sentinel-ID Global Security & SEO",
  },
  description:
    "Platform audit keamanan web pasif #1 (100% GET-only, zero-exploit) & SEO Master Internasional. Periksa celah keamanan (.env, .git, wp2shell, php2shell, node2shell, go2shell, py2shell), Brankas Bukti AES-256-GCM, HTTP headers, SSL/TLS, DNS, OSINT & optimasi Rank #1 Google Global. | #1 Free Passive Website Security Scanner, RCE Surface Auditor & International SEO Master.",
  keywords: MASTER_GLOBAL_KEYWORDS,
  authors: [{ name: "Kasyaf", url: "https://kasyaf-cv.my.id" }],
  creator: "Kasyaf",
  publisher: SITE_NAME,
  referrer: "origin-when-cross-origin",
  formatDetection: {
    email: false,
    address: false,
    telephone: false,
  },
  manifest: "/manifest.webmanifest",
  icons: {
    icon: [
      { url: "/favicon.ico" },
      { url: "/image/image.png", type: "image/png", sizes: "512x512" },
      { url: "/image/image.png", type: "image/png", sizes: "192x192" },
    ],
    apple: [{ url: "/image/image.png", sizes: "180x180", type: "image/png" }],
    shortcut: "/favicon.ico",
  },
  verification: {
    google: GOOGLE_VERIFICATION_CODE,
  },
  alternates: {
    canonical: SITE_URL,
    languages: buildLanguageAlternates(""),
    types: {
      "application/rss+xml": `${SITE_URL}/feed.xml`,
    },
  },
  openGraph: {
    title:
      "Sentinel-ID — #1 Passive Website Security Auditor, RCE Surface Scanner & Global SEO Master",
    description:
      "Free 100% passive GET-only website vulnerability scanner, AES-256-GCM sensitive file vault (.env/.git), deep shell surface engine (wp2shell/php2shell/node2shell), and International Google Rank #1 SEO Master.",
    url: SITE_URL,
    siteName: SITE_NAME,
    images: [
      {
        url: "/image/image.png",
        width: 1200,
        height: 630,
        alt: "Sentinel-ID — Global Passive Website Security Auditor & SEO Master",
      },
    ],
    locale: "en_US",
    alternateLocale: [
      "id_ID",
      "en_GB",
      "en_SG",
      "en_AU",
      "en_CA",
      "en_IN",
      "ms_MY",
      "ja_JP",
      "de_DE",
    ],
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title:
      "Sentinel-ID — Passive Website Security Auditor & International SEO Master",
    description:
      "100% passive GET-only web vulnerability scanner, AES-256-GCM evidence vault, deep RCE surface check & Google Rank #1 International SEO Master.",
    images: ["/image/image.png"],
    creator: "@Kasyaf",
    site: "@SentinelID",
  },
  robots: {
    index: true,
    follow: true,
    nocache: false,
    googleBot: {
      index: true,
      follow: true,
      noimageindex: false,
      "max-video-preview": -1,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },
  other: {
    "google-site-verification": GOOGLE_VERIFICATION_CODE,
    "content-language": "id, en",
    "geo.region": "ID-JB",
    "geo.placename": "Bandung, West Java, Indonesia",
    "distribution": "Global",
    "rating": "General",
    "target": "all",
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
      <head>
        <SeoJsonLd />
      </head>
      <body className="h-full antialiased bg-background text-foreground">
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