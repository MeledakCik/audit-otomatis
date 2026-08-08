import type { Metadata, Viewport } from "next";
import { GeistMono } from "geist/font/mono";
import { ThemeProvider } from "@/components/theme-provider";
import { AppShell } from "@/components/app-shell";
import "./globals.css";

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#09090b" },
  ],
};

export const metadata: Metadata = {
  metadataBase: new URL("https://www.sentinel-id.net"),
  title: {
    default: "Sentinel-ID — Passive Website Security Auditor & Scanner",
    template: "%s | Sentinel-ID",
  },
  description:
    "Platform audit keamanan web pasif 100% aman (GET-only) tanpa risiko merusak server. Periksa celah keamanan, header, dan kerentanan domain Anda secara instant.",
  keywords: [
    "security auditor",
    "passive vulnerability scanner",
    "audit keamanan website",
    "cek celah keamanan web",
    "website vulnerability checker",
    "ethical hacking tool",
    "Sentinel-ID",
    "security header checker",
  ],
  authors: [{ name: "Kasyaf", url: "https://www.sentinel-id.net" }],
  creator: "Kasyaf",
  publisher: "Sentinel-ID",
  formatDetection: {
    email: false,
    address: false,
    telephone: false,
  },
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
    google: "SgwdHR7nkAHjCTR-2VgSjZ6YRh5w8jIc0NBQtDjnyxg",
  },
  alternates: {
    canonical: "https://www.sentinel-id.net",
    languages: {
      "id-ID": "https://www.sentinel-id.net",
    },
    types: {
      "application/rss+xml": "https://www.sentinel-id.net/feed.xml",
    },
  },
  openGraph: {
    title: "Sentinel-ID — Passive Website Security Auditor",
    description:
      "Audit dan analisis keamanan website secara pasif, instan, dan aman tanpa payload berbahaya.",
    url: "https://www.sentinel-id.net",
    siteName: "Sentinel-ID",
    images: [
      {
        url: "/image/image.png",
        width: 1200,
        height: 630,
        alt: "Sentinel-ID Security Auditor Preview",
      },
    ],
    locale: "id_ID",
    type: "website",
  },
  twitter: {
    card: "summary_large_image",
    title: "Sentinel-ID — Passive Website Security Auditor",
    description:
      "Audit keamanan website pasif, same-origin & GET-only tanpa risiko merusak server.",
    images: ["/image/image.png"],
    creator: "@Kasyaf",
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-video-preview": -1,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
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