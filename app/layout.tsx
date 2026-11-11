import type { ReactNode } from "react";
import { GeistMono } from "geist/font/mono";
import { ThemeProvider } from "@/components/theme-provider";
import { AppShell } from "@/components/app-shell";
import { SeoJsonLd } from "@/components/seo-json-ld";
import "./globals.css";

export const metadata = {
  title: "Sentinel-ID — Auto Security Auditor",
  description:
    "Automated web security auditor untuk proyek GDG Bandung. Scan, temukan, dan perbaiki celah keamanan dengan cepat.",
};

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="id" className={GeistMono.variable} suppressHydrationWarning>
      <head>
        <SeoJsonLd />
      </head>
      <body className="min-h-screen antialiased bg-[var(--background)] text-[var(--foreground)] selection:bg-pink-500/20">
        <ThemeProvider attribute="class" defaultTheme="dark" enableSystem>
          <AppShell>{children}</AppShell>
        </ThemeProvider>
      </body>
    </html>
  );
}