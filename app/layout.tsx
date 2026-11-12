import { GeistMono } from "geist/font/mono";
import { ThemeProvider } from "@/components/theme-provider";
import { AppShell } from "@/components/app-shell";
import { SeoJsonLd } from "@/components/seo-json-ld";
import "./globals.css";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="id" className={GeistMono.variable} suppressHydrationWarning>
      <head>
        <SeoJsonLd />
      </head>
      <body className="min-h-screen antialiased bg-[var(--background)] text-[var(--foreground)] selection:bg-pink-500/20">
        <ThemeProvider attribute="class" defaultTheme="dark" enableSystem={true}>
          <AppShell>{children}</AppShell>
        </ThemeProvider>
      </body>
    </html>
  );
}
