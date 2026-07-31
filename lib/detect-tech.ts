export type PageData = {
  url: string;
  headers?: Record<string, string>;
  html?: string;
  contentType?: string;
};

/**
 * Deteksi tech stack ringan dari hasil crawl (halaman utama + header semua
 * halaman). Ini heuristik pasif — tidak selalu 100% akurat, cuma sinyal cepat
 * untuk request inspector.
 */
export function detectTechStack(pages: PageData[]): string[] {
  const found = new Set<string>();
  const main = pages[0];

  if (main) {
    const html = main.html ?? "";
    const url = main.url ?? "";

    if (html.includes("__NEXT_DATA__") || url.includes("/_next/")) found.add("Next.js");
    if (html.includes("wp-content") || html.includes("wp-json") || html.includes("wp-includes")) {
      found.add("WordPress");
    }
    if (/react/i.test(html)) found.add("React");
    if (/vue/i.test(html)) found.add("Vue");
    if (/svelte/i.test(html)) found.add("Svelte");
    if (/laravel/i.test(html)) found.add("Laravel");
  }

  for (const page of pages) {
    const headers = page.headers ?? {};
    const server = (headers["server"] ?? "").toLowerCase();

    if (server.includes("cloudflare")) found.add("Cloudflare");
    if (server.includes("vercel")) found.add("Vercel");
    if (server.includes("nginx")) found.add("Nginx");

    const poweredBy = headers["x-powered-by"];
    if (poweredBy) found.add(poweredBy);

    if (headers["x-vercel-cache"]) found.add("Vercel");
  }

  return Array.from(found).slice(0, 6);
}
