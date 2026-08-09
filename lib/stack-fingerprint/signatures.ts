import type { StackCategory } from "./types";

/**
 * Signature Wappalyzer-style — deteksi pasif dari header + HTML homepage saja
 * (tidak ada request tambahan, tidak ada bruteforce). Tujuan: asset inventory
 * edukatif, bukan tool exploitation.
 *
 * headerMatch  : nama header yang harus ada (opsional cek substring value).
 * htmlMatch    : substring/regex struktural di HTML mentah (mis. "wp-content").
 * jsHintMatch  : substring yang biasanya muncul di dalam <script> inline / nama
 *                file JS yang ter-referensi (sinyal lebih lemah).
 * generatorKey : kata kunci untuk mengambil versi dari <meta name="generator">.
 */
export interface HeaderMatchRule {
  header: string;
  valueIncludes?: string;
}

export interface StackSignature {
  id: string;
  name: string;
  icon: string;
  category: StackCategory;
  headerMatch?: HeaderMatchRule[];
  htmlMatch?: RegExp[];
  jsHintMatch?: RegExp[];
  generatorKey?: string;
}

export const STACK_SIGNATURES: StackSignature[] = [
  {
    id: "nextjs",
    name: "Next.js",
    icon: "▲",
    category: "Frontend",
    headerMatch: [{ header: "x-nextjs-cache" }],
    htmlMatch: [/_next\/static/i, /__NEXT_DATA__/],
  },
  {
    id: "react",
    name: "React",
    icon: "⚛",
    category: "Frontend",
    htmlMatch: [/data-reactroot/i, /__REACT/],
    jsHintMatch: [/react(-dom)?[.-]/i],
  },
  {
    id: "vuejs",
    name: "Vue.js",
    icon: "V",
    category: "Frontend",
    htmlMatch: [/data-v-[a-f0-9]{6,8}/i, /__vue__/i],
    jsHintMatch: [/vue(\.runtime)?[.-]min\.js/i],
  },
  {
    id: "jquery",
    name: "jQuery",
    icon: "jQ",
    category: "Frontend",
    jsHintMatch: [/jquery[.-]?(\d+\.\d+\.\d+)?(\.min)?\.js/i],
  },
  {
    id: "wordpress",
    name: "WordPress",
    icon: "W",
    category: "CMS",
    htmlMatch: [/wp-content/i, /wp-json/i, /wp-includes/i],
    generatorKey: "wordpress",
  },
  {
    id: "shopify",
    name: "Shopify",
    icon: "S",
    category: "CMS",
    htmlMatch: [/cdn\.shopify\.com/i, /myshopify\.com/i],
  },
  {
    id: "laravel",
    name: "Laravel",
    icon: "L",
    category: "Backend",
    headerMatch: [{ header: "x-powered-by", valueIncludes: "laravel" }],
    htmlMatch: [/laravel/i, /csrf-token/i],
  },
  {
    id: "nginx",
    name: "Nginx",
    icon: "N",
    category: "Backend",
    headerMatch: [{ header: "server", valueIncludes: "nginx" }],
  },
  {
    id: "supabase",
    name: "Supabase",
    icon: "⚡",
    category: "BaaS",
    htmlMatch: [/supabase\.co/i],
    jsHintMatch: [/supabase-js/i],
  },
  {
    id: "firebase",
    name: "Firebase",
    icon: "🔥",
    category: "BaaS",
    htmlMatch: [/firebaseapp\.com/i, /firebaseio\.com/i],
    jsHintMatch: [/firebase(storage|auth)?[.-]/i, /firestore/i],
  },
  {
    id: "cloudflare",
    name: "Cloudflare",
    icon: "☁",
    category: "CDN",
    headerMatch: [{ header: "cf-ray" }, { header: "cf-cache-status" }, { header: "server", valueIncludes: "cloudflare" }],
  },
  {
    id: "vercel",
    name: "Vercel",
    icon: "▲",
    category: "Hosting",
    headerMatch: [{ header: "x-vercel-id" }, { header: "x-vercel-cache" }],
  },
  {
    id: "netlify",
    name: "Netlify",
    icon: "◆",
    category: "Hosting",
    headerMatch: [{ header: "x-nf-request-id" }, { header: "server", valueIncludes: "netlify" }],
  },
  {
    id: "google-analytics",
    name: "Google Analytics",
    icon: "GA",
    category: "Analytics",
    htmlMatch: [/gtag\(/i, /google-analytics\.com/i, /googletagmanager\.com\/gtag/i],
  },
  {
    id: "gtm",
    name: "Google Tag Manager",
    icon: "GTM",
    category: "Analytics",
    htmlMatch: [/googletagmanager\.com\/gtm\.js/i, /GTM-[A-Z0-9]+/],
  },
  {
    id: "stripe",
    name: "Stripe",
    icon: "$",
    category: "Payments",
    htmlMatch: [/js\.stripe\.com/i],
    jsHintMatch: [/api\.stripe\.com/i],
  },
  {
    id: "auth0",
    name: "Auth0",
    icon: "0",
    category: "Auth",
    htmlMatch: [/auth0\.com/i, /cdn\.auth0\.com/i],
  },
];

export function findSignature(id: string): StackSignature | undefined {
  return STACK_SIGNATURES.find((s) => s.id === id);
}
