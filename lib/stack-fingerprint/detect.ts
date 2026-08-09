import { STACK_SIGNATURES } from "./signatures";
import type { DetectedStack, Evidence } from "./types";

const TIER_BASE = { header: 90, html: 80, jsHint: 60 } as const;
const TIER_MAX_BONUS = 8;

/**
 * Coba ambil versi dari <meta name="generator" content="...">. Ini satu-satunya
 * sumber versi yang dipakai — kalau tidak ketemu, versi ditandai "tidak
 * terdeteksi". Tidak ada lookup CVE / database kerentanan sama sekali.
 */
function extractGeneratorVersion(html: string, keyword: string): string | null {
  const metaMatch = html.match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["'][^>]*>/i);
  if (!metaMatch) return null;
  const content = metaMatch[1];
  if (!content.toLowerCase().includes(keyword.toLowerCase())) return null;
  const versionMatch = content.match(/(\d+(?:\.\d+){1,2})/);
  return versionMatch ? versionMatch[1] : null;
}

/**
 * Deteksi tech stack 100% pasif dari header + HTML homepage yang sudah
 * di-fetch server-side (GET saja, tanpa payload). Regex matching dijalankan
 * di sisi client, murni untuk mencari marker publik (bukan exploit apa pun).
 */
export function detectStacks(headers: Record<string, string>, html: string): DetectedStack[] {
  const lowerHeaders: Record<string, string> = {};
  for (const [k, v] of Object.entries(headers)) lowerHeaders[k.toLowerCase()] = v.toLowerCase();

  const results: DetectedStack[] = [];

  for (const sig of STACK_SIGNATURES) {
    const evidence: Evidence[] = [];

    for (const rule of sig.headerMatch ?? []) {
      const value = lowerHeaders[rule.header.toLowerCase()];
      if (value === undefined) continue;
      if (rule.valueIncludes && !value.includes(rule.valueIncludes.toLowerCase())) continue;
      evidence.push({ tier: "header", label: `Header "${rule.header}"${rule.valueIncludes ? ` mengandung "${rule.valueIncludes}"` : ""} ditemukan` });
    }

    for (const re of sig.htmlMatch ?? []) {
      const match = html.match(re);
      if (match) evidence.push({ tier: "html", label: `Ditemukan "${match[0]}" di HTML` });
    }

    for (const re of sig.jsHintMatch ?? []) {
      const match = html.match(re);
      if (match) evidence.push({ tier: "jsHint", label: `Petunjuk JS: "${match[0]}"` });
    }

    if (evidence.length === 0) continue;

    const bestTier = evidence.some((e) => e.tier === "header")
      ? "header"
      : evidence.some((e) => e.tier === "html")
        ? "html"
        : "jsHint";
    const extraMatches = evidence.length - 1;
    const confidence = Math.min(98, TIER_BASE[bestTier] + Math.min(extraMatches * 2, TIER_MAX_BONUS));

    const version = sig.generatorKey ? extractGeneratorVersion(html, sig.generatorKey) : null;

    results.push({
      id: sig.id,
      name: sig.name,
      icon: sig.icon,
      category: sig.category,
      confidence,
      evidence,
      version,
    });
  }

  return results.sort((a, b) => b.confidence - a.confidence);
}
