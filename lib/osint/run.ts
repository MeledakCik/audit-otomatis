import dns from "node:dns/promises";
import net from "node:net";
import crypto from "node:crypto";
import type {
  DomainOsint,
  EmailOsint,
  NameOsint,
  OsintLink,
  PlatformResult,
  UsernameOsint,
} from "./types";

/**
 * OSINT module — PUBLIC data only.
 * - Tidak ada login, scraping di balik auth, atau bypass proteksi.
 * - Host eksternal hanya yang di-hardcode (rdap.org, crt.sh, gravatar.com,
 *   dan template profil publik) sehingga tidak ada SSRF dari input user.
 */

const UA = "Sentinel-ID-OSINT/1.0 (public-data only)";
const TIMEOUT = 8000;

async function safeFetch(url: string, init?: RequestInit): Promise<Response | null> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), TIMEOUT);
  try {
    return await fetch(url, {
      ...init,
      signal: ctrl.signal,
      cache: "no-store",
      redirect: "follow",
      headers: { "User-Agent": UA, Accept: "*/*", ...(init?.headers ?? {}) },
    });
  } catch {
    return null;
  } finally {
    clearTimeout(t);
  }
}

// ---------- validators ----------

const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;

export function normalizeDomain(raw: string): string | null {
  let v = raw.trim().toLowerCase();
  v = v.replace(/^https?:\/\//, "").split(/[/?#]/)[0].replace(/:\d+$/, "");
  if (v.startsWith("www.")) v = v.slice(4);
  if (net.isIP(v) || v === "localhost" || !DOMAIN_RE.test(v)) return null;
  return v;
}

export function normalizeUsername(raw: string): string | null {
  const v = raw.trim().replace(/^@/, "");
  return /^[A-Za-z0-9._-]{2,40}$/.test(v) ? v : null;
}

export function normalizeEmail(raw: string): string | null {
  const v = raw.trim().toLowerCase();
  return /^[^\s@]{1,64}@[^\s@]+\.[^\s@]+$/.test(v) && v.length <= 254 ? v : null;
}

export function normalizeName(raw: string): string | null {
  const v = raw.trim().replace(/\s+/g, " ");
  return v.length >= 3 && v.length <= 80 && /^[\p{L}\p{M}\s.'-]+$/u.test(v) ? v : null;
}

// ---------- DOMAIN ----------

async function resolveAll<T>(p: Promise<T>, fallback: T): Promise<T> {
  try {
    return await p;
  } catch {
    return fallback;
  }
}

async function getMx(domain: string): Promise<string[]> {
  const mx = await resolveAll(dns.resolveMx(domain), []);
  return mx.sort((a, b) => a.priority - b.priority).map((m) => `${m.priority} ${m.exchange}`);
}

export async function osintDomain(domain: string): Promise<DomainOsint> {
  const [a, aaaa, mx, ns, txt, rdapRes, crtRes] = await Promise.all([
    resolveAll(dns.resolve4(domain), [] as string[]),
    resolveAll(dns.resolve6(domain), [] as string[]),
    getMx(domain),
    resolveAll(dns.resolveNs(domain), [] as string[]),
    resolveAll(dns.resolveTxt(domain), [] as string[][]),
    safeFetch(`https://rdap.org/domain/${encodeURIComponent(domain)}`, {
      headers: { Accept: "application/rdap+json" },
    }),
    safeFetch(`https://crt.sh/?q=${encodeURIComponent("%." + domain)}&output=json`),
  ]);

  let rdap: DomainOsint["rdap"] = null;
  if (rdapRes?.ok) {
    try {
      const j = (await rdapRes.json()) as {
        status?: string[];
        events?: { eventAction: string; eventDate: string }[];
        entities?: { roles?: string[]; vcardArray?: [string, [string, unknown, unknown, string][]] }[];
      };
      const ev = (name: string) => j.events?.find((e) => e.eventAction === name)?.eventDate;
      const registrarEnt = j.entities?.find((e) => e.roles?.includes("registrar"));
      const fn = registrarEnt?.vcardArray?.[1]?.find((x) => x[0] === "fn")?.[3];
      rdap = {
        registrar: fn,
        created: ev("registration"),
        updated: ev("last changed"),
        expires: ev("expiration"),
        status: j.status,
      };
    } catch {
      rdap = null;
    }
  }

  const subs = new Set<string>();
  if (crtRes?.ok) {
    try {
      const rows = (await crtRes.json()) as { name_value?: string }[];
      for (const r of rows.slice(0, 5000)) {
        for (const n of (r.name_value ?? "").split("\n")) {
          const h = n.trim().toLowerCase().replace(/^\*\./, "");
          if (h.endsWith("." + domain) && DOMAIN_RE.test(h)) subs.add(h);
        }
      }
    } catch {
      /* ignore */
    }
  }

  const links: OsintLink[] = [
    { group: "Arsip & histori", label: "Wayback Machine", url: `https://web.archive.org/web/*/${domain}` },
    { group: "Arsip & histori", label: "crt.sh (sertifikat)", url: `https://crt.sh/?q=${encodeURIComponent(domain)}` },
    { group: "Reputasi", label: "VirusTotal", url: `https://www.virustotal.com/gui/domain/${domain}` },
    { group: "Reputasi", label: "URLScan", url: `https://urlscan.io/search/#${encodeURIComponent(domain)}` },
    { group: "Infrastruktur", label: "SecurityTrails", url: `https://securitytrails.com/domain/${domain}/dns` },
    { group: "Infrastruktur", label: "Shodan", url: `https://www.shodan.io/search?query=hostname%3A${domain}` },
    { group: "Dork publik", label: "Google: site:", url: `https://www.google.com/search?q=${encodeURIComponent("site:" + domain)}` },
    { group: "Dork publik", label: "Google: mention", url: `https://www.google.com/search?q=${encodeURIComponent('"' + domain + '" -site:' + domain)}` },
  ];

  return {
    type: "domain",
    domain,
    dns: { a, aaaa, mx, ns, txt: txt.map((t) => t.join("")) },
    rdap,
    subdomains: Array.from(subs).sort().slice(0, 300),
    links,
  };
}

// ---------- EMAIL ----------

const DISPOSABLE = new Set([
  "mailinator.com", "10minutemail.com", "guerrillamail.com", "tempmail.com", "temp-mail.org",
  "yopmail.com", "trashmail.com", "sharklasers.com", "getnada.com", "throwawaymail.com",
  "maildrop.cc", "dispostable.com", "fakeinbox.com", "mailnesia.com", "mohmal.com",
]);

export async function osintEmail(email: string): Promise<EmailOsint> {
  const domain = email.split("@")[1];
  const hash = crypto.createHash("md5").update(email).digest("hex");
  const gravatarUrl = `https://www.gravatar.com/avatar/${hash}`;

  const [mx, gr] = await Promise.all([
    getMx(domain),
    safeFetch(`${gravatarUrl}?d=404&s=200`, { method: "HEAD" }),
  ]);

  const q = encodeURIComponent(`"${email}"`);
  const links: OsintLink[] = [
    { group: "Pencarian publik", label: "Google", url: `https://www.google.com/search?q=${q}` },
    { group: "Pencarian publik", label: "Bing", url: `https://www.bing.com/search?q=${q}` },
    { group: "Pencarian publik", label: "DuckDuckGo", url: `https://duckduckgo.com/?q=${q}` },
    { group: "Pencarian publik", label: "GitHub code search", url: `https://github.com/search?q=${q}&type=code` },
    { group: "Kebocoran data", label: "Breach Peek (menu ini)", url: `/scan/breach` },
    { group: "Kebocoran data", label: "XposedOrNot", url: `https://xposedornot.com/` },
    { group: "Kebocoran data", label: "Have I Been Pwned", url: `https://haveibeenpwned.com/account/${encodeURIComponent(email)}` },
  ];

  return {
    type: "email",
    email,
    validSyntax: true,
    domain,
    mx,
    disposable: DISPOSABLE.has(domain),
    gravatar: { exists: gr?.status === 200, url: gravatarUrl },
    links,
  };
}

// ---------- USERNAME ----------

interface Platform {
  name: string;
  url: (u: string) => string;
  /** "check" = status code bisa diandalkan; "manual" = butuh login/JS, hanya beri link */
  mode: "check" | "manual";
  note?: string;
}

const PLATFORMS: Platform[] = [
  { name: "Instagram", url: (u) => `https://www.instagram.com/${u}/`, mode: "manual", note: "Butuh login/JS — cek manual" },
  { name: "TikTok", url: (u) => `https://www.tiktok.com/@${u}`, mode: "manual", note: "Anti-bot — cek manual" },
  { name: "Facebook", url: (u) => `https://www.facebook.com/${u}`, mode: "manual", note: "Butuh login — cek manual" },
  { name: "X / Twitter", url: (u) => `https://x.com/${u}`, mode: "manual", note: "Butuh login/JS — cek manual" },
  { name: "Threads", url: (u) => `https://www.threads.net/@${u}`, mode: "manual", note: "Cek manual" },
  { name: "LinkedIn", url: (u) => `https://www.linkedin.com/in/${u}`, mode: "manual", note: "Anti-bot — cek manual" },
  { name: "YouTube", url: (u) => `https://www.youtube.com/@${u}`, mode: "check" },
  { name: "GitHub", url: (u) => `https://github.com/${u}`, mode: "check" },
  { name: "GitLab", url: (u) => `https://gitlab.com/${u}`, mode: "check" },
  { name: "Reddit", url: (u) => `https://www.reddit.com/user/${u}/about.json`, mode: "check" },
  { name: "Medium", url: (u) => `https://medium.com/@${u}`, mode: "check" },
  { name: "DEV.to", url: (u) => `https://dev.to/${u}`, mode: "check" },
  { name: "Telegram", url: (u) => `https://t.me/${u}`, mode: "manual", note: "Cek manual" },
  { name: "Pinterest", url: (u) => `https://www.pinterest.com/${u}/`, mode: "check" },
  { name: "SoundCloud", url: (u) => `https://soundcloud.com/${u}`, mode: "check" },
  { name: "Keybase", url: (u) => `https://keybase.io/${u}`, mode: "check" },
];

async function checkPlatform(p: Platform, username: string): Promise<PlatformResult> {
  const profileUrl = p.url(username).replace("/about.json", "");
  if (p.mode === "manual") {
    return { platform: p.name, url: profileUrl, status: "manual", note: p.note };
  }
  const res = await safeFetch(p.url(username), { method: "GET" });
  if (!res) return { platform: p.name, url: profileUrl, status: "unknown", note: "Timeout / diblokir" };
  if (res.status === 200) return { platform: p.name, url: profileUrl, status: "found" };
  if (res.status === 404) return { platform: p.name, url: profileUrl, status: "not_found" };
  return { platform: p.name, url: profileUrl, status: "unknown", note: `HTTP ${res.status}` };
}

export async function osintUsername(username: string): Promise<UsernameOsint> {
  const platforms = await Promise.all(PLATFORMS.map((p) => checkPlatform(p, username)));
  return { type: "username", username, platforms };
}

// ---------- NAME ----------

export function osintName(name: string): NameOsint {
  const parts = name.toLowerCase().split(" ").filter(Boolean);
  const first = parts[0];
  const last = parts[parts.length - 1];
  const guesses = new Set<string>();
  guesses.add(parts.join(""));
  guesses.add(parts.join("."));
  guesses.add(parts.join("_"));
  if (parts.length > 1) {
    guesses.add(first + last[0]);
    guesses.add(first[0] + last);
    guesses.add(last + first);
  }
  const q = encodeURIComponent(`"${name}"`);
  const links: OsintLink[] = [
    { group: "Mesin pencari", label: "Google", url: `https://www.google.com/search?q=${q}` },
    { group: "Mesin pencari", label: "Bing", url: `https://www.bing.com/search?q=${q}` },
    { group: "Mesin pencari", label: "DuckDuckGo", url: `https://duckduckgo.com/?q=${q}` },
    { group: "Mesin pencari", label: "Google Images", url: `https://www.google.com/search?tbm=isch&q=${q}` },
    { group: "Sosial media", label: "Instagram (via Google)", url: `https://www.google.com/search?q=${encodeURIComponent('site:instagram.com "' + name + '"')}` },
    { group: "Sosial media", label: "TikTok (via Google)", url: `https://www.google.com/search?q=${encodeURIComponent('site:tiktok.com "' + name + '"')}` },
    { group: "Sosial media", label: "Facebook (via Google)", url: `https://www.google.com/search?q=${encodeURIComponent('site:facebook.com "' + name + '"')}` },
    { group: "Sosial media", label: "LinkedIn (via Google)", url: `https://www.google.com/search?q=${encodeURIComponent('site:linkedin.com/in "' + name + '"')}` },
    { group: "Sosial media", label: "X (via Google)", url: `https://www.google.com/search?q=${encodeURIComponent('site:x.com "' + name + '"')}` },
    { group: "Dokumen publik", label: "Dokumen PDF", url: `https://www.google.com/search?q=${encodeURIComponent('"' + name + '" filetype:pdf')}` },
    { group: "Akademik & kode", label: "Google Scholar", url: `https://scholar.google.com/scholar?q=${q}` },
    { group: "Akademik & kode", label: "GitHub users", url: `https://github.com/search?q=${encodeURIComponent(name)}&type=users` },
  ];
  return { type: "name", name, usernameGuesses: Array.from(guesses).slice(0, 8), links };
}
