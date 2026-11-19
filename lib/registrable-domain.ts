/**
 * Domain induk (eTLD+1) untuk pemeriksaan email anti-spoofing.
 * SPF & DMARC berlaku di domain induk (kasyaf.id), bukan subdomain web
 * (www.kasyaf.id). Tanpa dependensi: daftar sufiks 2-level yang umum,
 * termasuk seluruh sufiks resmi PANDI (.co.id, .my.id, .web.id, ...).
 */
const MULTI_LEVEL_SUFFIXES = new Set([
  // Indonesia (PANDI)
  "co.id", "my.id", "web.id", "ac.id", "sch.id", "or.id", "go.id", "mil.id", "net.id",
  "biz.id", "desa.id", "ponpes.id", "art.id", "ponpes.id",
  // Umum internasional
  "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp",
  "com.sg", "edu.sg", "gov.sg", "org.sg",
  "com.my", "edu.my", "gov.my", "org.my",
  "co.nz", "org.nz", "com.br", "com.cn", "com.hk", "com.tw", "co.kr", "co.in",
  "co.za", "com.mx", "com.ar", "com.tr", "com.ph", "com.vn", "co.th", "in.th",
  // Platform hosting: setiap subdomain adalah "situs" tersendiri
  "vercel.app", "netlify.app", "pages.dev", "workers.dev", "github.io",
  "herokuapp.com", "up.railway.app", "firebaseapp.com", "web.app", "onrender.com",
]);

export function registrableDomain(hostname: string): string {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) return host; // IP
  const labels = host.split(".");
  if (labels.length <= 2) return host;
  // Cek sufiks 3-level (mis. up.railway.app) lalu 2-level
  const last3 = labels.slice(-3).join(".");
  if (MULTI_LEVEL_SUFFIXES.has(last3)) return labels.slice(-4).join(".");
  const last2 = labels.slice(-2).join(".");
  if (MULTI_LEVEL_SUFFIXES.has(last2)) return labels.slice(-3).join(".");
  return last2;
}
