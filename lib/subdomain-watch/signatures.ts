/**
 * Daftar fingerprint layanan pihak-ketiga yang dikenal rentan "subdomain
 * takeover" kalau record CNAME masih mengarah ke resource yang sudah
 * dihapus/unclaimed. Referensi: proyek publik "can-i-take-over-xyz".
 *
 * cnamePatterns : potongan string yang dicari di dalam nilai CNAME (lowercase).
 * bodyFingerprints : potongan string di body HTML yang menandakan resource
 *                     TIDAK diklaim siapa pun (artinya: bisa diklaim penyerang).
 * fix : saran remediasi singkat.
 */
export interface TakeoverSignature {
  service: string;
  cnamePatterns: string[];
  bodyFingerprints: string[];
  fix: string;
}

export const TAKEOVER_SIGNATURES: TakeoverSignature[] = [
  {
    service: "GitHub Pages",
    cnamePatterns: ["github.io"],
    bodyFingerprints: ["there isn't a github pages site here", "for root urls (like http://example.com/) you must provide an index.html"],
    fix: "Klaim repo/organisasi GitHub Pages tersebut, atau hapus record CNAME kalau sudah tidak dipakai.",
  },
  {
    service: "Heroku",
    cnamePatterns: ["herokuapp.com", "herokudns.com", "herokussl.com"],
    bodyFingerprints: ["no such app", "herokucdn.com/error-pages/no-such-app.html"],
    fix: "Buat ulang app Heroku dengan nama yang sama, atau hapus record CNAME.",
  },
  {
    service: "AWS S3",
    cnamePatterns: ["s3.amazonaws.com", "s3-website", "s3.dualstack"],
    bodyFingerprints: ["nosuchbucket", "the specified bucket does not exist"],
    fix: "Buat ulang S3 bucket dengan nama yang sama persis, atau hapus record CNAME.",
  },
  {
    service: "Azure",
    cnamePatterns: ["azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net", "azure-api.net", "azurefd.net"],
    bodyFingerprints: ["404 web site not found", "the resource you are looking for has been removed"],
    fix: "Klaim ulang resource Azure (App Service/Traffic Manager/Storage) tersebut, atau hapus record CNAME.",
  },
  {
    service: "Netlify",
    cnamePatterns: ["netlify.app", "netlify.com"],
    bodyFingerprints: ["not found - request id"],
    fix: "Hubungkan ulang domain ke site Netlify yang benar, atau hapus record CNAME.",
  },
  {
    service: "Vercel",
    cnamePatterns: ["vercel.app", "vercel-dns.com", "now.sh"],
    bodyFingerprints: ["deployment_not_found", "the deployment could not be found"],
    fix: "Tambahkan domain ini kembali ke project Vercel yang sesuai, atau hapus record CNAME.",
  },
  {
    service: "Shopify",
    cnamePatterns: ["myshopify.com"],
    bodyFingerprints: ["sorry, this shop is currently unavailable"],
    fix: "Sambungkan ulang domain di admin Shopify, atau hapus record CNAME.",
  },
  {
    service: "Zendesk",
    cnamePatterns: ["zendesk.com"],
    bodyFingerprints: ["help center closed"],
    fix: "Klaim ulang subdomain Zendesk tersebut, atau hapus record CNAME.",
  },
  {
    service: "Fastly",
    cnamePatterns: ["fastly.net"],
    bodyFingerprints: ["fastly error: unknown domain"],
    fix: "Konfigurasikan ulang service Fastly untuk domain ini, atau hapus record CNAME.",
  },
  {
    service: "Pantheon",
    cnamePatterns: ["pantheonsite.io"],
    bodyFingerprints: ["the gods are wise", "404 error unknown site"],
    fix: "Klaim ulang site Pantheon, atau hapus record CNAME.",
  },
  {
    service: "Tumblr",
    cnamePatterns: ["domains.tumblr.com"],
    bodyFingerprints: ["whatever you were looking for doesn't currently exist"],
    fix: "Sambungkan ulang custom domain di pengaturan Tumblr, atau hapus record CNAME.",
  },
  {
    service: "Bitbucket",
    cnamePatterns: ["bitbucket.io"],
    bodyFingerprints: ["repository not found"],
    fix: "Klaim ulang repo Bitbucket Pages tersebut, atau hapus record CNAME.",
  },
  {
    service: "Surge.sh",
    cnamePatterns: ["surge.sh"],
    bodyFingerprints: ["project not found"],
    fix: "Deploy ulang project Surge dengan domain yang sama, atau hapus record CNAME.",
  },
  {
    service: "UserVoice",
    cnamePatterns: ["uservoice.com"],
    bodyFingerprints: ["this uservoice subdomain is currently available"],
    fix: "Klaim ulang subdomain UserVoice tersebut, atau hapus record CNAME.",
  },
  {
    service: "Unbounce",
    cnamePatterns: ["unbouncepages.com"],
    bodyFingerprints: ["the requested url was not found on this server"],
    fix: "Sambungkan ulang landing page di Unbounce, atau hapus record CNAME.",
  },
  {
    service: "HelpScout Docs",
    cnamePatterns: ["helpscoutdocs.com"],
    bodyFingerprints: ["no settings were found for this company"],
    fix: "Klaim ulang docs site HelpScout, atau hapus record CNAME.",
  },
  {
    service: "Ghost (Ghost.io)",
    cnamePatterns: ["ghost.io"],
    bodyFingerprints: ["the thing you were looking for is no longer here"],
    fix: "Klaim ulang site Ghost tersebut, atau hapus record CNAME.",
  },
  {
    service: "Webflow",
    cnamePatterns: ["proxy-ssl.webflow.com", "webflow.io"],
    bodyFingerprints: ["the page you are looking for doesn't exist"],
    fix: "Sambungkan ulang custom domain di pengaturan Webflow, atau hapus record CNAME.",
  },
  {
    service: "Squarespace",
    cnamePatterns: ["squarespace.com", "sqspcdn.com"],
    bodyFingerprints: ["no such account"],
    fix: "Sambungkan ulang domain di pengaturan Squarespace, atau hapus record CNAME.",
  },
  {
    service: "Readme.io",
    cnamePatterns: ["readme.io"],
    bodyFingerprints: ["project doesnt exist... yet!"],
    fix: "Klaim ulang project ReadMe tersebut, atau hapus record CNAME.",
  },
  {
    service: "Cargo Collective",
    cnamePatterns: ["cargocollective.com"],
    bodyFingerprints: ["404 not found"],
    fix: "Klaim ulang site Cargo Collective, atau hapus record CNAME.",
  },
];

export function matchSignatureByCname(cname: string): TakeoverSignature | null {
  const lower = cname.toLowerCase().replace(/\.$/, "");
  return TAKEOVER_SIGNATURES.find((sig) => sig.cnamePatterns.some((p) => lower.includes(p))) ?? null;
}

export function bodyMatchesFingerprint(body: string, sig: TakeoverSignature): boolean {
  const lower = body.toLowerCase();
  return sig.bodyFingerprints.some((f) => lower.includes(f));
}
