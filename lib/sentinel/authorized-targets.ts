import { normalizeDomainCheckTarget } from "./domain-check";

/** Parse a domain or URL supplied by an authenticated admin and pin it to HTTPS. */
export function getAdminAuditTarget(input: unknown) {
  const domain = normalizeDomainCheckTarget(input);
  return domain ? { domain, origin: `https://${domain}` } : null;
}

/** Admin-only scan origins must use the same canonical form created above. */
export function isAdminAuditOrigin(origin: string) {
  try {
    const url = new URL(origin);
    return url.protocol === "https:"
      && url.origin === origin
      && url.pathname === "/"
      && !url.search
      && !url.hash
      && normalizeDomainCheckTarget(origin) === url.hostname;
  } catch {
    return false;
  }
}
