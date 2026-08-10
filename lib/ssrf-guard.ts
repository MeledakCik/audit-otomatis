/**
 * SSRF guard.
 *
 * This scanner accepts a user-supplied URL and fetches it server-side.
 * That's the single most common way a "harmless" URL-checker tool turns
 * into an internal network / cloud-metadata prober. Every fetch target
 * (homepage, security.txt, sensitive-path check) MUST be passed through
 * `assertPublicHttpsTarget` first.
 *
 * Rules enforced:
 *  - scheme must be https
 *  - hostname must not be a raw IP literal (forces a "real" domain)
 *  - resolved DNS address must not fall in a private / loopback /
 *    link-local / reserved / cloud-metadata range
 *  - no credentials in the URL (user:pass@host)
 */

import dns from "node:dns/promises";
import net from "node:net";

export class SsrfBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrfBlockedError";
  }
}

// Cloud metadata endpoints — these must always be blocked regardless of
// the private-range check, since 169.254.169.254 is the classic SSRF
// target for stealing cloud credentials.
const BLOCKED_EXACT_IPS = new Set([
  "169.254.169.254", // AWS / Azure / GCP metadata
  "100.100.100.200", // Alibaba Cloud metadata
]);

function isPrivateIPv4(ip: string): boolean {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return false;
  const [a, b] = parts;
  if (a === 10) return true; // 10.0.0.0/8
  if (a === 127) return true; // loopback
  if (a === 169 && b === 254) return true; // link-local + metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12
  if (a === 192 && b === 168) return true; // 192.168.0.0/16
  if (a === 0) return true; // "this network"
  if (a >= 224) return true; // multicast / reserved
  return false;
}

function isPrivateIPv6(ip: string): boolean {
  const norm = ip.toLowerCase();
  if (norm === "::1") return true; // loopback
  if (norm.startsWith("fe80:")) return true; // link-local
  if (norm.startsWith("fc") || norm.startsWith("fd")) return true; // unique local
  if (norm.startsWith("::ffff:")) {
    // IPv4-mapped IPv6 — recheck the embedded v4 address
    const v4 = norm.split(":").pop() ?? "";
    if (net.isIPv4(v4)) return isPrivateIPv4(v4);
  }
  return false;
}

export function isBlockedIp(ip: string): boolean {
  if (BLOCKED_EXACT_IPS.has(ip)) return true;
  if (net.isIPv4(ip)) return isPrivateIPv4(ip);
  if (net.isIPv6(ip)) return isPrivateIPv6(ip);
  return true; // unknown shape -> fail closed
}

export interface CheckedTarget {
  url: URL;
  resolvedIp: string;
}

/**
 * Validates that `rawUrl` is safe to fetch server-side. Throws
 * SsrfBlockedError (or a generic Error for malformed input) if not.
 */
export async function assertPublicHttpsTarget(rawUrl: string): Promise<CheckedTarget> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("That doesn't look like a valid URL.");
  }

  if (url.protocol !== "https:") {
    throw new Error("Only https:// URLs are supported.");
  }
  if (url.username || url.password) {
    throw new SsrfBlockedError("URLs with embedded credentials aren't allowed.");
  }
  if (url.port && !["443", ""].includes(url.port)) {
    // Non-standard ports are a common way to reach internal services
    // (admin panels, databases) that happen to sit behind a public
    // hostname. Keep this scanner to standard web ports.
    throw new SsrfBlockedError("Only the default https port (443) is supported.");
  }

  const hostname = url.hostname;

  // Reject raw IP literals outright — this is a domain scanner, not a
  // generic internal-network prober.
  if (net.isIPv4(hostname) || net.isIPv6(hostname)) {
    throw new SsrfBlockedError("Scanning raw IP addresses isn't supported — use a domain name.");
  }
  if (hostname === "localhost" || hostname.endsWith(".local")) {
    throw new SsrfBlockedError("Local hostnames aren't allowed.");
  }

  let addresses: string[];
  try {
    const records = await dns.lookup(hostname, { all: true, verbatim: false });
    addresses = records.map((r) => r.address);
  } catch {
    throw new Error(`Couldn't resolve ${hostname}.`);
  }
  if (addresses.length === 0) {
    throw new Error(`Couldn't resolve ${hostname}.`);
  }

  const blocked = addresses.find(isBlockedIp);
  if (blocked) {
    throw new SsrfBlockedError(
      `${hostname} resolves to a private or internal address — refusing to scan it.`
    );
  }

  return { url, resolvedIp: addresses[0] };
}

/** True if `candidate` is same-origin (scheme+host+port) as `origin`. */
export function isSameOrigin(candidate: URL, origin: URL): boolean {
  return candidate.protocol === origin.protocol && candidate.host === origin.host;
}
