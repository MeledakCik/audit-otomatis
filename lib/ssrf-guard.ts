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
import { addAbortListener } from "node:events";
import { BlockList, isIPv4, isIPv6 } from "node:net";

export class SsrfBlockedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SsrfBlockedError";
  }
}

const specialUse = new BlockList();
for (const [address, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10],
  ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24],
  ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24],
  ["203.0.113.0", 24], ["224.0.0.0", 3],
] as const) {
  specialUse.addSubnet(address, prefix);
}
specialUse.addSubnet("2001::", 23, "ipv6");
specialUse.addSubnet("2001:db8::", 32, "ipv6");
specialUse.addSubnet("2002::", 16, "ipv6");
specialUse.addSubnet("3fff::", 20, "ipv6");

const globalUnicast = new BlockList();
globalUnicast.addSubnet("2000::", 3, "ipv6");

export function isBlockedIp(ip: string): boolean {
  if (isIPv4(ip)) return specialUse.check(ip);
  if (isIPv6(ip)) return ip.includes("%") || !globalUnicast.check(ip, "ipv6") || specialUse.check(ip, "ipv6");
  return true;
}

export interface CheckedTarget {
  url: URL;
  resolvedIp: string;
}

/**
 * Validates that `rawUrl` is safe to fetch server-side. Throws
 * SsrfBlockedError (or a generic Error for malformed input) if not.
 */
export async function assertPublicHttpsTarget(rawUrl: string, signal?: AbortSignal): Promise<CheckedTarget> {
  let url: URL;
  try {
    url = new URL(rawUrl);
  } catch {
    throw new Error("That doesn't look like a valid URL.");
  }

  if (url.protocol !== "https:") {
    throw new SsrfBlockedError("Only https:// URLs are supported.");
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

  const hostname = url.hostname.replace(/\.$/, "");

  // Reject raw IP literals outright — this is a domain scanner, not a
  // generic internal-network prober.
  if (isIPv4(hostname) || hostname.startsWith("[")) {
    throw new SsrfBlockedError("Scanning raw IP addresses isn't supported — use a domain name.");
  }
  if (!hostname.includes(".") || hostname.endsWith(".localhost") || hostname.endsWith(".local")) {
    throw new SsrfBlockedError("Local hostnames aren't allowed.");
  }

  let addresses: string[];
  signal?.throwIfAborted();
  try {
    const lookup = dns.lookup(hostname, { all: true, verbatim: false });
    const records = signal ? await new Promise<Awaited<typeof lookup>>((resolve, reject) => {
      const listener = addAbortListener(signal, () => reject(signal.reason));
      void lookup.then(resolve, reject).finally(() => listener[Symbol.dispose]());
    }) : await lookup;
    addresses = records.map((r) => r.address);
  } catch {
    signal?.throwIfAborted();
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
