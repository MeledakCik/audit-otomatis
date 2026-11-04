import { K, TTL, redis, scanKeys } from "./redis";
import { decrypt, encrypt, randomId } from "./crypto";
import type { AuditResult, PublicFinding, RawEvidence } from "./audit";

export const DOMAIN_RE = /^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/;
export const VAULT_KEY_RE = /^sentinel:vault:admin:([a-z0-9.-]+):([0-9a-f]{12})$/;
export const AUTH_KEY_RE = /^sentinel:auth:([a-z0-9.-]+):([A-Za-z0-9_-]{16,64})$/;
export const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

const parse = <T>(s: string | null): T | null => {
  if (!s) return null;
  try { return JSON.parse(s) as T; } catch { return null; }
};

// ---------- PUBLIC ----------
export interface PublicRecord {
  domain: string;
  scannedAt: number;
  findings: PublicFinding[];
}

export async function savePublic(r: AuditResult) {
  const rec: PublicRecord = { domain: r.domain, scannedAt: r.scannedAt, findings: r.findings };
  await redis().set(K.public(r.domain), JSON.stringify(rec), { ex: TTL.public });
  return rec;
}

export async function getPublic(domain: string) {
  return parse<PublicRecord>(await redis().get<string>(K.public(domain)));
}

// ---------- VAULT (AES-256-GCM, AAD = nama key) ----------
export async function saveVault(raw: RawEvidence[]): Promise<string[]> {
  const ids: string[] = [];
  const p = redis().pipeline();
  for (const ev of raw) {
    const id = randomId();
    const key = K.vault(ev.domain, id);
    p.set(key, encrypt(JSON.stringify(ev), key), { ex: TTL.vault });
    ids.push(id);
  }
  if (ids.length) await p.exec();
  return ids;
}

export interface VaultListItem { key: string; domain: string; id: string; ttl: number }

export async function listVault(): Promise<VaultListItem[]> {
  const keys = (await scanKeys(K.vaultPattern())).filter((k) => VAULT_KEY_RE.test(k));
  if (!keys.length) return [];
  const p = redis().pipeline();
  keys.forEach((k) => p.ttl(k));
  const ttls = (await p.exec()) as number[];
  return keys
    .map((key, i) => {
      const m = VAULT_KEY_RE.exec(key)!;
      return { key, domain: m[1], id: m[2], ttl: Number(ttls[i]) };
    })
    .filter((x) => x.ttl > 0)
    .sort((a, b) => a.domain.localeCompare(b.domain));
}

export async function readVault(key: string): Promise<RawEvidence | null> {
  if (!VAULT_KEY_RE.test(key)) throw new Error("Key vault tidak valid.");
  const ct = await redis().get<string>(key);
  if (!ct) return null;
  return JSON.parse(decrypt(ct, key)) as RawEvidence;
}

export async function vaultKeysForDomain(domain: string): Promise<string[]> {
  return (await scanKeys(K.vaultPattern(domain))).filter((k) => VAULT_KEY_RE.test(k));
}

// ---------- AUTH REQUEST ----------
export type AuthStatus = "AWAITING_PROOF" | "PENDING" | "APPROVED" | "REJECTED" | "VIEWED";

export interface AuthRecord {
  domain: string;
  userId: string;
  status: AuthStatus;
  challenge: string; // sentinel-verify-xxxx
  proof?: { method: "dns" | "file"; verifiedAt: number };
  createdAt: number;
  decidedAt?: number;
  viewToken?: string;
  viewTokenExp?: number;
}

export async function getAuth(domain: string, userId: string) {
  return parse<AuthRecord>(await redis().get<string>(K.auth(domain, userId)));
}

/** Update tanpa memperpanjang TTL 48 jam. */
export async function putAuth(rec: AuthRecord, opts: { create?: boolean } = {}) {
  const key = K.auth(rec.domain, rec.userId);
  if (opts.create) await redis().set(key, JSON.stringify(rec), { ex: TTL.auth });
  else await redis().set(key, JSON.stringify(rec), { keepTtl: true });
}

export async function listAuth(): Promise<Array<{ key: string; ttl: number; rec: AuthRecord }>> {
  const keys = (await scanKeys(K.authPattern)).filter((k) => AUTH_KEY_RE.test(k));
  if (!keys.length) return [];
  const p = redis().pipeline();
  keys.forEach((k) => { p.get(k); p.ttl(k); });
  const res = await p.exec();
  const out: Array<{ key: string; ttl: number; rec: AuthRecord }> = [];
  keys.forEach((key, i) => {
    const rec = parse<AuthRecord>(res[i * 2] as string | null);
    if (rec) out.push({ key, ttl: Number(res[i * 2 + 1]), rec });
  });
  return out.sort((a, b) => b.rec.createdAt - a.rec.createdAt);
}

// ---------- TEMP ONE-TIME VIEW ----------
export interface TempView {
  userId: string;
  domain: string;
  items: Array<{ key: string; ct: string }>; // ciphertext tetap terenkripsi saat "at rest"
}

export async function createTempView(token: string, t: TempView) {
  await redis().set(K.tempView(token), JSON.stringify(t), { ex: TTL.tempView });
}
export async function peekTempView(token: string) {
  return parse<TempView>(await redis().get<string>(K.tempView(token)));
}
/** Atomic get+delete → benar-benar sekali pakai. */
export async function consumeTempView(token: string) {
  return parse<TempView>(await redis().getdel<string>(K.tempView(token)));
}
export const decryptItem = (i: { key: string; ct: string }) => JSON.parse(decrypt(i.ct, i.key)) as RawEvidence;
