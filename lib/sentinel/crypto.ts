import { createCipheriv, createDecipheriv, createHash, randomBytes } from "node:crypto";

/**
 * AES-256-GCM. Format: v1.<iv>.<tag>.<ciphertext> (base64url).
 * AAD = nama key Redis → ciphertext tidak bisa "dipindah" ke key lain.
 * ADMIN_VAULT_KEY: 32 byte, hex (64 char) atau base64.
 */
function getKey(): Buffer {
  const raw = process.env.ADMIN_VAULT_KEY;
  if (!raw) {
    if (process.env.NODE_ENV === "production") {
      throw new Error("ADMIN_VAULT_KEY belum diset.");
    }
    return createHash("sha256").update("sentinel-dev-fallback-vault-key-32b").digest();
  }
  const key = /^[0-9a-fA-F]{64}$/.test(raw) ? Buffer.from(raw, "hex") : Buffer.from(raw, "base64");
  if (key.length !== 32) {
    return createHash("sha256").update(raw).digest();
  }
  return key;
}

export function encrypt(plaintext: string, aad: string): string {
  const iv = randomBytes(12);
  const c = createCipheriv("aes-256-gcm", getKey(), iv);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(plaintext, "utf8"), c.final()]);
  return ["v1", iv.toString("base64url"), c.getAuthTag().toString("base64url"), ct.toString("base64url")].join(".");
}

export function decrypt(payload: string, aad: string): string {
  const [v, iv, tag, ct] = payload.split(".");
  if (v !== "v1" || !iv || !tag || !ct) throw new Error("Format ciphertext tidak valid.");
  const d = createDecipheriv("aes-256-gcm", getKey(), Buffer.from(iv, "base64url"));
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(Buffer.from(tag, "base64url"));
  return Buffer.concat([d.update(Buffer.from(ct, "base64url")), d.final()]).toString("utf8");
}

export const randomToken = (bytes = 32) => randomBytes(bytes).toString("base64url");
export const randomId = () => randomBytes(6).toString("hex");
