/**
 * Pembaca ZIP aman, tanpa dependensi (hanya zlib bawaan Node).
 *
 * Dirancang untuk input TIDAK tepercaya:
 * - Semua diproses di memori, tidak ada yang ditulis ke disk (zip-slip tidak mungkin).
 * - Path dinormalisasi; entri berisi ".." / absolut / drive Windows dilewati.
 * - Batas jumlah entri, ukuran per file, total ukuran terurai, dan rasio kompresi (zip bomb).
 * - inflateRawSync dengan maxOutputLength: dekompresi berhenti keras di batas, walau header berbohong.
 * - Entri terenkripsi, ZIP64, symlink dan metode kompresi selain store/deflate ditolak/dilewati.
 */
import { inflateRawSync } from "node:zlib";

export interface ZipLimits {
  maxEntries: number;
  maxFileBytes: number; // file lebih besar dilewati (bukan error)
  maxTotalBytes: number; // total byte terurai
  maxRatio: number; // rasio uncompressed/compressed per entri
}

export const DEFAULT_ZIP_LIMITS: ZipLimits = {
  maxEntries: 6000,
  maxFileBytes: 1_500_000,
  maxTotalBytes: 80_000_000,
  maxRatio: 250,
};

export interface ZipEntry {
  path: string;
  size: number;
  data: Buffer;
}

export interface ZipReadResult {
  entries: ZipEntry[];
  /** Semua path berkas (termasuk biner & folder yang diabaikan), untuk deteksi berkas sensitif dari nama. */
  allPaths: string[];
  hasGitDir: boolean;
  hasNodeModules: boolean;
  skipped: { path: string; reason: string }[];
  totalEntries: number;
  totalBytes: number;
}

export class ZipError extends Error {}

const SIG_EOCD = 0x06054b50;
const SIG_CEN = 0x02014b50;
const SIG_LOC = 0x04034b50;

/** Folder/berkas yang tidak berguna untuk audit (vendor, build, biner besar). */
const IGNORED_DIRS = /(^|\/)(node_modules|\.git|\.next|\.nuxt|dist|build|out|coverage|\.turbo|\.vercel|\.cache|vendor\/bundle|__pycache__|\.venv|venv|\.idea|\.gradle|Pods|bin\/Debug|bin\/Release|obj)(\/|$)/;
const BINARY_EXT = /\.(png|jpe?g|gif|webp|avif|ico|bmp|tiff?|psd|mp[34]|mov|avi|webm|wav|ogg|flac|zip|rar|7z|gz|tgz|bz2|xz|jar|war|class|exe|dll|so|dylib|o|a|bin|dat|woff2?|ttf|otf|eot|pdf|docx?|xlsx?|pptx?|apk|aab|ipa|dmg|iso|db|sqlite3?|pyc|wasm)$/i;

export function normalizeZipPath(raw: string): string | null {
  let p = raw.replace(/\\/g, "/");
  if (/^[a-zA-Z]:/.test(p) || p.startsWith("/")) return null; // absolut
  const parts: string[] = [];
  for (const seg of p.split("/")) {
    if (seg === "" || seg === ".") continue;
    if (seg === "..") return null; // traversal
    parts.push(seg);
  }
  p = parts.join("/");
  return p || null;
}

export function readZip(buf: Buffer, limits: ZipLimits = DEFAULT_ZIP_LIMITS): ZipReadResult {
  if (buf.length < 22 || buf.readUInt32LE(0) !== SIG_LOC) {
    throw new ZipError("Berkas bukan arsip ZIP yang valid.");
  }

  // Cari End Of Central Directory dari belakang (komentar ZIP maks 65535 byte).
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 65535); i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new ZipError("Struktur ZIP rusak (EOCD tidak ditemukan).");

  const totalEntries = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if (totalEntries === 0xffff || cdOffset === 0xffffffff || cdSize === 0xffffffff) {
    throw new ZipError("ZIP64 tidak didukung. Kompres ulang proyek tanpa node_modules/build.");
  }
  if (totalEntries > limits.maxEntries) {
    throw new ZipError(`Terlalu banyak file (${totalEntries}). Maksimal ${limits.maxEntries}; buang node_modules, .git dan folder build.`);
  }
  if (cdOffset + cdSize > buf.length) throw new ZipError("Struktur ZIP rusak (central directory di luar berkas).");

  const entries: ZipEntry[] = [];
  const allPaths: string[] = [];
  let hasGitDir = false;
  let hasNodeModules = false;
  const skipped: { path: string; reason: string }[] = [];
  let totalBytes = 0;
  let p = cdOffset;

  for (let n = 0; n < totalEntries; n++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== SIG_CEN) {
      throw new ZipError("Struktur ZIP rusak (entri central directory tidak valid).");
    }
    const versionMadeBy = buf.readUInt16LE(p + 4);
    const flags = buf.readUInt16LE(p + 8);
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const uncompSize = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const externalAttr = buf.readUInt32LE(p + 38);
    const localOffset = buf.readUInt32LE(p + 42);
    const rawName = buf.toString(flags & 0x800 ? "utf8" : "latin1", p + 46, p + 46 + nameLen);
    p += 46 + nameLen + extraLen + commentLen;

    if (rawName.endsWith("/")) continue; // direktori
    const path = normalizeZipPath(rawName);
    if (!path) {
      skipped.push({ path: rawName.slice(0, 200), reason: "path tidak aman (absolut/..)" });
      continue;
    }
    if (/(^|\/)\.git\//.test(path)) hasGitDir = true;
    if (/(^|\/)node_modules\//.test(path)) hasNodeModules = true;
    if (IGNORED_DIRS.test(path)) continue;
    if (allPaths.length < 20000) allPaths.push(path);
    if (BINARY_EXT.test(path)) continue;

    if (flags & 0x1) {
      skipped.push({ path, reason: "terenkripsi" });
      continue;
    }
    const unixMode = (versionMadeBy >> 8) === 3 ? (externalAttr >>> 16) & 0o170000 : 0;
    if (unixMode === 0o120000) {
      skipped.push({ path, reason: "symlink" });
      continue;
    }
    if (method !== 0 && method !== 8) {
      skipped.push({ path, reason: `metode kompresi ${method} tidak didukung` });
      continue;
    }
    if (compSize === 0xffffffff || uncompSize === 0xffffffff) {
      skipped.push({ path, reason: "ZIP64" });
      continue;
    }
    if (uncompSize > limits.maxFileBytes) {
      skipped.push({ path, reason: `terlalu besar (${Math.round(uncompSize / 1024)} KB)` });
      continue;
    }
    if (compSize > 0 && uncompSize / compSize > limits.maxRatio) {
      throw new ZipError(`Rasio kompresi mencurigakan pada ${path} (indikasi zip bomb). Audit dibatalkan.`);
    }
    if (totalBytes + uncompSize > limits.maxTotalBytes) {
      throw new ZipError("Total isi arsip melebihi batas aman. Buang folder dependensi/build lalu coba lagi.");
    }

    // Local header: nama & extra bisa berbeda panjang dengan central directory.
    if (localOffset + 30 > buf.length || buf.readUInt32LE(localOffset) !== SIG_LOC) {
      skipped.push({ path, reason: "local header tidak valid" });
      continue;
    }
    const lNameLen = buf.readUInt16LE(localOffset + 26);
    const lExtraLen = buf.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + lNameLen + lExtraLen;
    const dataEnd = dataStart + compSize;
    if (dataEnd > buf.length) {
      skipped.push({ path, reason: "data terpotong" });
      continue;
    }
    const raw = buf.subarray(dataStart, dataEnd);

    let data: Buffer;
    try {
      // maxOutputLength: batas keras, tidak peduli apa kata header (anti zip bomb).
      data = method === 0 ? Buffer.from(raw) : inflateRawSync(raw, { maxOutputLength: limits.maxFileBytes + 1 });
    } catch {
      skipped.push({ path, reason: "gagal didekompresi / melebihi batas" });
      continue;
    }
    if (data.length > limits.maxFileBytes) {
      skipped.push({ path, reason: "ukuran aktual melebihi batas" });
      continue;
    }
    totalBytes += data.length;
    if (totalBytes > limits.maxTotalBytes) {
      throw new ZipError("Total isi arsip melebihi batas aman.");
    }
    entries.push({ path, size: data.length, data });
  }

  return { entries, allPaths, hasGitDir, hasNodeModules, skipped, totalEntries, totalBytes };
}

/** Heuristik teks: tolak berkas dengan byte NUL di 8 KB pertama. */
export function isProbablyText(data: Buffer): boolean {
  const n = Math.min(data.length, 8192);
  for (let i = 0; i < n; i++) if (data[i] === 0) return false;
  return true;
}
