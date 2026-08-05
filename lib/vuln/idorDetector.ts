/**
 * lib/vuln/idorDetector.ts
 *
 * Deteksi pola URL yang mengandung numeric ID (mis. /user/123 atau segmen
 * numerik >=2 digit lainnya) lalu generate kandidat ID pengganti buat dites
 * IDOR (Insecure Direct Object Reference) di step lain. TIDAK melakukan
 * request apapun di sini — cuma generate test case.
 *
 * Pure function.
 */

import type { AuditFinding } from "./types";

const USER_ID_RE = /\/users?\/(\d+)(?=\/|$|\?)/;
const GENERIC_ID_RE = /\/(\d{2,})(?=\/|$|\?)/;

export interface IdorCase extends AuditFinding {
  type: "IDOR_CANDIDATE";
  originalUrl: string;
  originalId: string;
  /** URL siap-test dengan ID diganti candidateId (belum di-fetch) */
  testUrl: string;
  candidateId: string;
}

function buildCandidateIds(originalId: string): string[] {
  const n = parseInt(originalId, 10);
  const candidates = new Set<string>();
  if (!Number.isNaN(n)) {
    candidates.add(String(n + 1));
  }
  candidates.add("1");
  candidates.add("0");
  candidates.delete(originalId); // jangan generate kandidat yang sama dengan original
  return Array.from(candidates);
}

function replaceFirstOccurrence(url: string, originalId: string, candidateId: string): string {
  // ganti hanya kemunculan pertama angka tsb yang diapit "/" (biar tidak nyasar ganti substring lain)
  return url.replace(new RegExp(`/${originalId}(?=/|$|\\?)`), `/${candidateId}`);
}

/**
 * Scan daftar URL, cari pola /user/<id> atau /users/<id> atau segmen numerik
 * >=2 digit (/.../123/...), lalu generate IdorCase per URL yang match:
 * kandidat ID pengganti = [originalId+1, 1, 0] (dedup, exclude originalId).
 */
export function generateIdorCases(urls: string[]): IdorCase[] {
  const cases: IdorCase[] = [];

  for (const url of urls) {
    const userMatch = USER_ID_RE.exec(url);
    const genericMatch = !userMatch ? GENERIC_ID_RE.exec(url) : null;
    const match = userMatch ?? genericMatch;
    if (!match) continue;

    const originalId = match[1];
    const candidates = buildCandidateIds(originalId);

    for (const candidateId of candidates) {
      cases.push({
        type: "IDOR_CANDIDATE",
        severity: "medium",
        url,
        originalUrl: url,
        originalId,
        candidateId,
        testUrl: replaceFirstOccurrence(url, originalId, candidateId),
        evidence: `URL "${url}" mengandung ID numerik "${originalId}" di path — pattern ${
          userMatch ? "/user(s)/<id>" : "/<id>/ generic"
        }`,
      });
    }
  }

  return cases;
}
