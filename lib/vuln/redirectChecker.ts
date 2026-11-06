/**
 * lib/vuln/redirectChecker.ts
 *
 * Analisis nama query-param secara pasif (TANPA fetch / TANPA eksekusi payload):
 * 1. OPEN_REDIRECT & SSRF (url, redirect, next, dest, target, returnUrl)
 * 2. NODE_OOB (Out-of-Band interaction / webhook / callback / XML / pingback kandidat)
 * 3. SHELL_SURFACE (kandidat parameter command/code/file-inclusion: cmd, exec, shell, php, file, path, template)
 * 4. FILEMANAGER_SHELL (kandidat parameter kontrol WebShell / FileManager: dir, cwd, chmod, mkdir, unlink, rename, act, upfile, d, f, p)
 *
 * Pure function.
 */

import type { AuditFinding, AuditSeverity } from "./types";

const REDIRECT_PARAM_NAMES = ["url", "redirect", "next", "dest", "target", "returnUrl"] as const;
const OOB_PARAM_NAMES = [
  "callback",
  "webhook",
  "notify_url",
  "pingback",
  "oob",
  "wsdl",
  "xml",
  "uri",
  "host",
  "domain",
] as const;
const SHELL_PARAM_NAMES = [
  "cmd",
  "exec",
  "shell",
  "command",
  "code",
  "eval",
  "template",
  "include",
  "file",
  "path",
  "passthru",
  "system",
] as const;
const FILEMANAGER_PARAM_NAMES = [
  "dir",
  "cwd",
  "chmod",
  "mkdir",
  "unlink",
  "rename",
  "upfile",
  "upload",
  "fm_usr",
  "fm_pwd",
  "elfinder",
] as const;

const OPEN_REDIRECT_PAYLOAD = "https://evil.com";
const SSRF_PAYLOADS = ["http://127.0.0.1", "http://169.254.169.254"] as const;

export interface TestCase extends AuditFinding {
  type: "OPEN_REDIRECT" | "SSRF" | "NODE_OOB" | "SHELL_SURFACE" | "FILEMANAGER_SURFACE";
  originalUrl: string;
  param: string;
  payload: string;
}

function safeParseUrl(raw: string): URL | null {
  try {
    return new URL(raw, "https://placeholder.invalid");
  } catch {
    return null;
  }
}

function severityFor(type: TestCase["type"]): AuditSeverity {
  if (type === "SSRF" || type === "SHELL_SURFACE" || type === "FILEMANAGER_SURFACE" || type === "NODE_OOB")
    return "high";
  return "medium";
}

/**
 * Cek query param di `url` secara pasif tanpa mengirim request apa pun.
 */
export function detectRedirectParams(url: string): TestCase[] {
  const parsed = safeParseUrl(url);
  if (!parsed) return [];

  const cases: TestCase[] = [];
  const redirectSet = new Set(REDIRECT_PARAM_NAMES.map((p) => p.toLowerCase()));
  const oobSet = new Set(OOB_PARAM_NAMES.map((p) => p.toLowerCase()));
  const shellSet = new Set(SHELL_PARAM_NAMES.map((p) => p.toLowerCase()));
  const fmSet = new Set(FILEMANAGER_PARAM_NAMES.map((p) => p.toLowerCase()));

  for (const key of parsed.searchParams.keys()) {
    const k = key.toLowerCase();

    if (redirectSet.has(k)) {
      cases.push({
        type: "OPEN_REDIRECT",
        severity: severityFor("OPEN_REDIRECT"),
        url,
        originalUrl: url,
        param: key,
        payload: OPEN_REDIRECT_PAYLOAD,
        evidence: `param "${key}" terlihat seperti redirect target di ${url}`,
      });

      for (const ssrfPayload of SSRF_PAYLOADS) {
        cases.push({
          type: "SSRF",
          severity: severityFor("SSRF"),
          url,
          originalUrl: url,
          param: key,
          payload: ssrfPayload,
          evidence: `param "${key}" berpotensi dipakai server buat fetch balik ke internal/metadata endpoint`,
        });
      }
    }

    if (oobSet.has(k)) {
      cases.push({
        type: "NODE_OOB",
        severity: severityFor("NODE_OOB"),
        url,
        originalUrl: url,
        param: key,
        payload: "https://oob-audit.sentinel-id.invalid/callback",
        evidence: `param "${key}" berpotensi memicu koneksi Out-of-Band (OOB / SSRF / Webhook) pada ${url}`,
      });
    }

    if (shellSet.has(k)) {
      cases.push({
        type: "SHELL_SURFACE",
        severity: severityFor("SHELL_SURFACE"),
        url,
        originalUrl: url,
        param: key,
        payload: "<passive-review-only>",
        evidence: `param "${key}" pada ${url} memiliki penamaan kandidat eksekusi perintah/webshell/file (wp2shell/php2shell/node2shell/py2shell/go2shell/webshell)`,
      });
    }

    if (fmSet.has(k)) {
      cases.push({
        type: "FILEMANAGER_SURFACE",
        severity: severityFor("FILEMANAGER_SURFACE"),
        url,
        originalUrl: url,
        param: key,
        payload: "<passive-review-only>",
        evidence: `param "${key}" pada ${url} merupakan parameter khas operasi Web FileManager / WebShell (navigasi direktori, chmod, upload, atau manipulasi file)`,
      });
    }
  }

  return cases;
}
