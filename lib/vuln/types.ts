/**
 * lib/vuln/types.ts
 *
 * Shared "standard JSON" shape untuk semua modul passive-audit baru
 * (jsLibChecker, domSink, redirectChecker, idorDetector, authChecker, dst).
 *
 * NOTE: project ini sudah punya `Severity` sendiri di lib/types.ts
 * ("CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO", uppercase) yang dipakai
 * oleh `Finding`. Modul baru di task ini secara eksplisit diminta pakai
 * severity lowercase ('low' | 'medium' | 'high'), jadi didefinisikan sebagai
 * type terpisah (`AuditSeverity`) supaya tidak bentrok. Kalau nanti mau
 * disatukan ke `Finding` yang lama, tinggal pakai `toLegacySeverity()` di
 * bawah saat mapping.
 */

export type AuditSeverity = "low" | "medium" | "high";

/** Bentuk JSON standar yang diminta di task untuk semua modul baru. */
export interface AuditFinding {
  type: string;
  severity: AuditSeverity;
  /** Boleh kosong kalau fungsi tidak punya konteks URL (mis. hanya dikasih jsContent). */
  url?: string;
  evidence: string;
  payload?: string;
}

/** Helper opsional kalau nanti mau di-merge ke Finding/Severity lama di lib/types.ts */
export function toLegacySeverity(
  s: AuditSeverity
): "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO" {
  switch (s) {
    case "high":
      return "HIGH";
    case "medium":
      return "MEDIUM";
    case "low":
    default:
      return "LOW";
  }
}
