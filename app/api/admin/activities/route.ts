import { NextResponse } from "next/server";
import { guardAdmin, noStore } from "@/lib/sentinel/admin-auth";
import { buildUserProfiles, listUserActivities, type UserActivityRecord } from "@/lib/activity-store";
import { listScans } from "@/lib/scan-store";
import { listQcs } from "@/lib/qc-store";
import { listAuth, listVault } from "@/lib/sentinel/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET(req: Request) {
  const denied = await guardAdmin(req);
  if (denied) return denied;

  try {
    const [recordedActivities, scans, qcs, authRequests, vaultItems] = await Promise.all([
      listUserActivities(300),
      listScans(100).catch(() => []),
      listQcs(50).catch(() => []),
      listAuth().catch(() => []),
      listVault().catch(() => []),
    ]);

    // Merge synthetic activity entries from existing scans/QCs/authRequests if not already in recordedActivities
    const existingScanIds = new Set(
      recordedActivities.map((a) => a.meta?.scanId).filter(Boolean)
    );

    const syntheticActivities: UserActivityRecord[] = [];

    for (const s of scans) {
      if (existingScanIds.has(s.id)) continue;
      const crit = s.severityCounts?.CRITICAL ?? 0;
      const high = s.severityCounts?.HIGH ?? 0;
      syntheticActivities.push({
        id: `scan_${s.id}`,
        timestamp: s.createdAt,
        ip: "recorded-scan",
        userAgent: "Sentinel-ID Scanner Engine",
        userId: `scan_${s.id.slice(0, 6)}`,
        module: "FULL_SCAN",
        moduleLabel: "Full Passive Scan",
        action: `Full Audit & Sentinel Scan (${s.status})`,
        target: s.domain,
        status:
          crit > 0
            ? "CRITICAL"
            : high > 0
            ? "WARNING"
            : s.status === "error"
            ? "ERROR"
            : s.status === "blocked_cloudflare"
            ? "BLOCKED"
            : s.status === "done"
            ? "SUCCESS"
            : "RUNNING",
        summary: `${s.pagesCount} halaman · ${s.findingsCount} temuan (${crit} CRIT, ${high} HIGH)`,
        meta: {
          scanId: s.id,
          findingsCount: s.findingsCount,
          criticalCount: crit,
          highCount: high,
          pagesCount: s.pagesCount,
          scanStatus: s.status,
        },
      });
    }

    for (const q of qcs) {
      if (existingScanIds.has(q.id)) continue;
      syntheticActivities.push({
        id: `qc_${q.id}`,
        timestamp: q.createdAt,
        ip: "recorded-qc",
        userAgent: "Sentinel-ID QC Engine",
        userId: `qc_${q.id.slice(0, 6)}`,
        module: "QC_SCAN",
        moduleLabel: "QC Otomatis (SEO/Perf)",
        action: `QC Otomatis Domain (${q.status})`,
        target: q.domain,
        status: q.status === "error" ? "ERROR" : q.status === "done" ? "SUCCESS" : "RUNNING",
        summary: `Skor QC: ${q.overallScore ?? "—"} · ${q.requestsMade} request`,
        meta: {
          scanId: q.id,
          overallScore: q.overallScore ?? 0,
        },
      });
    }

    for (const a of authRequests) {
      const synthId = `auth_${a.rec.domain}_${a.rec.createdAt}`;
      if (recordedActivities.some((x) => x.id === synthId)) continue;
      syntheticActivities.push({
        id: synthId,
        timestamp: a.rec.createdAt,
        ip: "domain-owner",
        userAgent: "Domain Claim Verification",
        userId: a.rec.userId.slice(0, 12),
        module: "SENTINEL_CLAIM",
        moduleLabel: "Klaim Kepemilikan Domain",
        action: `Klaim Domain (${a.rec.status})`,
        target: a.rec.domain,
        status:
          a.rec.status === "APPROVED" || a.rec.status === "VIEWED"
            ? "SUCCESS"
            : a.rec.status === "PENDING"
            ? "WARNING"
            : a.rec.status === "REJECTED"
            ? "ERROR"
            : "RUNNING",
        summary: a.rec.proof
          ? `Bukti ${a.rec.proof.method.toUpperCase()} terverifikasi · Status: ${a.rec.status}`
          : `Menunggu bukti kepemilikan (${a.rec.status})`,
        meta: {
          claimStatus: a.rec.status,
          proofMethod: a.rec.proof?.method ?? null,
        },
      });
    }

    const allActivities = [...recordedActivities, ...syntheticActivities]
      .sort((a, b) => b.timestamp - a.timestamp)
      .slice(0, 350);

    const users = buildUserProfiles(allActivities);

    const stats = {
      totalActivities: allActivities.length,
      uniqueUsers: users.length,
      totalScans: scans.length,
      totalQcs: qcs.length,
      vaultItemsCount: vaultItems.length,
      pendingClaimsCount: authRequests.filter((r) => r.rec.status === "PENDING").length,
      totalClaimsCount: authRequests.length,
      criticalEventsCount: allActivities.filter((a) => a.status === "CRITICAL").length,
    };

    return NextResponse.json(
      {
        ok: true,
        stats,
        activities: allActivities,
        users,
        scans,
        qcs,
        vaultCount: vaultItems.length,
        claimsCount: authRequests.length,
      },
      { headers: noStore }
    );
  } catch (e) {
    console.error("[api/admin/activities] error:", e);
    return NextResponse.json(
      { error: e instanceof Error ? e.message : "Gagal memuat aktivitas user" },
      { status: 500, headers: noStore }
    );
  }
}
