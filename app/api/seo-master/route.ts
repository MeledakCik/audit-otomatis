// app/api/seo-master/route.ts
import { NextResponse } from "next/server";
import { validateDomainInput } from "@/lib/validate-domain";
import { assertPublicHttpsTarget, SsrfBlockedError } from "@/lib/ssrf-guard";
import { runSeoMasterAudit } from "@/lib/seo-master-scanner";
import { logUserActivity } from "@/lib/activity-store";

export const maxDuration = 60;

export async function POST(req: Request) {
  try {
    const body = await req.json().catch(() => ({}));
    const rawDomain = typeof body.domain === "string" ? body.domain.trim() : "";
    const targetKeyword =
      typeof body.keyword === "string" ? body.keyword.trim().slice(0, 120) : undefined;

    const validation = validateDomainInput(rawDomain);
    if (!validation.ok || !validation.normalizedUrl || !validation.hostname) {
      return NextResponse.json(
        { ok: false, error: validation.error ?? "Domain tidak valid." },
        { status: 400 }
      );
    }

    await assertPublicHttpsTarget(validation.normalizedUrl);

    const audit = await runSeoMasterAudit(
      validation.normalizedUrl,
      validation.hostname,
      targetKeyword
    );

    await logUserActivity({
      req,
      module: "SEO_MASTER",
      action: "SCAN_SEO_MASTER",
      target: validation.hostname,
      status:
        audit.overallMasterScore >= 75
          ? "SUCCESS"
          : audit.overallMasterScore >= 50
          ? "WARNING"
          : "CRITICAL",
      summary: `SEO Master Score ${audit.overallMasterScore}/100 (Grade ${audit.rankReadinessGrade}) · Intl ${audit.seo.internationalScore}/100 · Tech ${audit.seo.technicalScore}/100`,
      meta: {
        overallScore: audit.overallMasterScore,
        grade: audit.rankReadinessGrade,
        intlScore: audit.seo.internationalScore,
        techScore: audit.seo.technicalScore,
        hreflangCount: audit.seo.meta.hreflangTags.length,
        jsonLdCount: audit.seo.meta.jsonLdCount,
      },
    }).catch(() => {});

    return NextResponse.json({ ok: true, audit });
  } catch (err) {
    if (err instanceof SsrfBlockedError) {
      return NextResponse.json({ ok: false, error: err.message }, { status: 403 });
    }
    return NextResponse.json(
      {
        ok: false,
        error:
          err instanceof Error
            ? err.message
            : "Gagal menjalankan analisis SEO Master.",
      },
      { status: 500 }
    );
  }
}
