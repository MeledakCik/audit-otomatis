import { after } from "next/server";
import { nanoid } from "nanoid";
import { validateDomainInput } from "@/lib/validate-domain";
import { checkAndRegisterCooldown } from "@/lib/rate-limit";
import { createQc } from "@/lib/qc-store";
import { runQc } from "@/lib/qc-runner";
import { logUserActivity } from "@/lib/activity-store";
import type { QcModulesSelection } from "@/lib/qc-types";

interface ScanBody {
  domain?: string;
  modules?: Partial<QcModulesSelection>;
}

export async function POST(req: Request) {
  try {
    let body: ScanBody;
    try {
      body = (await req.json()) as ScanBody;
    } catch {
      return Response.json({ ok: false, error: "Body request tidak valid (harus JSON)." }, { status: 400 });
    }

    const validation = validateDomainInput(body.domain ?? "");
    if (!validation.ok || !validation.normalizedUrl || !validation.hostname) {
      return Response.json({ ok: false, error: validation.error }, { status: 400 });
    }

    const modules: QcModulesSelection = {
      seo: body.modules?.seo ?? true,
      perf: body.modules?.perf ?? true,
      content: body.modules?.content ?? true,
    };

    if (!modules.seo && !modules.perf && !modules.content) {
      return Response.json(
        { ok: false, error: "Pilih minimal satu modul QC (SEO / Performance / Content)." },
        { status: 400 }
      );
    }

    const userKey = req.headers.get("x-forwarded-for") || req.headers.get("x-real-ip") || "anonymous";

    try {
      const cooldown = await checkAndRegisterCooldown(userKey, `qc:${validation.hostname}`);
      if (!cooldown.allowed) {
        const seconds = Math.ceil(cooldown.retryAfterMs / 1000);
        return Response.json(
          {
            ok: false,
            error: `Domain ini baru saja di-QC. Coba lagi dalam ${seconds} detik (limit: 1 QC/domain/5 menit).`,
          },
          { status: 429 }
        );
      }
    } catch {
      // Jangan blokir apabila Redis cooldown gagal
    }

    const qcId = nanoid(10);
    await createQc(qcId, validation.hostname, validation.normalizedUrl, modules);

    await logUserActivity({
      req,
      module: "QC_SCAN",
      action: "Memulai QC Otomatis (SEO Master · Perf · Content)",
      target: validation.hostname,
      status: "RUNNING",
      summary: `QC ID: ${qcId} (SEO: ${modules.seo ? "Ya" : "Tidak"}, Perf: ${modules.perf ? "Ya" : "Tidak"}, Content: ${modules.content ? "Ya" : "Tidak"})`,
      meta: { scanId: qcId },
    }).catch(() => {});

    try {
      after(async () => {
        await runQc(qcId, validation.normalizedUrl!, modules);
      });
    } catch {
      void runQc(qcId, validation.normalizedUrl!, modules);
    }

    return Response.json({ ok: true, id: qcId, domain: validation.hostname });
  } catch (err) {
    return Response.json(
      {
        ok: false,
        error: err instanceof Error ? err.message : "Gagal memulai QC di server.",
      },
      { status: 500 }
    );
  }
}
