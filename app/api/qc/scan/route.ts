import { after } from "next/server";
import { nanoid } from "nanoid";
import { validateDomainInput } from "@/lib/validate-domain";
import { checkAndRegisterCooldown } from "@/lib/rate-limit";
import { createQc } from "@/lib/qc-store";
import { runQc } from "@/lib/qc-runner";
import type { QcModulesSelection } from "@/lib/qc-types";

interface ScanBody {
  domain?: string;
  modules?: Partial<QcModulesSelection>;
}

export async function POST(req: Request) {
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

  // Cooldown key dipisah dari passive scan (prefix "qc:") supaya QC dan
  // Passive Security Audit tidak saling memblokir cooldown-nya.
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

  const qcId = nanoid(10);
  // WAJIB di-await: harus tersimpan di Redis sebelum response balik ke
  // client, karena client langsung connect ke /api/qc/[id]/stream begitu
  // dapat id.
  await createQc(qcId, validation.hostname, validation.normalizedUrl, modules);

  after(async () => {
    await runQc(qcId, validation.normalizedUrl!, modules);
  });

  return Response.json({ ok: true, id: qcId });
}
