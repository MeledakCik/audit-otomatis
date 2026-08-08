import { analyzeSecurityLog } from "@/lib/maintenance/analyzer";
import { enrichReportWithGroq } from "@/lib/maintenance/groq-enrich";

const MAX_INPUT_CHARS = 10 * 1024 * 1024; // ~10MB, selaras dengan batas upload di UI

interface AnalyzeBody {
  input?: string;
  filename?: string;
}

export async function POST(req: Request) {
  let body: AnalyzeBody;
  try {
    body = (await req.json()) as AnalyzeBody;
  } catch {
    return Response.json({ ok: false, error: "Body request tidak valid (harus JSON)." }, { status: 400 });
  }

  const input = (body.input ?? "").toString();
  if (!input.trim()) {
    return Response.json({ ok: false, error: "Input kosong. Upload file atau paste kode/log dulu." }, { status: 400 });
  }
  if (input.length > MAX_INPUT_CHARS) {
    return Response.json({ ok: false, error: "Input terlalu besar (maks. 10MB)." }, { status: 413 });
  }

  try {
    let report = analyzeSecurityLog(input, body.filename);
    report = await enrichReportWithGroq(report, input);
    return Response.json({ ok: true, report });
  } catch (err) {
    console.error("[maintenance-log/analyze] error:", err);
    return Response.json({ ok: false, error: "Gagal menganalisis input." }, { status: 500 });
  }
}
