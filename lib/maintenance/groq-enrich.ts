import type { SecurityReport } from "./types";

const GROQ_MODEL = "llama-3.3-70b-versatile";

const SYSTEM_PROMPT = `You are Sentinel-ID, a senior SOC analyst. You will be given a preliminary
static-analysis security report (JSON) plus the raw input it was derived from. Refine and enrich
the executive summary and the "attackVector" / "prevention" text for the findings so they read like
a human senior analyst wrote them — clear, specific, in Bahasa Indonesia. Do NOT invent findings that
aren't backed by the input. Return ONLY valid JSON matching this shape, nothing else, no markdown fences:
{ "summary": string, "findings": [ { "id": string, "attackVector": string, "prevention": string } ] }`;

/**
 * Enriches a static-analysis SecurityReport with an LLM pass via Groq, if
 * GROQ_API_KEY is configured. This is best-effort: any failure (missing key,
 * network error, bad JSON back) silently falls back to the original report
 * so the feature keeps working without an AI key configured.
 */
export async function enrichReportWithGroq(report: SecurityReport, rawInput: string): Promise<SecurityReport> {
  const apiKey = process.env.GROQ_API_KEY;
  if (!apiKey || report.findings.length === 0) return report;

  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 15_000);

    const res = await fetch("https://api.groq.com/openai/v1/chat/completions", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${apiKey}`,
      },
      body: JSON.stringify({
        model: GROQ_MODEL,
        temperature: 0.2,
        max_tokens: 2000,
        messages: [
          { role: "system", content: SYSTEM_PROMPT },
          {
            role: "user",
            content: JSON.stringify({
              preliminaryReport: {
                summary: report.summary,
                findings: report.findings.map((f) => ({
                  id: f.id,
                  title: f.title,
                  severity: f.severity,
                  vulnerabilityType: f.vulnerabilityType,
                  leakLocation: f.leakLocation,
                })),
              },
              rawInputExcerpt: rawInput.slice(0, 4000),
            }),
          },
        ],
      }),
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!res.ok) return report;

    const data = (await res.json()) as {
      choices?: { message?: { content?: string } }[];
    };
    const text = data.choices?.[0]?.message?.content;
    if (!text) return report;

    const cleaned = text.replace(/```json|```/g, "").trim();
    const parsed = JSON.parse(cleaned) as {
      summary?: string;
      findings?: { id: string; attackVector?: string; prevention?: string }[];
    };

    const byId = new Map((parsed.findings ?? []).map((f) => [f.id, f]));

    return {
      ...report,
      summary: parsed.summary || report.summary,
      aiEnriched: true,
      findings: report.findings.map((f) => {
        const enriched = byId.get(f.id);
        if (!enriched) return f;
        return {
          ...f,
          attackVector: enriched.attackVector || f.attackVector,
          prevention: enriched.prevention || f.prevention,
        };
      }),
    };
  } catch {
    // Groq tidak tersedia / timeout / respons tidak valid -> tetap pakai hasil static analysis.
    return report;
  }
}
