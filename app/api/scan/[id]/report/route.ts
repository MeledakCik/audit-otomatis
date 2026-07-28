import { getScan } from "@/lib/scan-store";
import { renderPentestReportHtml } from "@/lib/report-html";

export async function GET(
  req: Request,
  { params }: { params: Promise<{ id: string }> }
) {
  const { id } = await params;
  const scan = getScan(id);

  if (!scan) {
    return new Response("Scan tidak ditemukan.", { status: 404 });
  }

  const url = new URL(req.url);
  const download = url.searchParams.get("download") === "1";
  const filename = `report-${scan.domain}-${scan.id}.html`;

  let html: string;
  try {
    html = renderPentestReportHtml(scan);
  } catch (err) {
    // Sebelumnya kalau render gagal (mis. field finding yang tidak
    // terduga), route ini melempar exception tanpa body -> browser cuma
    // menampilkan iframe kosong/hitam tanpa penjelasan apa pun. Sekarang
    // selalu kembalikan halaman HTML yang jelas menyatakan errornya.
    const message = err instanceof Error ? err.message : String(err);
    return new Response(
      `<!DOCTYPE html><html lang="id"><head><meta charset="utf-8"><title>Gagal membuat report</title>
      <style>body{font-family:ui-monospace,monospace;background:#0b0e14;color:#d6dae3;padding:40px;}
      .box{max-width:640px;margin:0 auto;border:1px solid #7c2d12;background:#2a1509;color:#fdba74;padding:20px 24px;border-radius:8px;}
      code{background:#1c2130;padding:2px 6px;border-radius:3px;}</style></head>
      <body><div class="box"><h1 style="font-size:16px;margin-top:0;">⚠️ Gagal membuat report</h1>
      <p>Terjadi error saat merender laporan untuk scan ini. Coba muat ulang, atau kalau masih gagal, cek log server.</p>
      <p><code>${message.replace(/</g, "&lt;")}</code></p></div></body></html>`,
      { status: 500, headers: { "Content-Type": "text/html; charset=utf-8" } }
    );
  }

  return new Response(html, {
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      ...(download ? { "Content-Disposition": `attachment; filename="${filename}"` } : {}),
    },
  });
}