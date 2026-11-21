import { createHash, randomBytes } from "node:crypto";
import { NextResponse } from "next/server";
import { guardAdmin, noStore } from "@/lib/sentinel/admin-auth";
import { isAdminAuditOrigin } from "@/lib/sentinel/authorized-targets";
import { getScan } from "@/lib/scan-store";
import { clientIp, rateLimit } from "@/lib/sentinel/redis";
import { normalizeUploadEndpoint, testFileUpload } from "@/lib/sentinel/domain-check";
import { SsrfBlockedError } from "@/lib/ssrf-guard";

export const runtime = "nodejs";
export const maxDuration = 15;

const MAX_REQUEST_BYTES = 48 * 1024;
const MAX_FILE_BYTES = 32 * 1024;

async function readRequestBody(req: Request) {
  const length = Number(req.headers.get("content-length"));
  if (Number.isFinite(length) && length > MAX_REQUEST_BYTES) throw new Error("LARGE_REQUEST");
  if (!req.body) throw new Error("EMPTY_REQUEST");

  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_REQUEST_BYTES) {
        await reader.cancel();
        throw new Error("LARGE_REQUEST");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  return Buffer.concat(chunks, total);
}

export async function POST(req: Request) {
  const denied = await guardAdmin(req);
  if (denied) return denied;

  if (!/^multipart\/form-data\s*;/i.test(req.headers.get("content-type") ?? "")) {
    return NextResponse.json({ error: "Pilih file teks .txt untuk diuji." }, { status: 415, headers: noStore });
  }

  let form: FormData;
  try {
    const body = await readRequestBody(req);
    form = await new Request(req.url, {
      method: "POST",
      headers: { "content-type": req.headers.get("content-type")! },
      body,
    }).formData();
  } catch (error) {
    const tooLarge = error instanceof Error && error.message === "LARGE_REQUEST";
    return NextResponse.json(
      { error: tooLarge ? "Ukuran request melebihi batas 48 KB." : "Form upload tidak valid." },
      { status: tooLarge ? 413 : 400, headers: noStore },
    );
  }

  const scanId = form.get("scanId");
  const endpointInput = form.get("endpoint");
  const file = form.get("file");
  if (typeof scanId !== "string" || !/^[A-Za-z0-9_-]{6,32}$/.test(scanId) || typeof endpointInput !== "string") {
    return NextResponse.json({ error: "Scan ID atau endpoint tidak valid." }, { status: 400, headers: noStore });
  }
  const scan = await getScan(scanId);
  if (!scan || !scan.adminOnly || !isAdminAuditOrigin(scan.origin)) {
    return NextResponse.json({ error: "Audit admin tidak ditemukan atau tidak valid." }, { status: 404, headers: noStore });
  }
  const domain = new URL(scan.origin).hostname;
  const endpoint = normalizeUploadEndpoint(domain, endpointInput);
  const discovered = endpoint && scan.endpoints.find((item) =>
    item.method === "POST" && item.url === endpoint.href && item.fileFields?.length,
  );
  const uploadFinding = scan.findings.some((finding) => finding.category === "php-upload");
  if (!endpoint || !discovered || !uploadFinding) {
    return NextResponse.json({ error: "POST hanya tersedia setelah audit menemukan form upload pada target yang sama." }, { status: 409, headers: noStore });
  }
  const fieldName = discovered.fileFields?.find((name) => /^[A-Za-z][A-Za-z0-9_.-]{0,63}$/.test(name));
  if (!fieldName) {
    return NextResponse.json({ error: "Nama field file dari form target tidak aman untuk diuji." }, { status: 409, headers: noStore });
  }
  if (!(file instanceof File) || file.size === 0 || file.size > MAX_FILE_BYTES) {
    return NextResponse.json({ error: "Pilih file .txt berisi teks dengan ukuran 1 byte hingga 32 KB." }, { status: 400, headers: noStore });
  }
  const filename = file.name;
  if (!/^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}\.txt$/i.test(filename) || filename.includes("..")) {
    return NextResponse.json({ error: "Nama file harus sederhana dan berakhiran .txt." }, { status: 400, headers: noStore });
  }
  if (file.type && file.type !== "text/plain") {
    return NextResponse.json({ error: "Sampel yang didukung berformat teks biasa (.txt)." }, { status: 415, headers: noStore });
  }

  const contents = Buffer.from(await file.arrayBuffer());
  try {
    const decoded = new TextDecoder("utf-8", { fatal: true }).decode(contents);
    if (/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/.test(decoded)) throw new Error();
  } catch {
    return NextResponse.json({ error: "Sampel harus berisi teks UTF-8 tanpa karakter kontrol." }, { status: 415, headers: noStore });
  }

  if (!(await rateLimit("admin-upload-test", clientIp(req), 2, 60))) {
    return NextResponse.json({ error: "Batas uji tercapai. Coba lagi dalam satu menit." }, { status: 429, headers: noStore });
  }

  const timeout = AbortSignal.timeout(8000);
  try {
    const uploadFilename = `sentinel-test-${randomBytes(6).toString("hex")}-${filename}`;
    const result = await testFileUpload({
      domain,
      endpoint,
      fieldName,
      filename: uploadFilename,
      file: contents,
      signal: AbortSignal.any([timeout, req.signal]),
    });
    return NextResponse.json({
      ...result,
      file: {
        name: uploadFilename,
        originalName: filename,
        size: contents.length,
        sha256: createHash("sha256").update(contents).digest("hex"),
      },
    }, { headers: noStore });
  } catch (error) {
    if (error instanceof SsrfBlockedError) {
      return NextResponse.json({ error: "Target harus mengarah ke alamat publik." }, { status: 422, headers: noStore });
    }
    if (timeout.aborted) {
      return NextResponse.json({ error: "Endpoint upload tidak merespons dalam 8 detik." }, { status: 504, headers: noStore });
    }
    return NextResponse.json({ error: "Gagal membuat koneksi HTTPS ke endpoint upload." }, { status: 502, headers: noStore });
  }
}
