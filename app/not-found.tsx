import Link from "next/link";
import { Button } from "@/components/ui/button";

export default function NotFound() {
  return (
    <div className="flex flex-1 flex-col items-center justify-center gap-4 px-6 text-center">
      <span className="rounded-full border border-sev-critical/40 bg-sev-critical/10 px-3 py-1 text-[11px] uppercase tracking-widest text-sev-critical">
        404 — not found
      </span>
      <h1 className="text-lg font-semibold text-foreground">
        Halaman atau scan ID ini tidak ditemukan
      </h1>
      <p className="max-w-sm text-xs text-muted leading-relaxed">
        Scan mungkin sudah kedaluwarsa (data disimpan sementara di memory,
        otomatis dibersihkan 30 menit setelah dibuat) atau ID salah ketik.
      </p>
      <Link href="/">
        <Button variant="outline" size="sm">
          ← kembali ke beranda
        </Button>
      </Link>
    </div>
  );
}
