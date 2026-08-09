import { Suspense } from "react";
import { StackFingerprintView } from "@/components/stack-fingerprint/stack-fingerprint-view";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "Tech Stack Fingerprint",
  description: "Deteksi tech stack dari homepage secara pasif — header + HTML marker publik saja, untuk asset inventory edukatif.",
};

export default function StackFingerprintPage() {
  return (
    <Suspense fallback={null}>
      <StackFingerprintView />
    </Suspense>
  );
}
