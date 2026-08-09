import { Suspense } from "react";
import { SecretHunterView } from "@/components/secret-hunter/secret-hunter-view";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "JS Secret Hunter",
  description: "Cari credential/secret ter-hardcode di JS same-origin secara pasif — GET-only, tanpa verifikasi value.",
};

export default function SecretHunterPage() {
  return (
    <Suspense fallback={null}>
      <SecretHunterView />
    </Suspense>
  );
}
