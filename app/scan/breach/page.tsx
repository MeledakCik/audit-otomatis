import { Suspense } from "react";
import { BreachPeekView } from "@/components/breach-peek/breach-peek-view";

export const dynamic = "force-dynamic";

export const metadata = {
  title: "Breach Peek — Free OSINT Breach Checker",
  description: "Check if an email or domain appears in known data breaches. 100% passive, free, no API key required.",
};

export default function BreachPeekPage() {
  return (
    <Suspense fallback={null}>
      <BreachPeekView />
    </Suspense>
  );
}
