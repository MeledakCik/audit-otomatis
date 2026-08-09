import { PartyPopper } from "lucide-react";

export function CleanResult({ query }: { query: string }) {
  return (
    <div className="rounded-2xl border border-sev-low/40 bg-sev-low/10 p-8 flex flex-col items-center text-center gap-3">
      <div className="h-14 w-14 grid place-items-center rounded-full bg-sev-low/20 text-sev-low">
        <PartyPopper className="h-7 w-7" />
      </div>
      <h3 className="text-lg font-extrabold text-sev-low tracking-tight">CLEAN — No breaches found</h3>
      <p className="text-xs font-mono text-muted-dim max-w-sm">
        {query} doesn&apos;t appear in any breach XposedOrNot has indexed. Keep it that way with a unique password and 2FA.
      </p>
    </div>
  );
}
