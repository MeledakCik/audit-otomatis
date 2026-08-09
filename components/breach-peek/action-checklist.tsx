import { KeyRound, ShieldCheck, Fingerprint, Mail } from "lucide-react";

const ACTIONS = [
  {
    icon: KeyRound,
    title: "Reset your password",
    detail: "Use a unique, long passphrase for this account — never reuse it anywhere else.",
  },
  {
    icon: ShieldCheck,
    title: "Enable Two-Factor Authentication (2FA)",
    detail: "An authenticator app (not SMS) blocks most account-takeover attempts even if your password leaks.",
  },
  {
    icon: Fingerprint,
    title: "Check for reused passwords",
    detail: "If this password is used elsewhere, rotate it there too — a password manager makes this painless.",
  },
  {
    icon: Mail,
    title: "Watch for targeted phishing",
    detail: "Leaked data is often used to craft convincing scam emails. Be extra skeptical of unexpected messages.",
  },
];

export function ActionChecklist() {
  return (
    <div className="rounded-2xl border border-border bg-surface shadow-[0_12px_32px_-16px_rgba(0,0,0,0.5)] overflow-hidden">
      <div className="border-b border-border px-4 py-3.5">
        <h2 className="text-[11px] font-bold uppercase tracking-widest text-muted">Recommended Next Steps</h2>
      </div>
      <div className="p-4 grid sm:grid-cols-2 gap-3">
        {ACTIONS.map((a) => (
          <div key={a.title} className="flex gap-3 rounded-xl border border-border-strong bg-surface-raised p-3">
            <div className="h-8 w-8 shrink-0 grid place-items-center rounded-lg bg-gradient-to-br from-[#c084fc] to-[#9333ea] text-white">
              <a.icon className="h-4 w-4" strokeWidth={2.5} />
            </div>
            <div className="space-y-0.5">
              <p className="text-xs font-bold text-foreground">{a.title}</p>
              <p className="text-[11px] text-muted leading-relaxed">{a.detail}</p>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
