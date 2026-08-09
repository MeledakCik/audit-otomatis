"use client";

import { useState } from "react";
import { Mail, Globe, Search, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { cn } from "@/lib/utils";
import type { ScanMode } from "@/lib/breach-check/types";

const QUICK_DOMAINS = ["gmail.com", "yahoo.com", "outlook.com", "example.com"];

export function InputPanel({
  onScanEmail,
  onScanDomain,
  loading,
  liveStatus,
}: {
  onScanEmail: (email: string) => void;
  onScanDomain: (domain: string) => void;
  loading: boolean;
  liveStatus: string | null;
}) {
  const [mode, setMode] = useState<ScanMode>("email");
  const [emailValue, setEmailValue] = useState("");
  const [domainValue, setDomainValue] = useState("");

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (loading) return;
    if (mode === "email") {
      const trimmed = emailValue.trim();
      if (trimmed) onScanEmail(trimmed);
    } else {
      const trimmed = domainValue.trim();
      if (trimmed) onScanDomain(trimmed);
    }
  }

  return (
    <div className="rounded-2xl border border-border bg-surface shadow-[0_12px_32px_-16px_rgba(0,0,0,0.5)] p-4 space-y-4">
      <div className="flex rounded-xl border border-border-strong bg-surface-raised p-1">
        <ModeTab active={mode === "email"} onClick={() => setMode("email")} icon={Mail} label="Email" />
        <ModeTab active={mode === "domain"} onClick={() => setMode("domain")} icon={Globe} label="Domain" />
      </div>

      <form onSubmit={handleSubmit} className="space-y-3">
        {mode === "email" ? (
          <Input
            type="email"
            placeholder="admin@yourdomain.com"
            value={emailValue}
            onChange={(e) => setEmailValue(e.target.value)}
            disabled={loading}
          />
        ) : (
          <div className="space-y-2">
            <Input
              type="text"
              placeholder="yourdomain.com"
              value={domainValue}
              onChange={(e) => setDomainValue(e.target.value)}
              disabled={loading}
            />
            <div className="flex flex-wrap gap-1.5">
              {QUICK_DOMAINS.map((d) => (
                <button
                  key={d}
                  type="button"
                  onClick={() => setDomainValue(d)}
                  disabled={loading}
                  className="rounded-full border border-border-strong px-2.5 py-1 text-[10px] font-mono text-muted hover:border-accent hover:text-accent transition-colors disabled:opacity-40"
                >
                  {d}
                </button>
              ))}
            </div>
            <p className="text-[10px] font-mono text-muted-dim">
              Checks 5 common addresses: admin@, info@, contact@, support@, hello@
            </p>
          </div>
        )}

        <Button type="submit" variant="primary" size="md" className="w-full" disabled={loading}>
          {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Search className="h-3.5 w-3.5" />}
          {loading ? "Scanning..." : "Scan for Breaches"}
        </Button>
      </form>

      {liveStatus && <p className="text-[11px] font-mono text-muted-dim animate-pulse">{liveStatus}</p>}
    </div>
  );
}

function ModeTab({
  active,
  onClick,
  icon: Icon,
  label,
}: {
  active: boolean;
  onClick: () => void;
  icon: typeof Mail;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={cn(
        "flex-1 flex items-center justify-center gap-1.5 rounded-lg py-1.5 text-xs font-semibold tracking-wide transition-colors",
        active ? "bg-gradient-accent text-accent-fg shadow-[0_0_16px_-4px_var(--accent)]" : "text-muted hover:text-foreground"
      )}
    >
      <Icon className="h-3.5 w-3.5" />
      {label}
    </button>
  );
}
