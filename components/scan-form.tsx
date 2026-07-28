"use client";
import { useActionState, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { startScanAction, type StartScanResult } from "@/lib/actions";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";

const initialState: StartScanResult = { ok: false };

export function ScanForm() {
  const router = useRouter();
  const [checked, setChecked] = useState(false);
  const [state, formAction, pending] = useActionState(
    (_p: StartScanResult, fd: FormData) => startScanAction(fd),
    initialState,
  );
  useEffect(() => {
    if (state.ok && state.scanId) router.push(`/scan/${state.scanId}`);
  }, [state, router]);

  return (
    <form action={formAction} className="flex flex-col gap-4">
      <Input
        name="domain"
        placeholder="example.com"
        className="h-10 bg-background"
        required
        disabled={pending}
      />
      <input type="hidden" name="permission" value={checked ? "on" : ""} />

      <label className="flex items-start gap-2.5 cursor-pointer group">
        <Checkbox
          checked={checked}
          onCheckedChange={(v) => setChecked(v === true)}
          className="mt-0.5"
        />
        <span className="text-xs leading-relaxed text-muted group-hover:text-foreground">
          I have authorization to audit this domain.
        </span>
      </label>

      {state.error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-2 text-xs text-red-400">
          {state.error}
        </div>
      )}

      <Button
        disabled={pending || !checked}
        className="w-full h-10 bg-[#a855f7] hover:bg-[#9333ea] text-white font-medium rounded-xl shadow-[0_0_20px_-6px_#a855f7]"
      >
        {pending ? "PREPARING..." : "START AUDIT →"}
      </Button>

      <p className="text-sm text-center text-muted-dim">
        Passive-only: GET-only, No 100 req/scan.
      </p>
    </form>
  );
}
