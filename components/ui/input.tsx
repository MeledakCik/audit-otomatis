import * as React from "react";
import { cn } from "@/lib/utils";

const Input = React.forwardRef<HTMLInputElement, React.ComponentProps<"input">>(
  ({ className, ...props }, ref) => {
    return (
      <input
        ref={ref}
        className={cn(
          "flex h-11 w-full rounded-xl border border-border-strong bg-surface-raised px-3.5 text-sm text-foreground placeholder:text-muted-dim focus-visible:outline-none focus-visible:border-accent focus-visible:shadow-[0_0_0_3px_color-mix(in_srgb,var(--accent)_25%,transparent)] disabled:cursor-not-allowed disabled:opacity-40",
          className
        )}
        {...props}
      />
    );
  }
);
Input.displayName = "Input";

export { Input };
