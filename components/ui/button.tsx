import * as React from "react";
import { Slot } from "@radix-ui/react-slot";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const buttonVariants = cva(
  "inline-flex items-center justify-center gap-2 whitespace-nowrap rounded-full text-xs font-semibold tracking-wide uppercase transition-all duration-150 ease-out disabled:pointer-events-none disabled:opacity-40 border focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/60 active:scale-[0.97]",
  {
    variants: {
      variant: {
        primary:
          "bg-gradient-accent text-accent-fg border-transparent shadow-[0_0_20px_-4px_var(--accent)] hover:shadow-[0_0_28px_-2px_var(--accent)] hover:brightness-110",
        outline:
          "bg-transparent text-foreground border-border-strong hover:border-accent hover:text-accent hover:shadow-[0_0_16px_-6px_var(--accent)]",
        ghost:
          "bg-transparent text-muted border-transparent hover:text-foreground hover:bg-surface-raised",
        danger:
          "bg-transparent text-sev-critical border-sev-critical/40 hover:bg-sev-critical/10",
      },
      size: {
        sm: "h-7 px-3 text-[11px]",
        md: "h-9 px-4",
        lg: "h-11 px-6 text-sm",
      },
    },
    defaultVariants: { variant: "primary", size: "md" },
  }
);

export interface ButtonProps
  extends React.ButtonHTMLAttributes<HTMLButtonElement>,
    VariantProps<typeof buttonVariants> {
  asChild?: boolean;
}

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant, size, asChild = false, ...props }, ref) => {
    const Comp = asChild ? Slot : "button";
    return (
      <Comp
        ref={ref}
        className={cn(buttonVariants({ variant, size, className }))}
        {...props}
      />
    );
  }
);
Button.displayName = "Button";

export { Button, buttonVariants };
