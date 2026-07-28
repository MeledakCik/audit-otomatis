import { cn } from "@/lib/utils";

export function Card({
  className,
  children,
  style,
}: {
  className?: string;
  children: React.ReactNode;
  style?: React.CSSProperties;
}) {
  return (
    <div
      className={cn(
        "rounded-2xl border border-border bg-surface shadow-[0_12px_32px_-16px_rgba(0,0,0,0.5)] overflow-hidden",
        className
      )}
      style={style}
    >
      {children}
    </div>
  );
}

export function CardHeader({ className, children }: { className?: string; children: React.ReactNode }) {
  return (
    <div
      className={cn(
        "border-b border-border px-4 py-3.5 flex flex-wrap items-center justify-between gap-2",
        className
      )}
    >
      {children}
    </div>
  );
}

export function CardTitle({ className, children }: { className?: string; children: React.ReactNode }) {
  return (
    <h2 className={cn("text-[11px] font-bold uppercase tracking-widest text-muted flex items-center gap-2", className)}>
      {children}
    </h2>
  );
}

export function CardContent({ className, children }: { className?: string; children: React.ReactNode }) {
  return <div className={cn("p-4", className)}>{children}</div>;
}
