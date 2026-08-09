export function LoadingSkeleton() {
  return (
    <div className="space-y-4 animate-pulse">
      <div className="grid grid-cols-3 gap-3">
        {[0, 1, 2].map((i) => (
          <div key={i} className="h-20 rounded-2xl border border-border bg-surface-raised" />
        ))}
      </div>
      {[0, 1, 2].map((i) => (
        <div key={i} className="h-24 rounded-2xl border border-border bg-surface-raised" />
      ))}
    </div>
  );
}
