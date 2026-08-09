import { NODE_COLORS } from "./map-node";
import type { AttackMapNodeType } from "@/lib/attack-map/types";

const LEGEND_ITEMS: { type: AttackMapNodeType; label: string }[] = [
  { type: "ROOT", label: "Root" },
  { type: "API", label: "API" },
  { type: "PAGE", label: "Page" },
  { type: "EXTERNAL", label: "External" },
  { type: "FORM", label: "Form" },
  { type: "ASSET", label: "Asset (JS)" },
];

export function Legend() {
  return (
    <div className="flex flex-wrap items-center gap-3">
      {LEGEND_ITEMS.map((item) => (
        <div key={item.type} className="flex items-center gap-1.5 text-[10px] font-mono text-muted-dim">
          <span
            className="h-2.5 w-2.5 rounded-full shrink-0"
            style={{ background: NODE_COLORS[item.type], boxShadow: `0 0 6px 1px ${NODE_COLORS[item.type]}90` }}
          />
          {item.label}
        </div>
      ))}
    </div>
  );
}
