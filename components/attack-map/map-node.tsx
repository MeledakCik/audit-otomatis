import { memo } from "react";
import { Handle, Position, type NodeProps } from "@xyflow/react";
import { Globe, FileText, Zap, ListChecks, ExternalLink, FileCode2 } from "lucide-react";
import type { AttackMapNodeType } from "@/lib/attack-map/types";

export const NODE_COLORS: Record<AttackMapNodeType, string> = {
  ROOT: "#c084fc",
  API: "#ff4d6d",
  PAGE: "#38bdf8",
  EXTERNAL: "#9ca3af",
  FORM: "#e93ee8",
  ASSET: "#2dd4bf",
};

const NODE_ICONS: Record<AttackMapNodeType, typeof Globe> = {
  ROOT: Globe,
  PAGE: FileText,
  API: Zap,
  FORM: ListChecks,
  EXTERNAL: ExternalLink,
  ASSET: FileCode2,
};

export interface MapNodeData extends Record<string, unknown> {
  label: string;
  nodeType: AttackMapNodeType;
  methods?: string[];
  isAdminLike?: boolean;
}

function MapNodeInner({ data }: NodeProps) {
  const d = data as MapNodeData;
  const color = NODE_COLORS[d.nodeType];
  const Icon = NODE_ICONS[d.nodeType];
  const isRoot = d.nodeType === "ROOT";

  return (
    <div
      className="group flex items-center gap-2 rounded-xl border px-3 py-2 font-mono text-[11px] cursor-pointer transition-transform hover:scale-[1.03]"
      style={{
        borderColor: `${color}66`,
        background: `linear-gradient(135deg, ${color}1f, #0f0b16)`,
        boxShadow: `0 0 16px -4px ${color}90, inset 0 0 0 1px ${color}22`,
        minWidth: isRoot ? 140 : 170,
        maxWidth: 220,
      }}
    >
      <Handle type="target" position={Position.Left} style={{ background: color, border: "none", width: 6, height: 6 }} />
      <Icon className="h-3.5 w-3.5 shrink-0" style={{ color }} />
      <div className="min-w-0 flex-1">
        <div className="truncate font-semibold" style={{ color }} title={d.label}>
          {d.label}
        </div>
        {d.methods && d.methods.length > 0 && (
          <div className="truncate text-[9px] text-white/50">{d.methods.join(" · ")}</div>
        )}
        {d.isAdminLike && <div className="text-[9px] text-sev-critical font-bold uppercase tracking-wide">⚠ admin-like</div>}
      </div>
      <Handle type="source" position={Position.Right} style={{ background: color, border: "none", width: 6, height: 6 }} />
    </div>
  );
}

export const MapNode = memo(MapNodeInner);

export const mapNodeTypes = { mapNode: MapNode };
