"use client";

import { forwardRef, useImperativeHandle, useMemo, useRef } from "react";
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  BackgroundVariant,
  useReactFlow,
  type Node,
  type Edge,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { mapNodeTypes, NODE_COLORS, type MapNodeData } from "./map-node";
import { layoutAttackMap } from "@/lib/attack-map/layout";
import type { AttackMapEdge, AttackMapNode } from "@/lib/attack-map/types";

const ADMIN_PATH_RE = /\b(admin|dashboard|wp-admin|manage|internal|debug|config|superuser)\b/i;

export interface FlowCanvasHandle {
  getViewportEl: () => HTMLElement | null;
  fitView: () => void;
}

interface FlowCanvasProps {
  nodes: AttackMapNode[];
  edges: AttackMapEdge[];
  onNodeSelect: (node: AttackMapNode) => void;
}

export const FlowCanvas = forwardRef<FlowCanvasHandle, FlowCanvasProps>(function FlowCanvas(
  { nodes, edges, onNodeSelect },
  ref
) {
  const wrapperRef = useRef<HTMLDivElement>(null);
  const { fitView } = useReactFlow();

  useImperativeHandle(ref, () => ({
    getViewportEl: () => wrapperRef.current,
    fitView: () => fitView({ padding: 0.2, duration: 400 }),
  }));

  const flowNodes: Node<MapNodeData>[] = useMemo(() => {
    const positioned = layoutAttackMap(nodes);
    return positioned.map((n) => ({
      id: n.id,
      type: "mapNode",
      position: { x: n.x, y: n.y },
      data: {
        label: n.label,
        nodeType: n.type,
        methods: n.methods,
        isAdminLike: (n.type === "PAGE" || n.type === "API") && ADMIN_PATH_RE.test(n.label),
      },
    }));
  }, [nodes]);

  const flowEdges: Edge[] = useMemo(
    () =>
      edges.map((e) => ({
        id: e.id,
        source: e.source,
        target: e.target,
        animated: !!e.animated,
        style: {
          stroke: e.animated ? NODE_COLORS.API : "#453264",
          strokeWidth: e.animated ? 1.6 : 1.2,
        },
      })),
    [edges]
  );

  const nodeMap = useMemo(() => new Map(nodes.map((n) => [n.id, n])), [nodes]);

  return (
    <div ref={wrapperRef} className="h-full w-full">
      <ReactFlow
        nodes={flowNodes}
        edges={flowEdges}
        nodeTypes={mapNodeTypes}
        onNodeClick={(_, node) => {
          const original = nodeMap.get(node.id);
          if (original) onNodeSelect(original);
        }}
        fitView
        minZoom={0.15}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
        colorMode="dark"
      >
        <Background variant={BackgroundVariant.Dots} color="#2a1842" gap={22} size={1.3} />
        <Controls className="!bg-[#0f0b16] !border !border-white/10 !rounded-lg overflow-hidden" showInteractive={false} />
        <MiniMap
          className="!bg-[#0f0b16] !border !border-white/10 !rounded-lg overflow-hidden"
          maskColor="rgba(10,7,16,0.75)"
          nodeColor={(n) => NODE_COLORS[(n.data as MapNodeData).nodeType] ?? "#c084fc"}
        />
      </ReactFlow>
    </div>
  );
});
