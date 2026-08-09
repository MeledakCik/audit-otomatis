import type { AttackMapNode, AttackMapNodeType } from "./types";

const COL_WIDTH = 260;
const ROW_HEIGHT = 84;
const TYPE_ORDER: Record<AttackMapNodeType, number> = {
  ROOT: 0,
  PAGE: 1,
  API: 2,
  FORM: 3,
  EXTERNAL: 4,
  ASSET: 5,
};

export interface PositionedNode extends AttackMapNode {
  x: number;
  y: number;
}

/**
 * Layout kolom sederhana: kolom = node.depth (jarak dari ROOT), urutan
 * vertikal dalam kolom dikelompokkan per tipe supaya rapi dilihat. Tidak
 * pakai dagre/elk — cukup buat graph yang selalu berbentuk pohon dangkal
 * (maxDepth 2 + 1 level anak).
 */
export function layoutAttackMap(nodes: AttackMapNode[]): PositionedNode[] {
  const byDepth = new Map<number, AttackMapNode[]>();
  for (const n of nodes) {
    if (!byDepth.has(n.depth)) byDepth.set(n.depth, []);
    byDepth.get(n.depth)!.push(n);
  }

  const positioned: PositionedNode[] = [];
  const depths = Array.from(byDepth.keys()).sort((a, b) => a - b);

  for (const depth of depths) {
    const group = byDepth.get(depth)!;
    group.sort((a, b) => TYPE_ORDER[a.type] - TYPE_ORDER[b.type] || a.label.localeCompare(b.label));
    const totalHeight = group.length * ROW_HEIGHT;
    const startY = -totalHeight / 2;
    group.forEach((node, i) => {
      positioned.push({
        ...node,
        x: depth * COL_WIDTH,
        y: startY + i * ROW_HEIGHT,
      });
    });
  }

  return positioned;
}
