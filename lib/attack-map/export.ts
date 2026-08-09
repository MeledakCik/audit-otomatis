import type { AttackMapReport } from "./types";
import { toPng } from "html-to-image";

export function downloadAttackMapAsJson(report: AttackMapReport) {
  const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `sentinel-attack-map-${report.hostname}-${report.id}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

/**
 * Export canvas React Flow yang sedang tampil ke PNG, murni di browser
 * (html-to-image) — tidak ada request ke server.
 */
export async function exportMapAsPng(viewportEl: HTMLElement, filename: string) {
  const dataUrl = await toPng(viewportEl, {
    backgroundColor: "#0a0710",
    pixelRatio: 2,
  });
  const a = document.createElement("a");
  a.href = dataUrl;
  a.download = filename;
  a.click();
}

