"use client";

import dynamic from "next/dynamic";

// @xyflow/react and html-to-image are heavy; load them only on the map page.
const AttackMapView = dynamic(
  () => import("./attack-map-view").then((m) => m.AttackMapView),
  {
    ssr: false,
    loading: () => (
      <div
        role="status"
        aria-live="polite"
        className="p-6 text-sm text-slate-300"
      >
        Memuat peta…
      </div>
    ),
  }
);

export function AttackMapLazy() {
  return <AttackMapView />;
}
