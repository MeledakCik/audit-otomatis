"use client";

import { create } from "zustand";
import type { QcLogEvent, QcResult, QcStatus } from "./qc-types";

interface QcStreamState {
  qcId: string | null;
  status: QcStatus | "connecting";
  logs: QcLogEvent[];
  result: QcResult;
  errorMessage?: string;
  connected: boolean;
  connect: (qcId: string) => void;
  reset: () => void;
}

let currentSource: EventSource | null = null;

export const useQcStream = create<QcStreamState>((set, get) => ({
  qcId: null,
  status: "connecting",
  logs: [],
  result: {},
  errorMessage: undefined,
  connected: false,

  connect: (qcId: string) => {
    if (get().qcId === qcId && currentSource) return;

    currentSource?.close();
    set({
      qcId,
      status: "connecting",
      logs: [],
      result: {},
      errorMessage: undefined,
      connected: false,
    });

    const source = new EventSource(`/api/qc/${qcId}/stream`);
    currentSource = source;

    source.onopen = () => set({ connected: true });

    source.onmessage = (msg) => {
      try {
        const evt: QcLogEvent = JSON.parse(msg.data);
        set((state) => {
          const next: Partial<QcStreamState> = { logs: [...state.logs, evt] };
          if (evt.type === "status" && evt.status) next.status = evt.status;
          if (evt.type === "done") next.status = "done";
          if (evt.type === "error") {
            next.status = "error";
            next.errorMessage = evt.message;
          }
          return next;
        });

        // Modul selesai / QC selesai -> ambil ulang hasil lengkap dari
        // /api/qc/[id] (SSE cuma bawa notifikasi, bukan payload besar).
        if (evt.type === "module_done" || evt.type === "done") {
          fetch(`/api/qc/${qcId}`)
            .then((r) => (r.ok ? r.json() : null))
            .then((data) => {
              if (data?.result) set({ result: data.result });
            })
            .catch(() => {});
        }

        if (evt.type === "done" || evt.type === "error") {
          source.close();
          if (currentSource === source) currentSource = null;
          set({ connected: false });
        }
      } catch {
        // ignore malformed frame
      }
    };

    source.onerror = () => {
      // EventSource retries automatically.
    };
  },

  reset: () => {
    currentSource?.close();
    currentSource = null;
    set({
      qcId: null,
      status: "connecting",
      logs: [],
      result: {},
      errorMessage: undefined,
      connected: false,
    });
  },
}));
