"use client";

import { create } from "zustand";
import type { DiscoveredEndpoint, Finding, ScanLogEvent, ScanStatus } from "./types";

interface ScanStreamState {
  scanId: string | null;
  status: ScanStatus | "connecting";
  logs: ScanLogEvent[];
  findings: Finding[];
  endpoints: DiscoveredEndpoint[];
  blockedReason?: string;
  connected: boolean;
  connect: (scanId: string) => void;
  reset: () => void;
}

let currentSource: EventSource | null = null;

export const useScanStream = create<ScanStreamState>((set, get) => ({
  scanId: null,
  status: "connecting",
  logs: [],
  findings: [],
  endpoints: [],
  blockedReason: undefined,
  connected: false,

  connect: (scanId: string) => {
    if (get().scanId === scanId && currentSource) return;

    currentSource?.close();
    set({
      scanId,
      status: "connecting",
      logs: [],
      findings: [],
      endpoints: [],
      blockedReason: undefined,
      connected: false,
    });

    const source = new EventSource(`/api/scan/${scanId}/stream`);
    currentSource = source;

    source.onopen = () => set({ connected: true });

    source.onmessage = (msg) => {
      try {
        const evt: ScanLogEvent = JSON.parse(msg.data);
        set((state) => {
          const next: Partial<ScanStreamState> = {
            logs: [...state.logs, evt],
          };
          if (evt.type === "status" && evt.status) next.status = evt.status;
          if (evt.type === "finding" && evt.finding) {
            next.findings = [...state.findings, evt.finding];
          }
          if (evt.type === "endpoints" && evt.endpoints) {
            next.endpoints = evt.endpoints;
          }
          if (evt.type === "blocked") {
            next.status = "blocked_cloudflare";
            next.blockedReason = evt.message;
          }
          if (evt.type === "done") next.status = "done";
          if (evt.type === "error") next.status = "error";
          return next;
        });
        if (evt.type === "done" || evt.type === "error" || evt.type === "blocked") {
          source.close();
          if (currentSource === source) currentSource = null;
          set({ connected: false });
        }
      } catch {
        // ignore malformed frame
      }
    };

    source.onerror = () => {
      // EventSource will retry automatically; if scan already terminal
      // this is a no-op since we've closed the connection ourselves.
    };
  },

  reset: () => {
    currentSource?.close();
    currentSource = null;
    set({
      scanId: null,
      status: "connecting",
      logs: [],
      findings: [],
      endpoints: [],
      blockedReason: undefined,
      connected: false,
    });
  },
}));
