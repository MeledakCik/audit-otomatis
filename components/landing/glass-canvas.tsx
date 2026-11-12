"use client";

import { useEffect, useRef } from "react";

type Particle = { x: number; y: number; vx: number; vy: number; r: number };
type NavigatorHints = Navigator & {
  deviceMemory?: number;
  connection?: { saveData?: boolean };
};

/**
 * Latar canvas ringan:
 * - jumlah partikel & FPS menyesuaikan perangkat (core CPU, RAM, layar, Save-Data)
 * - DPR dibatasi, tanpa filter blur / gradient besar per frame
 * - berhenti saat tab tersembunyi atau canvas keluar layar
 * - statis jika pengguna memilih reduced-motion
 * - menandai <html data-perf="low"> agar blur kaca di CSS ikut dimatikan
 */
export function GlassCanvas({ className = "" }: { className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const nav = navigator as NavigatorHints;
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const cores = nav.hardwareConcurrency ?? 4;
    const mem = nav.deviceMemory ?? 4;
    const saveData = nav.connection?.saveData === true;
    const small = window.innerWidth < 640;
    const low = saveData || cores <= 4 || mem <= 4 || small;

    const root = document.documentElement;
    if (low) root.dataset.perf = "low";

    const cfg = low
      ? { count: 22, fps: 24, links: true, linkDist: 90, dprMax: 1 }
      : { count: 46, fps: 36, links: true, linkDist: 120, dprMax: 1.5 };

    let w = 0;
    let h = 0;
    let dpr = 1;
    let particles: Particle[] = [];
    let colorA = "#ec4899";
    let colorB = "#8b5cf6";
    let raf = 0;
    let last = 0;
    let visible = true;

    const readColors = () => {
      const cs = getComputedStyle(root);
      colorA = cs.getPropertyValue("--accent").trim() || colorA;
      colorB = cs.getPropertyValue("--accent-2").trim() || colorB;
    };

    const seed = () => {
      const n = Math.round(cfg.count * Math.min(1, (w * h) / (1280 * 720)) + 8);
      particles = Array.from({ length: n }, () => ({
        x: Math.random() * w,
        y: Math.random() * h,
        vx: (Math.random() - 0.5) * 0.25,
        vy: (Math.random() - 0.5) * 0.25,
        r: 1 + Math.random() * 1.6,
      }));
    };

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      w = Math.max(1, rect.width);
      h = Math.max(1, rect.height);
      dpr = Math.min(window.devicePixelRatio || 1, cfg.dprMax);
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      seed();
      draw(false);
    };

    function draw(step: boolean) {
      ctx!.clearRect(0, 0, w, h);
      const d2 = cfg.linkDist * cfg.linkDist;

      if (step) {
        for (const p of particles) {
          p.x += p.vx;
          p.y += p.vy;
          if (p.x < -10) p.x = w + 10;
          else if (p.x > w + 10) p.x = -10;
          if (p.y < -10) p.y = h + 10;
          else if (p.y > h + 10) p.y = -10;
        }
      }

      if (cfg.links) {
        ctx!.lineWidth = 1;
        ctx!.strokeStyle = colorB;
        for (let i = 0; i < particles.length; i++) {
          const a = particles[i];
          for (let j = i + 1; j < particles.length; j++) {
            const b = particles[j];
            const dx = a.x - b.x;
            const dy = a.y - b.y;
            const dist = dx * dx + dy * dy;
            if (dist < d2) {
              ctx!.globalAlpha = (1 - dist / d2) * 0.35;
              ctx!.beginPath();
              ctx!.moveTo(a.x, a.y);
              ctx!.lineTo(b.x, b.y);
              ctx!.stroke();
            }
          }
        }
      }

      ctx!.globalAlpha = 0.75;
      ctx!.fillStyle = colorA;
      for (const p of particles) {
        ctx!.beginPath();
        ctx!.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx!.fill();
      }
      ctx!.globalAlpha = 1;
    }

    const loop = (t: number) => {
      raf = requestAnimationFrame(loop);
      if (!visible || document.hidden) return;
      if (t - last < 1000 / cfg.fps) return;
      last = t;
      draw(true);
    };

    readColors();
    resize();
    if (!reduce) raf = requestAnimationFrame(loop);

    const ro = new ResizeObserver(resize);
    ro.observe(canvas);
    const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting; });
    io.observe(canvas);
    const mo = new MutationObserver(() => { readColors(); draw(false); });
    mo.observe(root, { attributes: true, attributeFilter: ["class"] });

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      io.disconnect();
      mo.disconnect();
    };
  }, []);

  return <canvas ref={ref} aria-hidden className={`pointer-events-none ${className}`} />;
}
