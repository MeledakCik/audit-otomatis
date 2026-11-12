"use client";

import { useEffect, useRef } from "react";

type Particle = {
  x: number; y: number;
  vx: number; vy: number;
  r: number;
  hue: number;      // 0..1 → untuk warna interpolasi A↔B
  color: string;    // cache string rgb()
};

type NavigatorHints = Navigator & {
  deviceMemory?: number;
  connection?: { saveData?: boolean; effectiveType?: string };
};

type Tier = "ultra" | "high" | "medium" | "low";

const CONFIG: Record<Tier, {
  count: number;
  fps: number;          // 0 = uncapped (ikut refresh rate)
  dprMax: number;
  linkDist: number;
  glow: boolean;
  links: boolean;
  mouse: boolean;
  linkBatches: number;
  trails: boolean;
}> = {
  ultra:  { count: 100, fps: 0,   dprMax: 2.5, linkDist: 150, glow: true,  links: true, mouse: true,  linkBatches: 14, trails: true  },
  high:   { count: 68,  fps: 60,  dprMax: 2,   linkDist: 135, glow: true,  links: true, mouse: true,  linkBatches: 10, trails: false },
  medium: { count: 40,  fps: 45,  dprMax: 1.5, linkDist: 115, glow: false, links: true, mouse: false, linkBatches: 8,  trails: false },
  low:    { count: 24,  fps: 30,  dprMax: 1,   linkDist: 95,  glow: false, links: true, mouse: false, linkBatches: 6,  trails: false },
};

export function GlassCanvas({ className = "" }: { className?: string }) {
  const ref = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = ref.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d", { alpha: true, desynchronized: true });
    if (!ctx) return;

    const nav = navigator as NavigatorHints;
    const root = document.documentElement;
    const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const hasHover = window.matchMedia("(hover: hover)").matches;

    // ---------- Tier detection (sekali) ----------
    const cores = nav.hardwareConcurrency ?? 4;
    const mem   = nav.deviceMemory ?? 4;
    const saveData = nav.connection?.saveData === true;
    const small = window.innerWidth < 640;
    const dpr0 = window.devicePixelRatio || 1;

    let tier: Tier;
    if (saveData || cores <= 2 || mem <= 2) {
      tier = "low";
    } else if (small || cores <= 4 || mem <= 4) {
      tier = "medium";
    } else if (cores >= 8 && mem >= 8 && (dpr0 >= 1.5 || window.innerWidth >= 1920)) {
      tier = "ultra";
    } else {
      tier = "high";
    }

    const cfg = CONFIG[tier];
    const mouseEnabled = cfg.mouse && hasHover;
    root.dataset.perf = tier;

    // ---------- State ----------
    let w = 0, h = 0, scale = 1;
    let particles: Particle[] = [];
    let colorA = "#ec4899", colorB = "#8b5cf6";
    let colorARGB: [number, number, number] = [236, 72, 153];
    let colorBRGB: [number, number, number] = [139, 92, 246];
    let isDark = root.classList.contains("dark");
    let raf = 0;
    let last = 0;
    let visible = true;
    const mouse = { x: -9999, y: -9999, active: false };

    // ---------- Utils warna ----------
    const parseColor = (s: string): [number, number, number] | null => {
      s = s.trim();
      if (s.startsWith("#")) {
        if (s.length === 4) return [parseInt(s[1]+s[1],16), parseInt(s[2]+s[2],16), parseInt(s[3]+s[3],16)];
        if (s.length === 7) return [parseInt(s.slice(1,3),16), parseInt(s.slice(3,5),16), parseInt(s.slice(5,7),16)];
      }
      const m = s.match(/rgba?\(\s*([\d.]+)[,\s]+([\d.]+)[,\s]+([\d.]+)/);
      if (m) return [parseFloat(m[1]), parseFloat(m[2]), parseFloat(m[3])];
      return null;
    };
    const mixRGB = (a: [number,number,number], b: [number,number,number], t: number) =>
      `rgb(${Math.round(a[0]+(b[0]-a[0])*t)},${Math.round(a[1]+(b[1]-a[1])*t)},${Math.round(a[2]+(b[2]-a[2])*t)})`;

    // ---------- Offscreen glow sprites (tinted A & B) ----------
    const SR = 16; // sprite radius (px)
    const spriteA = document.createElement("canvas");
    const spriteB = document.createElement("canvas");
    let spritesReady = false;

    const buildSprites = () => {
      const size = SR * 2;
      spriteA.width = spriteB.width = size;
      spriteA.height = spriteB.height = size;

      const tmp = document.createElement("canvas");
      tmp.width = tmp.height = size;
      const tctx = tmp.getContext("2d")!;
      const g = tctx.createRadialGradient(SR, SR, 0, SR, SR, SR);
      g.addColorStop(0,   "rgba(255,255,255,1)");
      g.addColorStop(0.35,"rgba(255,255,255,0.55)");
      g.addColorStop(1,   "rgba(255,255,255,0)");
      tctx.fillStyle = g;
      tctx.fillRect(0, 0, size, size);

      const tint = (dst: HTMLCanvasElement, color: string) => {
        const c = dst.getContext("2d")!;
        c.clearRect(0, 0, size, size);
        c.fillStyle = color;
        c.fillRect(0, 0, size, size);
        c.globalCompositeOperation = "destination-in";
        c.drawImage(tmp, 0, 0);
        c.globalCompositeOperation = "source-over";
      };
      tint(spriteA, colorA);
      tint(spriteB, colorB);
      spritesReady = true;
    };

    const readColors = () => {
      const cs = getComputedStyle(root);
      colorA = cs.getPropertyValue("--accent").trim() || colorA;
      colorB = cs.getPropertyValue("--accent-2").trim() || colorB;
      const a = parseColor(colorA);
      const b = parseColor(colorB);
      if (a) colorARGB = a;
      if (b) colorBRGB = b;
      isDark = root.classList.contains("dark");
      buildSprites();
      for (const p of particles) p.color = mixRGB(colorARGB, colorBRGB, p.hue);
    };

    // ---------- Seed & resize ----------
    const seed = () => {
      const area = w * h;
      const n = Math.max(12, Math.round(cfg.count * Math.min(1, area / (1440 * 900))));
      particles = Array.from({ length: n }, () => {
        const ang = Math.random() * Math.PI * 2;
        const sp  = 0.08 + Math.random() * 0.22;
        const hue = Math.random();
        return {
          x: Math.random() * w,
          y: Math.random() * h,
          vx: Math.cos(ang) * sp,
          vy: Math.sin(ang) * sp,
          r: 1.2 + Math.random() * 2,
          hue,
          color: mixRGB(colorARGB, colorBRGB, hue),
        };
      });
    };

    const resize = () => {
      const rect = canvas.getBoundingClientRect();
      w = Math.max(1, rect.width);
      h = Math.max(1, rect.height);

      let s = Math.min(window.devicePixelRatio || 1, cfg.dprMax);
      // Cap render di ~16 MP supaya aman di monitor raksasa / 4K+DPR tinggi
      const MAX_PIX = 16_000_000;
      if (w * h * s * s > MAX_PIX) s = Math.sqrt(MAX_PIX / (w * h));
      scale = s;

      canvas.width  = Math.floor(w * scale);
      canvas.height = Math.floor(h * scale);
      ctx.setTransform(scale, 0, 0, scale, 0, 0);
      seed();
      draw(0, false);
    };

    // ---------- Spatial grid (dibersihkan & diisi tiap frame) ----------
    const grid = new Map<number, number[]>();
    const GKEY = (cx: number, cy: number) => (cx + 2000) * 8192 + (cy + 2000);

    const buildGrid = () => {
      grid.clear();
      const cs = cfg.linkDist;
      for (let i = 0; i < particles.length; i++) {
        const p = particles[i];
        const k = GKEY(Math.floor(p.x / cs), Math.floor(p.y / cs));
        let arr = grid.get(k);
        if (!arr) { arr = []; grid.set(k, arr); }
        arr.push(i);
      }
    };

    // Reusable batched link paths
    const paths: Path2D[] = [];

    // ---------- Draw ----------
    const draw = (dt: number, step: boolean) => {
      if (cfg.trails && step) {
        // Motion-blur trails: pudarkan frame sebelumnya menuju transparan
        ctx.globalCompositeOperation = "destination-out";
        ctx.fillStyle = "rgba(0,0,0,0.22)";
        ctx.fillRect(0, 0, w, h);
        ctx.globalCompositeOperation = "source-over";
      } else {
        ctx.clearRect(0, 0, w, h);
      }

      const dtUnit = Math.min(dt, 50) / 16.667; // normalisasi ke ~60fps unit
      const cs = cfg.linkDist;

      // ---- Physics ----
      if (step) {
        for (const p of particles) {
          // Mouse repulsion (hanya jika aktif)
          if (mouseEnabled && mouse.active) {
            const dx = p.x - mouse.x;
            const dy = p.y - mouse.y;
            const d2 = dx * dx + dy * dy;
            const R = 160;
            if (d2 < R * R && d2 > 1) {
              const d = Math.sqrt(d2);
              const f = (1 - d / R) * 0.5;
              p.vx += (dx / d) * f * dtUnit;
              p.vy += (dy / d) * f * dtUnit;
            }
          }

          // Clamp kecepatan supaya gerak stabil & tidak meledak
          const sp2 = p.vx * p.vx + p.vy * p.vy;
          const MAX = 0.85, MIN = 0.05;
          if (sp2 > MAX * MAX) {
            const sp = Math.sqrt(sp2);
            p.vx = (p.vx / sp) * MAX;
            p.vy = (p.vy / sp) * MAX;
          } else if (sp2 < MIN * MIN && sp2 > 0) {
            const sp = Math.sqrt(sp2);
            p.vx = (p.vx / sp) * MIN;
            p.vy = (p.vy / sp) * MIN;
          }

          p.x += p.vx * dtUnit;
          p.y += p.vy * dtUnit;

          // Wrap with margin
          const m = 24;
          if (p.x < -m) p.x = w + m;
          else if (p.x > w + m) p.x = -m;
          if (p.y < -m) p.y = h + m;
          else if (p.y > h + m) p.y = -m;
        }
      }

      // ---- Links (spatial grid + batched paths) ----
      if (cfg.links && particles.length > 1) {
        buildGrid();

        const batches = cfg.linkBatches;
        while (paths.length < batches) paths.push(new Path2D());
        for (let b = 0; b < batches; b++) paths[b] = new Path2D();

        const linkDist2 = cs * cs;

        for (let i = 0; i < particles.length; i++) {
          const a = particles[i];
          const acx = Math.floor(a.x / cs);
          const acy = Math.floor(a.y / cs);

          for (let ox = -1; ox <= 1; ox++) {
            for (let oy = -1; oy <= 1; oy++) {
              const arr = grid.get(GKEY(acx + ox, acy + oy));
              if (!arr) continue;
              for (let k = 0; k < arr.length; k++) {
                const j = arr[k];
                if (j <= i) continue; // dedupe pasangan
                const b = particles[j];
                const dx = a.x - b.x;
                const dy = a.y - b.y;
                const d2 = dx * dx + dy * dy;
                if (d2 >= linkDist2) continue;
                const t = 1 - Math.sqrt(d2) / cs;
                const bucket = Math.min(batches - 1, (t * batches) | 0);
                paths[bucket].moveTo(a.x, a.y);
                paths[bucket].lineTo(b.x, b.y);
              }
            }
          }
        }

        ctx.lineWidth = 1;
        ctx.strokeStyle = colorB;
        const baseAlpha = isDark ? 0.5 : 0.3;
        for (let b = 0; b < batches; b++) {
          ctx.globalAlpha = ((b + 0.5) / batches) * baseAlpha;
          ctx.stroke(paths[b]);
        }
        ctx.globalAlpha = 1;
      }

      // ---- Glow (hanya dark mode + tier dengan glow) ----
      const useGlow = cfg.glow && isDark && spritesReady;
      if (useGlow) ctx.globalCompositeOperation = "lighter";
      for (const p of particles) {
        if (!useGlow) continue;
        const s = p.r * 3.5;
        const spr = p.hue < 0.5 ? spriteA : spriteB;
        ctx.globalAlpha = 0.42;
        ctx.drawImage(spr, p.x - s, p.y - s, s * 2, s * 2);
      }
      if (useGlow) ctx.globalCompositeOperation = "source-over";

      // ---- Core dots ----
      ctx.globalAlpha = isDark ? 0.95 : 0.75;
      for (const p of particles) {
        ctx.fillStyle = p.color;
        ctx.beginPath();
        ctx.arc(p.x, p.y, p.r, 0, Math.PI * 2);
        ctx.fill();
      }
      ctx.globalAlpha = 1;
    };

    // ---------- Loop (frame-rate independent) ----------
    const loop = (t: number) => {
      raf = requestAnimationFrame(loop);
      if (!visible || document.hidden) { last = 0; return; }
      if (last === 0) { last = t; return; }
      const dt = t - last;
      if (cfg.fps > 0 && dt < 1000 / cfg.fps - 1) return; // cap FPS bila perlu
      last = t;
      draw(dt, true);
    };

    // ---------- Init ----------
    readColors();
    resize();

    if (!reduceMotion) raf = requestAnimationFrame(loop);

    // ---------- Listeners ----------
    const onPointer = (e: PointerEvent) => {
      if (!mouseEnabled) return;
      const rect = canvas.getBoundingClientRect();
      mouse.x = e.clientX - rect.left;
      mouse.y = e.clientY - rect.top;
      mouse.active = true;
    };
    const onLeave = () => { mouse.active = false; };

    const ro = new ResizeObserver(resize);
    ro.observe(canvas);

    const io = new IntersectionObserver(([e]) => { visible = e.isIntersecting; });
    io.observe(canvas);

    const mo = new MutationObserver(() => { readColors(); });
    mo.observe(root, { attributes: true, attributeFilter: ["class"] });

    if (mouseEnabled) {
      window.addEventListener("pointermove", onPointer, { passive: true });
      window.addEventListener("pointerleave", onLeave);
    }

    return () => {
      cancelAnimationFrame(raf);
      ro.disconnect();
      io.disconnect();
      mo.disconnect();
      window.removeEventListener("pointermove", onPointer);
      window.removeEventListener("pointerleave", onLeave);
    };
  }, []);

  return <canvas ref={ref} aria-hidden className={`pointer-events-none ${className}`} />;
}