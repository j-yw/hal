// Framework-agnostic Canvas runtime for the exported retro-fx-config.json.
// Usage:
//   import { createRetroFX } from './retro-fx-runtime.mjs';
//   const fx = createRetroFX(document.querySelector('canvas'), config);
//   await fx.setImage('/hero.jpg');
//   fx.start();

export function createRetroFX(canvas, config = {}) {
  const renderer = new RetroFX(canvas, config);
  return {
    start: () => renderer.start(),
    stop: () => renderer.stop(),
    destroy: () => renderer.destroy(),
    update: nextConfig => renderer.update(nextConfig),
    setImage: source => renderer.setImage(source),
    exportPNG: () => renderer.exportPNG(),
    get config() { return renderer.config; },
  };
}

const DEFAULTS = {
  size: { width: 960, height: 540, sourceWidth: 320, sourceHeight: 180 },
  layerOrder: ['dither', 'ascii', 'crt'],
  text: { main: 'ASCII', subtitle: 'DITHER // CRT // PHOSPHOR' },
  effects: {
    dither: { enabled: true, strength: 0.35, grain: 4, crawlSpeed: 0.12 },
    ascii: {
      enabled: true,
      animateUploaded: true,
      cell: 8,
      fps: 24,
      shimmer: 0.12,
      speed: 0.8,
      glyphRamp: ' .:-=+*#%@',
      palette: 'color',
      lowColor: '#06100b',
      highColor: '#77f2a1',
      background: '#020409',
    },
    crt: { enabled: true, strength: 0.85, speed: 1, glow: 0.42, scanlines: 0.16, chroma: 0.15, vignette: 0.68 },
    orb: { enabled: true, strength: 0.55, speed: 1 },
    source: { speed: 1 },
  },
};

const BAYER4 = [
  0, 8, 2, 10,
  12, 4, 14, 6,
  3, 11, 1, 9,
  15, 7, 13, 5,
].map(v => (v + 0.5) / 16);

class RetroFX {
  constructor(canvas, config) {
    if (!canvas) throw new Error('createRetroFX requires a canvas element');
    this.canvas = canvas;
    this.ctx = canvas.getContext('2d', { alpha: false });
    this.config = mergeConfig(DEFAULTS, config);

    this.W = this.config.size.width || canvas.width || 960;
    this.H = this.config.size.height || canvas.height || 540;
    this.SRC_W = this.config.size.sourceWidth || 320;
    this.SRC_H = this.config.size.sourceHeight || 180;
    canvas.width = this.W;
    canvas.height = this.H;

    this.source = makeCanvas(this.SRC_W, this.SRC_H);
    this.sourceFull = makeCanvas(this.W, this.H);
    this.ascii = makeCanvas(this.W, this.H);
    this.dithered = makeCanvas(this.W, this.H);
    this.bloom = makeCanvas(this.W, this.H);
    this.sample = makeCanvas(16, 16);
    this.ditherTexture = makeCanvas(16, 16);
    this.ditherTextureKey = '';
    this.ditherPattern = null;

    this.sctx = this.source.getContext('2d', { willReadFrequently: true });
    this.sfctx = this.sourceFull.getContext('2d', { alpha: true });
    this.actx = this.ascii.getContext('2d', { alpha: true });
    this.dctx = this.dithered.getContext('2d', { alpha: true });
    this.bctx = this.bloom.getContext('2d', { alpha: true });
    this.sampleCtx = this.sample.getContext('2d', { willReadFrequently: true });

    this.image = null;
    this.current = this.ascii;
    this.running = false;
    this.raf = 0;
    this.last = performance.now();
    this.lastAsciiUpdate = 0;
    this.dirty = true;
    this.time = { source: 0, dither: 0, ascii: 0, crt: 0, orb: 0 };

    if (this.config.source?.image) this.setImage(this.config.source.image);
  }

  start() {
    if (this.running) return;
    this.running = true;
    this.last = performance.now();
    this.raf = requestAnimationFrame(now => this.frame(now));
  }

  stop() {
    this.running = false;
    if (this.raf) cancelAnimationFrame(this.raf);
    this.raf = 0;
  }

  destroy() {
    this.stop();
    this.image = null;
  }

  update(nextConfig = {}) {
    this.config = mergeConfig(this.config, nextConfig);
    this.dirty = true;
  }

  async setImage(source) {
    if (!source) {
      this.image = null;
      this.dirty = true;
      return null;
    }

    if (source instanceof HTMLCanvasElement || source instanceof HTMLImageElement || source instanceof ImageBitmap) {
      this.image = this.fitImage(source);
      this.dirty = true;
      return this.image;
    }

    const img = new Image();
    img.crossOrigin = 'anonymous';
    const loaded = new Promise((resolve, reject) => {
      img.onload = () => resolve(img);
      img.onerror = reject;
    });
    img.src = String(source);
    await loaded;
    this.image = this.fitImage(img);
    this.dirty = true;
    return this.image;
  }

  exportPNG() {
    return new Promise(resolve => this.canvas.toBlob(resolve, 'image/png'));
  }

  frame(now) {
    if (!this.running) return;
    const fx = this.config.effects;
    const dt = Math.min(0.05, (now - this.last) / 1000);
    this.last = now;
    this.time.source += dt * (fx.source?.speed ?? 1);
    this.time.dither += dt * (fx.dither?.crawlSpeed ?? 0);
    this.time.ascii += dt * (fx.ascii?.speed ?? 0.6);
    this.time.crt += dt * (fx.crt?.speed ?? 1);
    this.time.orb += dt * (fx.orb?.speed ?? 1);

    const asciiFPS = Math.max(1, fx.ascii?.fps ?? 24);
    const sourceMoves = !this.image && (fx.source?.speed ?? 1) > 0;
    const uploadedASCIIAllowed = !this.image || fx.ascii?.animateUploaded !== false;
    const asciiShimmers = this.asciiEnabled() && uploadedASCIIAllowed && (fx.ascii?.shimmer ?? 0) > 0 && (fx.ascii?.speed ?? 0.6) > 0;
    const ditherBreathes = uploadedASCIIAllowed && this.ditherEnabled() && (fx.dither?.crawlSpeed ?? 0) > 0 && (this.ditherBeforeAscii() || this.ditherBetweenBaseAndCRT() || this.ditherFinal());
    const crtMovesBeforeASCII = this.crtBeforeAscii() && (fx.crt?.speed ?? 1) > 0;
    const shouldUpdate = this.dirty || ((sourceMoves || asciiShimmers || ditherBreathes || crtMovesBeforeASCII) && now - this.lastAsciiUpdate >= 1000 / asciiFPS);

    if (shouldUpdate) {
      this.rebuildBase();
      this.lastAsciiUpdate = now;
      this.dirty = false;
    }

    this.renderFrame();
    this.raf = requestAnimationFrame(next => this.frame(next));
  }

  layerIndex(name) { return this.config.layerOrder.indexOf(name); }
  effectEnabled(name) {
    const e = this.config.effects;
    if (name === 'dither') return !!e.dither?.enabled;
    if (name === 'ascii') return !!e.ascii?.enabled;
    if (name === 'crt') return !!e.crt?.enabled;
    return true;
  }
  activeLayers() { return this.config.layerOrder.filter(name => this.effectEnabled(name)); }
  ditherEnabled() { return !!this.config.effects.dither?.enabled && (this.config.effects.dither?.strength ?? 0) > 0; }
  asciiEnabled() { return !!this.config.effects.ascii?.enabled; }
  crtEnabled() { return !!this.config.effects.crt?.enabled && (this.config.effects.crt?.strength ?? 0) > 0; }
  crtBeforeAscii() { return this.crtEnabled() && this.asciiEnabled() && this.layerIndex('crt') < this.layerIndex('ascii'); }
  crtAfterBase() { return this.crtEnabled() && (!this.asciiEnabled() || this.layerIndex('crt') > this.layerIndex('ascii')); }
  ditherBeforeAscii() { return this.ditherEnabled() && this.asciiEnabled() && this.layerIndex('dither') < this.layerIndex('ascii'); }
  ditherBetweenBaseAndCRT() {
    if (!this.ditherEnabled() || this.ditherBeforeAscii()) return false;
    const active = this.activeLayers();
    const d = active.indexOf('dither');
    const c = active.indexOf('crt');
    if (d < 0) return false;
    if (c < 0) return true;
    return d < c;
  }
  ditherFinal() {
    if (!this.ditherEnabled() || this.ditherBeforeAscii()) return false;
    const active = this.activeLayers();
    return active[active.length - 1] === 'dither';
  }

  rebuildBase() {
    this.drawSource();
    if (this.crtBeforeAscii()) this.applySourceCRT();

    if (this.asciiEnabled()) {
      this.drawASCII(this.ditherBeforeAscii());
      this.current = this.ascii;
    } else {
      this.drawSourceFull();
      this.current = this.sourceFull;
    }

    if (this.ditherBetweenBaseAndCRT()) {
      this.current = this.applyPostDither(this.current, this.dithered);
    }

    if (this.crtAfterBase()) this.updateBloom(this.current);
  }

  renderFrame() {
    if (this.crtAfterBase()) this.composeCRT(this.current);
    else this.renderRaw(this.current);

    if (this.ditherFinal()) {
      this.applyPostDither(this.canvas, this.dithered);
      this.ctx.clearRect(0, 0, this.W, this.H);
      this.ctx.drawImage(this.dithered, 0, 0);
    }
    this.drawSmoothDitherDrift();
  }

  drawSource() {
    const c = this.sctx;
    c.clearRect(0, 0, this.SRC_W, this.SRC_H);
    if (this.image) {
      c.drawImage(this.image, 0, 0, this.SRC_W, this.SRC_H);
      c.fillStyle = 'rgba(0,0,0,.18)';
      c.fillRect(0, 0, this.SRC_W, this.SRC_H);
    } else {
      const t = this.time.source;
      const bg = c.createLinearGradient(0, 0, this.SRC_W, this.SRC_H);
      bg.addColorStop(0, '#070b14');
      bg.addColorStop(.46, '#141029');
      bg.addColorStop(1, '#05070b');
      c.fillStyle = bg;
      c.fillRect(0, 0, this.SRC_W, this.SRC_H);
      this.drawGeneratedBlobs(c, t);
    }
    this.drawText(c);
  }

  drawGeneratedBlobs(c, t) {
    const blobs = [
      { x: 95 + Math.sin(t * .75) * 22, y: 82 + Math.cos(t * .9) * 13, r: 56, color: '#ffcc33' },
      { x: 188 + Math.cos(t * .55) * 34, y: 95 + Math.sin(t * .8) * 18, r: 66, color: '#7c5cff' },
      { x: 246 + Math.sin(t * .62 + 2.1) * 25, y: 82 + Math.cos(t * .72) * 15, r: 48, color: '#22d3ff' },
    ];
    for (const blob of blobs) {
      const g = c.createRadialGradient(blob.x, blob.y, 0, blob.x, blob.y, blob.r);
      g.addColorStop(0, blob.color);
      g.addColorStop(.62, `${blob.color}cc`);
      g.addColorStop(1, `${blob.color}00`);
      c.fillStyle = g;
      c.beginPath();
      c.arc(blob.x, blob.y, blob.r, 0, Math.PI * 2);
      c.fill();
    }
  }

  drawText(c) {
    const text = this.config.text || {};
    const main = String(text.main || '').trim();
    const sub = String(text.subtitle || '').trim();
    if (!main && !sub) return;
    c.save();
    c.translate(this.SRC_W / 2, this.SRC_H / 2);
    c.textAlign = 'center';
    c.textBaseline = 'middle';
    if (main) {
      c.fillStyle = 'rgba(255,255,255,.94)';
      c.font = `800 ${main.length > 14 ? 27 : 35}px ui-sans-serif, system-ui, sans-serif`;
      c.fillText(main, 0, sub ? -8 : 0, 252);
    }
    if (sub) {
      c.fillStyle = this.config.effects.ascii?.highColor || '#77f2a1';
      c.font = `700 ${sub.length > 30 ? 10 : 12}px ui-sans-serif, system-ui, sans-serif`;
      c.fillText(sub, 0, main ? 26 : 0, 252);
    }
    c.restore();
  }

  drawSourceFull() {
    const bg = this.config.effects.ascii?.background || '#020409';
    this.sfctx.clearRect(0, 0, this.W, this.H);
    this.sfctx.fillStyle = bg;
    this.sfctx.fillRect(0, 0, this.W, this.H);
    this.sfctx.imageSmoothingEnabled = true;
    this.sfctx.imageSmoothingQuality = 'high';
    this.sfctx.drawImage(this.source, 0, 0, this.W, this.H);
  }

  drawASCII(usePreDither) {
    const fx = this.config.effects;
    const ascii = fx.ascii || {};
    const bg = ascii.background || '#020409';
    const cellW = Math.max(3, ascii.cell || 8);
    const cellH = Math.round(cellW * 1.5);
    const cols = Math.ceil(this.W / cellW);
    const rows = Math.ceil(this.H / cellH);
    const ramp = ascii.glyphRamp?.length ? ascii.glyphRamp : ' .:-=+*#%@';
    const img = this.sctx.getImageData(0, 0, this.SRC_W, this.SRC_H).data;

    this.actx.clearRect(0, 0, this.W, this.H);
    this.actx.fillStyle = bg;
    this.actx.fillRect(0, 0, this.W, this.H);
    this.actx.font = `700 ${cellH}px ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace`;
    this.actx.textBaseline = 'top';

    const d = fx.dither || {};
    for (let gy = 0; gy < rows; gy++) {
      for (let gx = 0; gx < cols; gx++) {
        const sx = Math.min(this.SRC_W - 1, Math.floor((gx + 0.5) * this.SRC_W / cols));
        const sy = Math.min(this.SRC_H - 1, Math.floor((gy + 0.5) * this.SRC_H / rows));
        const i = (sy * this.SRC_W + sx) * 4;
        const r = img[i], g = img[i + 1], b = img[i + 2];
        const baseLum = (0.2126 * r + 0.7152 * g + 0.0722 * b) / 255;
        let glyphLum = baseLum;
        if (usePreDither) {
          const threshold = BAYER4[(gy & 3) * 4 + (gx & 3)] - 0.5;
          const pulse = (d.crawlSpeed || 0) > 0
            ? 1 + Math.sin(gx * 0.57 + gy * 0.41 + this.time.dither * 5.2) * 0.42
            : 1;
          glyphLum = clamp(baseLum + threshold * (d.strength || 0) * pulse);
        }
        const motion = (ascii.shimmer || 0) > 0 && (ascii.speed || 0) > 0 ? ascii.shimmer : 0;
        const flowA = gx * 0.31 + gy * 0.23 + this.time.ascii * 2.7;
        const flowB = gx * -0.17 + gy * 0.29 + this.time.ascii * 1.9;
        const shimmerValue = motion > 0 ? Math.sin(flowA) * 0.65 + Math.cos(flowB) * 0.35 : 0;
        const displayLum = clamp(glyphLum + shimmerValue * motion * 0.9);
        const dx = motion > 0 ? Math.sin(flowA) * cellW * motion * 2.9 : 0;
        const dy = motion > 0 ? Math.cos(flowB) * cellH * motion * 1.15 : 0;
        const ch = ramp[Math.min(ramp.length - 1, Math.max(0, Math.floor(glyphLum * ramp.length)))] || ' ';
        if (ch === ' ') continue;
        this.actx.fillStyle = this.paletteColor(r, g, b, displayLum);
        this.actx.globalAlpha = clamp(lerp(.42, 1, displayLum) + shimmerValue * motion * .45, .22, 1);
        this.actx.fillText(ch, gx * cellW + dx, gy * cellH - 1 + dy);
      }
    }
    this.actx.globalAlpha = 1;
  }

  paletteColor(r, g, b, lum) {
    const ascii = this.config.effects.ascii || {};
    const gain = lerp(0.62, 1.35, lum);
    if (ascii.palette === 'custom') return mixHex(ascii.lowColor, ascii.highColor, lum);
    if (ascii.palette === 'green') return `rgb(${Math.round(55 * lum)}, ${Math.round(255 * gain)}, ${Math.round(115 * gain)})`;
    if (ascii.palette === 'amber') return `rgb(${Math.round(255 * gain)}, ${Math.round(180 * gain)}, ${Math.round(64 * lum)})`;
    if (ascii.palette === 'white') {
      const v = Math.round(lerp(80, 255, lum));
      return `rgb(${v}, ${v}, ${Math.round(v * .92)})`;
    }
    return `rgb(${Math.round(r * gain)}, ${Math.round(g * gain)}, ${Math.round(b * gain)})`;
  }

  applySourceCRT() {
    const crt = this.config.effects.crt || {};
    const strength = crt.strength || 0;
    const c = this.sctx;
    c.save();
    c.fillStyle = `rgba(0,0,0,${0.10 * strength})`;
    for (let y = 2; y < this.SRC_H; y += 4) c.fillRect(0, y, this.SRC_W, 2);
    c.globalCompositeOperation = 'screen';
    c.fillStyle = `rgba(170,255,205,${0.08 * strength})`;
    const y = ((this.time.crt * 14) % (this.SRC_H + 40)) - 20;
    c.fillRect(0, y, this.SRC_W, 8);
    c.restore();
  }

  applyPostDither(input, output) {
    const d = this.config.effects.dither || {};
    const bg = this.config.effects.ascii?.background || '#020409';
    const grain = Math.max(1, Math.round(d.grain || 4));
    const cols = Math.ceil(this.W / grain);
    const rows = Math.ceil(this.H / grain);

    this.dctx.clearRect(0, 0, this.W, this.H);
    this.dctx.fillStyle = bg;
    this.dctx.fillRect(0, 0, this.W, this.H);
    this.dctx.drawImage(input, 0, 0);

    if (this.sample.width !== cols || this.sample.height !== rows) {
      this.sample.width = cols;
      this.sample.height = rows;
    }
    this.sampleCtx.clearRect(0, 0, cols, rows);
    this.sampleCtx.drawImage(input, 0, 0, cols, rows);
    const pixels = this.sampleCtx.getImageData(0, 0, cols, rows).data;

    this.dctx.fillStyle = bg;
    for (let gy = 0; gy < rows; gy++) {
      for (let gx = 0; gx < cols; gx++) {
        const i = (gy * cols + gx) * 4;
        const lum = (0.2126 * pixels[i] + 0.7152 * pixels[i + 1] + 0.0722 * pixels[i + 2]) / 255;
        const threshold = BAYER4[(gy & 3) * 4 + (gx & 3)];
        const pulse = (d.crawlSpeed || 0) > 0
          ? 1 + Math.sin(gx * 0.57 + gy * 0.41 + this.time.dither * 5.2) * 0.42
          : 1;
        if (lum < lerp(-0.1, threshold, clamp((d.strength || 0) * pulse, 0, 1))) this.dctx.fillRect(gx * grain, gy * grain, grain, grain);
      }
    }
    return output;
  }

  ensureDitherPattern() {
    const d = this.config.effects.dither || {};
    const ascii = this.config.effects.ascii || {};
    const grain = Math.max(2, Math.round(d.grain || 4));
    const high = ascii.palette === 'custom' ? ascii.highColor : '#77f2a1';
    const key = `${grain}:${ascii.background || '#020409'}:${high}`;
    if (this.ditherPattern && this.ditherTextureKey === key) return this.ditherPattern;

    const cells = 8;
    this.ditherTexture.width = grain * cells;
    this.ditherTexture.height = grain * cells;
    const c = this.ditherTexture.getContext('2d');
    c.clearRect(0, 0, this.ditherTexture.width, this.ditherTexture.height);
    for (let y = 0; y < cells; y++) {
      for (let x = 0; x < cells; x++) {
        const threshold = BAYER4[(y & 3) * 4 + (x & 3)];
        if (threshold < 0.34) {
          c.fillStyle = 'rgba(0,0,0,.9)';
          c.fillRect(x * grain, y * grain, grain, grain);
        } else if (threshold > 0.78) {
          c.fillStyle = rgbaHex(high, .72);
          c.fillRect(x * grain, y * grain, grain, grain);
        }
      }
    }
    this.ditherPattern = this.ctx.createPattern(this.ditherTexture, 'repeat');
    this.ditherTextureKey = key;
    return this.ditherPattern;
  }

  drawSmoothDitherDrift() {
    const d = this.config.effects.dither || {};
    if (!this.ditherEnabled() || (d.crawlSpeed || 0) <= 0.001) return;
    const pattern = this.ensureDitherPattern();
    if (!pattern) return;

    const driftPixels = this.time.dither * 180;
    const wobbleX = Math.sin(this.time.dither * 0.73) * (d.grain || 4) * 0.7;
    const wobbleY = Math.cos(this.time.dither * 0.61) * (d.grain || 4) * 0.7;
    const speedVisibility = Math.min(1, Math.sqrt((d.crawlSpeed || 0) / 0.12));
    const alpha = Math.min(0.24, (0.05 + (d.strength || 0) * 0.20) * speedVisibility);

    this.ctx.save();
    this.ctx.globalAlpha = alpha;
    this.ctx.globalCompositeOperation = 'source-over';
    this.ctx.translate(driftPixels + wobbleX, driftPixels * 0.45 + wobbleY);
    this.ctx.fillStyle = pattern;
    this.ctx.fillRect(-this.W, -this.H, this.W * 3, this.H * 3);
    this.ctx.restore();
  }

  updateBloom(input) {
    this.bctx.save();
    this.bctx.clearRect(0, 0, this.W, this.H);
    this.bctx.filter = 'blur(8px) brightness(1.55) saturate(1.25)';
    this.bctx.drawImage(input, 0, 0);
    this.bctx.restore();
  }

  composeCRT(input) {
    const crt = this.config.effects.crt || {};
    const bg = this.config.effects.ascii?.background || '#020409';
    const strength = crt.strength || 0;
    this.ctx.save();
    this.ctx.clearRect(0, 0, this.W, this.H);
    this.ctx.fillStyle = bg;
    this.ctx.fillRect(0, 0, this.W, this.H);
    this.ctx.globalCompositeOperation = 'screen';
    this.ctx.globalAlpha = (crt.glow || 0) * strength;
    this.ctx.drawImage(this.bloom, 0, 0);
    this.ctx.globalCompositeOperation = 'source-over';
    this.ctx.globalAlpha = 1;
    this.ctx.drawImage(input, 0, 0);

    const chroma = crt.chroma ?? 0.15;
    const shift = 1.2 + chroma * 16;
    this.ctx.globalCompositeOperation = 'screen';
    this.ctx.globalAlpha = chroma * strength;
    this.ctx.filter = 'hue-rotate(-22deg) saturate(1.6)';
    this.ctx.drawImage(input, -shift, 0);
    this.ctx.filter = 'hue-rotate(155deg) saturate(1.6)';
    this.ctx.drawImage(input, shift, 0);
    this.ctx.filter = 'none';
    this.ctx.globalAlpha = 1;
    this.ctx.globalCompositeOperation = 'source-over';

    this.drawOrb(this.ctx);

    this.ctx.fillStyle = `rgba(0,0,0,${(crt.scanlines ?? 0.16) * strength})`;
    for (let y = 0; y < this.H; y += 4) this.ctx.fillRect(0, y + 2, this.W, 2);

    const y = ((this.time.crt * 44) % (this.H + 120)) - 60;
    const roll = this.ctx.createLinearGradient(0, y - 24, 0, y + 24);
    roll.addColorStop(0, 'rgba(255,255,255,0)');
    roll.addColorStop(.5, `rgba(170,255,205,${0.07 * strength})`);
    roll.addColorStop(1, 'rgba(255,255,255,0)');
    this.ctx.fillStyle = roll;
    this.ctx.fillRect(0, y - 24, this.W, 48);

    const vignette = crt.vignette ?? 0.68;
    const v = this.ctx.createRadialGradient(this.W / 2, this.H / 2, this.H * .15, this.W / 2, this.H / 2, this.W * .62);
    v.addColorStop(0, 'rgba(0,0,0,0)');
    v.addColorStop(.72, `rgba(0,0,0,${0.26 * vignette * strength})`);
    v.addColorStop(1, `rgba(0,0,0,${vignette * strength})`);
    this.ctx.fillStyle = v;
    this.ctx.fillRect(0, 0, this.W, this.H);
    this.ctx.restore();
  }

  renderRaw(input) {
    const bg = this.config.effects.ascii?.background || '#020409';
    this.ctx.save();
    this.ctx.clearRect(0, 0, this.W, this.H);
    this.ctx.fillStyle = bg;
    this.ctx.fillRect(0, 0, this.W, this.H);
    this.ctx.drawImage(input, 0, 0);
    this.drawOrb(this.ctx);
    this.ctx.restore();
  }

  drawOrb(c) {
    const orb = this.config.effects.orb || {};
    if (!orb.enabled || (orb.strength || 0) <= 0) return;
    const ascii = this.config.effects.ascii || {};
    const high = ascii.palette === 'custom' ? ascii.highColor : '#77f2a1';
    const hot = ascii.palette === 'custom' ? ascii.lowColor : '#7c5cff';
    const t = this.time.orb;
    const cx = this.W * 0.5 + Math.sin(t * 0.72) * this.W * 0.17;
    const cy = this.H * 0.49 + Math.cos(t * 0.91) * this.H * 0.12;
    const r = Math.min(this.W, this.H) * 0.34;
    c.save();
    c.globalCompositeOperation = 'screen';
    const g = c.createRadialGradient(cx, cy, 0, cx, cy, r);
    g.addColorStop(0, rgbaHex(high, 0.32 * orb.strength));
    g.addColorStop(0.36, rgbaHex(hot, 0.16 * orb.strength));
    g.addColorStop(0.72, rgbaHex(high, 0.055 * orb.strength));
    g.addColorStop(1, 'rgba(0,0,0,0)');
    c.fillStyle = g;
    c.fillRect(0, 0, this.W, this.H);
    c.restore();
  }

  fitImage(img) {
    const fitted = makeCanvas(this.SRC_W, this.SRC_H);
    const c = fitted.getContext('2d');
    const iw = img.naturalWidth || img.width;
    const ih = img.naturalHeight || img.height;
    const scale = Math.max(this.SRC_W / iw, this.SRC_H / ih);
    const dw = iw * scale;
    const dh = ih * scale;
    c.drawImage(img, (this.SRC_W - dw) / 2, (this.SRC_H - dh) / 2, dw, dh);
    return fitted;
  }
}

function makeCanvas(w, h) {
  const c = document.createElement('canvas');
  c.width = w;
  c.height = h;
  return c;
}

function mergeConfig(base, next) {
  if (!next) return structuredCloneSafe(base);
  const out = structuredCloneSafe(base);
  deepMerge(out, normalizeConfig(next));
  return out;
}

function normalizeConfig(config) {
  const copy = structuredCloneSafe(config);
  if (Array.isArray(copy.layerOrder)) copy.layerOrder = copy.layerOrder.join('-').split('-');
  else if (typeof copy.layerOrder === 'string') copy.layerOrder = copy.layerOrder.split('-');
  return copy;
}

function deepMerge(target, source) {
  for (const [key, value] of Object.entries(source || {})) {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      target[key] ||= {};
      deepMerge(target[key], value);
    } else {
      target[key] = value;
    }
  }
  return target;
}

function structuredCloneSafe(value) {
  return JSON.parse(JSON.stringify(value));
}

function clamp(v, lo = 0, hi = 1) { return Math.max(lo, Math.min(hi, v)); }
function lerp(a, b, t) { return a + (b - a) * t; }

function hexToRgb(hex) {
  const clean = String(hex || '').replace('#', '').trim();
  if (!/^[0-9a-fA-F]{6}$/.test(clean)) return { r: 255, g: 255, b: 255 };
  return {
    r: parseInt(clean.slice(0, 2), 16),
    g: parseInt(clean.slice(2, 4), 16),
    b: parseInt(clean.slice(4, 6), 16),
  };
}

function rgbaHex(hex, alpha) {
  const rgb = hexToRgb(hex);
  return `rgba(${rgb.r}, ${rgb.g}, ${rgb.b}, ${alpha})`;
}

function mixHex(lowHex, highHex, t) {
  const low = hexToRgb(lowHex);
  const high = hexToRgb(highHex);
  return `rgb(${Math.round(lerp(low.r, high.r, t))}, ${Math.round(lerp(low.g, high.g, t))}, ${Math.round(lerp(low.b, high.b, t))})`;
}
