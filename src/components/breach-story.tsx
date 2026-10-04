import { useEffect, useMemo, useRef, useState } from "react";
import {
  CartesianGrid,
  ComposedChart,
  Line,
  ReferenceLine,
  ResponsiveContainer,
  Scatter,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
} from "recharts";
import { ArrowDown, Flame, RefreshCw, Shield, Zap, Sparkles, ArrowUpRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { aiAmplifiers, AI_SCENARIOS, applyAIScenario, isAIScenario, riskRange, NDAY_MEDIAN_DAYS, DEFAULT_COMPANY, OWN_BASE_ATTACKER_WIN, VENDOR_ZERO_DAY_SHARE, computeRisk, IRIS_TARGET, UK_ATTACK_TARGET, M_EXP_CRED, M_EXP_PHISH, DEVICE_COVERAGE, calibratedExposure, endpointMultiplier, type CompanySize, type CompanyInputs, type CompanyResult } from "@/lib/company-risk";
import { createSim, simParams, simStats, stepSim, BURNING, OK, VULN, type Sim, type SimStats } from "@/lib/company-sim";

type Rng = () => number;

function mulberry32(seed: number): Rng {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const CCDF = [
  [500, 1],
  [100_000, 0.153],
  [300_000, 0.075],
  [1_000_000, 0.027],
  [3_000_000, 0.0082],
  [10_000_000, 0.0017],
  [30_000_000, 0.00043],
  [100_000_000, 0.00022],
  [192_700_000, 0],
] as const;

function sampleBreach(rng: Rng) {
  const survival = rng();
  for (let i = 0; i < CCDF.length - 1; i += 1) {
    const lower = CCDF[i];
    const upper = CCDF[i + 1];
    if (!lower || !upper) continue;
    const [x1, p1] = lower;
    const [x2, p2] = upper;
    if (survival <= p1 && survival >= p2) {
      if (p2 === 0) return Math.min(x2, x1 * Math.pow(x2 / x1, rng()));
      const t = (Math.log(survival) - Math.log(p1)) / (Math.log(p2) - Math.log(p1));
      return Math.exp(Math.log(x1) + t * (Math.log(x2) - Math.log(x1)));
    }
  }
  return 500;
}

const fmt = new Intl.NumberFormat("en-US", { maximumFractionDigits: 0 });
const compact = new Intl.NumberFormat("en-US", { notation: "compact", maximumFractionDigits: 1 });

function SectionIntro({ number, question, children }: { number: string; question: string; children: React.ReactNode }) {
  return (
    <header className="section-intro">
      <span className="section-number">{number}</span>
      <h2>{question}</h2>
      <p>{children}</p>
    </header>
  );
}

function Metric({ label, value, detail }: { label: string; value: string; detail?: string }) {
  return (
    <div className="metric">
      <span>{label}</span>
      <strong>{value}</strong>
      {detail ? <small>{detail}</small> : null}
    </div>
  );
}

const APPSEC_LABELS = ["none", "basic SAST/DAST", "AI-assisted", "AI-first, continuous"];
const HARDENING_LABELS = ["flat network", "basic", "segmented", "zero trust", "isolated & hardened"];
const SOC_LABELS = ["none", "business hours", "24/7 MDR", "24/7 + threat hunting"];
const GOV_LABELS = ["none", "basic", "minimised & encrypted", "strict minimisation"];
const IDENTITY_LABELS = ["none", "passwords + SMS codes", "MFA everywhere", "phishing-resistant MFA everywhere"];
const FILTERING_LABELS = ["basic · ×1.3", "standard · ×1", "advanced sandboxing · ×0.8"];
const TRAINING_LABELS = ["none · ×1.05", "annual · ×1", "regular with phishing simulations · ×0.92"];
const EDR_LABELS = ["none", "antivirus", "EDR", "EDR with automated blocking"];
const DEVICE_LABELS = ["unmanaged devices allowed", "BYOD with MDM", "managed devices only, full inventory"];
const CHANNEL_LABELS = { vuln: "Vulnerabilities", cred: "Credential abuse", phish: "Phishing", pretext: "Pretexting", other: "Residual: other routes, errors & insider misuse (model bucket)" } as const;

const COMPANY_PRESETS: Record<string, CompanyInputs> = {
  "Typical company": DEFAULT_COMPANY,
  "Built on vendors, slow patching": { vendorVulns: 6, neverPatched: 0.3, patchDays: 90, appsec: 0, bountyK: 0, hardening: 1, soc: 0, governance: 0, inHouse: 0.1, threat: 1, vendorGrowth: 1 },
  "Vendor vulnpocalypse": { ...DEFAULT_COMPANY, vendorGrowth: 2.2 },
  "AI builder, no AppSec": { vendorVulns: 6, neverPatched: 0.1, patchDays: 30, appsec: 0, bountyK: 0, hardening: 1, soc: 1, governance: 1, inHouse: 0.8, threat: 5, vendorGrowth: 1 },
  "AI attackers everywhere": { ...DEFAULT_COMPANY, threat: 6 },
  "Fortress": { vendorVulns: 6, neverPatched: 0.02, patchDays: 5, appsec: 3, bountyK: 500, hardening: 4, soc: 3, governance: 3, inHouse: 0.5, threat: 1, vendorGrowth: 1 },
};

const pct = (p: number) => (p < 0.001 ? "<0.1%" : `${(p * 100).toFixed(p < 0.1 ? 1 : 0)}%`);
const rate = (x: number) => x.toFixed(x < 0.1 ? 3 : 2);
const exactPct = (p: number) => `${(100 * p).toLocaleString("en-US", { maximumFractionDigits: 1 })}%`;
const SIZE_OPTIONS: [CompanySize, string][] = [["small", "Small"], ["mid", "Mid-size"], ["large", "Very large (Fortune 1000-scale)"]];
const EVENT_LABELS = { reported: "Publicly known significant cyber events", any: "Breaches of any size", incidents: "Incidents", reached: "Attacks via vulnerabilities, credential abuse, phishing and pretexting" } as const;

function CompanyCanvas({ inputs, result }: { inputs: CompanyInputs; result: CompanyResult }) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const simRef = useRef<Sim | null>(null);
  const seedRef = useRef<number | null>(null);
  const newSeed = () => crypto.getRandomValues(new Uint32Array(1))[0] ?? Date.now();
  const params = simParams(inputs, result);
  const paramsKey = JSON.stringify(params);
  const paramsRef = useRef(params);
  paramsRef.current = params;
  const gridRef = useRef({ cols: 26, rows: 14 });
  const [speed, setSpeed] = useState(1);
  const speedRef = useRef(1);
  speedRef.current = speed;
  const [runId, setRunId] = useState(1);
  const [stats, setStats] = useState<SimStats | null>(null);

  // Settings replay the same luck; only page load and Restart draw a new seed.
  useEffect(() => {
    if (seedRef.current === null) seedRef.current = newSeed();
    const { cols, rows } = gridRef.current;
    simRef.current = createSim(cols, rows, seedRef.current, paramsRef.current);
    setStats(simStats(simRef.current));
  }, [paramsKey, runId]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const css = getComputedStyle(canvas);
    const col = (name: string) => css.getPropertyValue(name).trim();
    const colors = { tree: col("--sim-vendor"), patched: col("--sim-patch"), fire: col("--fire"), cool: col("--sim-own"), muted: col("--sim-burned"), vulnerable: col("--sim-vulnerable"), small: col("--sim-small"), reported: col("--sim-reported"), crew: col("--sim-crew"), other: col("--sim-other"), fg: col("--foreground"), cred: col("--bolt-cred"), phish: col("--bolt-phish") };

    const narrow = canvas.clientWidth < 520;
    const cols = narrow ? 18 : 26;
    const rows = narrow ? 12 : 14;
    if (gridRef.current.cols !== cols) {
      gridRef.current = { cols, rows };
      if (seedRef.current !== null) simRef.current = createSim(cols, rows, seedRef.current, paramsRef.current);
    }
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    let cellSize = 10;
    const resize = () => {
      const w = canvas.clientWidth;
      cellSize = w / cols;
      const h = cellSize * rows;
      canvas.width = w * dpr;
      canvas.height = h * dpr;
      canvas.style.height = `${h}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);

    const draw = () => {
      const sim = simRef.current;
      if (!sim) return;
      const w = canvas.clientWidth;
      ctx.clearRect(0, 0, w, cellSize * rows);
      const pad = Math.max(1, cellSize * 0.12);
      const flash = 8 * Math.max(1, speedRef.current / 4); // sim-days a flash stays visible
      for (let i = 0; i < sim.cells.length; i += 1) {
        const cell = sim.cells[i];
        if (!cell) continue;
        const x = (i % cols) * cellSize;
        const y = Math.floor(i / cols) * cellSize;
        if (cell.state === OK) { ctx.globalAlpha = 0.75; ctx.fillStyle = cell.own ? colors.cool : colors.tree; }
        else if (cell.state === VULN) { ctx.globalAlpha = 0.9; ctx.fillStyle = colors.vulnerable; }
        else if (cell.state === BURNING) { ctx.globalAlpha = 0.6 + 0.35 * Math.abs(Math.sin(sim.day * 0.8 + i)); const kind = sim.fires.find((f) => f.id === cell.fire)?.kind; ctx.fillStyle = kind === "contained" ? colors.crew : kind === "small" ? colors.small : colors.reported; }
        else { ctx.globalAlpha = 0.75; ctx.fillStyle = colors.muted; }
        ctx.fillRect(x + pad, y + pad, cellSize - 2 * pad, cellSize - 2 * pad);
        // A circular centre marks custom code even when the cell changes state.
        if (cell.own) {
          ctx.globalAlpha = 0.85; ctx.strokeStyle = colors.fg; ctx.lineWidth = 1;
          ctx.beginPath(); ctx.arc(x + cellSize / 2, y + cellSize / 2, cellSize * 0.2, 0, Math.PI * 2); ctx.stroke();
        }
        if (cell.state === BURNING) {
          const kind = sim.fires.find((f) => f.id === cell.fire)?.kind;
          if (kind !== "contained") {
            const scale = kind === "small" ? 0.23 : 0.42;
            const cx = x + cellSize / 2, cy = y + cellSize / 2;
            ctx.globalAlpha = 1;
            ctx.fillStyle = kind === "small" ? colors.small : colors.reported;
            ctx.beginPath();
            ctx.moveTo(cx, cy - cellSize * scale * 1.6);
            ctx.quadraticCurveTo(cx + cellSize * scale * 1.5, cy, cx + cellSize * scale, cy + cellSize * scale);
            ctx.quadraticCurveTo(cx, cy + cellSize * scale * 1.5, cx - cellSize * scale, cy + cellSize * scale);
            ctx.quadraticCurveTo(cx - cellSize * scale, cy, cx, cy - cellSize * scale * 1.6);
            ctx.fill();
            ctx.strokeStyle = colors.fg; ctx.lineWidth = 1; ctx.stroke();
          }
        }
        if (cell.state === VULN) {
          // patch countdown: vendor patch days, or own-code fix time from AppSec + bounty
          ctx.globalAlpha = 0.95;
          ctx.strokeStyle = colors.patched;
          ctx.lineWidth = 1.6;
          ctx.beginPath();
          if (cell.never) {
            ctx.setLineDash([2, 2]);
            ctx.strokeRect(x + pad, y + pad, cellSize - 2 * pad, cellSize - 2 * pad);
            ctx.setLineDash([]);
          } else {
            const done = Math.min(1, (sim.day - cell.vulnAt) / Math.max(1, cell.patchAt - cell.vulnAt));
            ctx.arc(x + cellSize / 2, y + cellSize / 2, cellSize * 0.4, -Math.PI / 2, -Math.PI / 2 + Math.PI * 2 * done);
            ctx.stroke();
          }
        }
        const since = sim.day - cell.struckAt;
        if (cell.outcome !== null && since >= 0 && since < flash) {
          const a = 1 - since / flash;
          // lightning bolt
          ctx.globalAlpha = a * 0.9;
          const boltColor = cell.src === "cred" ? colors.cred : (cell.src === "phish" || cell.src === "pretext") ? colors.phish : cell.src === "other" ? colors.other : colors.fire;
          ctx.strokeStyle = cell.outcome === "patched" ? colors.patched : boltColor;
          ctx.lineWidth = cell.src === "other" ? 1 : 1.6;
          const cx = x + cellSize / 2;
          ctx.beginPath();
          ctx.moveTo(cx - cellSize * 0.3, 0);
          ctx.lineTo(cx + cellSize * 0.15, y * 0.5);
          ctx.lineTo(cx - cellSize * 0.1, y * 0.5);
          ctx.lineTo(cx, y + cellSize / 2);
          ctx.stroke();
          // patched / blocked: a shield ring, nothing happens
          if (cell.src === "other") {
            // grey spark: insiders, errors, physical, unknown
            ctx.fillStyle = colors.other;
            for (let k = 0; k < 6; k += 1) { const ang = k * 1.047 + i; const rr = cellSize * (0.2 + 0.5 * (1 - a)); ctx.fillRect(cx + Math.cos(ang) * rr - 1, y + cellSize / 2 + Math.sin(ang) * rr - 1, 2, 2); }
          }
          if (cell.state === OK && (cell.outcome === "patched" || cell.outcome === "stopped")) {
            ctx.strokeStyle = cell.outcome === "stopped" ? boltColor : colors.patched;
            ctx.lineWidth = 2;
            ctx.beginPath();
            ctx.arc(cx, y + cellSize / 2, cellSize * (0.35 + 0.3 * (1 - a)), 0, Math.PI * 2);
            ctx.stroke();
          }
        }
      }
      // Not exposed / not targeted: a faint flash on a wet tree, no shield ring.
      for (const wet of sim.wetFlashes) {
        const t = (sim.day - wet.at) / flash;
        if (t < 0 || t >= 1) continue;
        const x = (wet.cell % cols) * cellSize;
        const y = Math.floor(wet.cell / cols) * cellSize;
        ctx.globalAlpha = 0.28 * (1 - t);
        ctx.fillStyle = colors.patched;
        ctx.fillRect(x + pad, y + pad, cellSize - 2 * pad, cellSize - 2 * pad);
      }
      // network segments (hardening slider): walls between cells of different sectors
      ctx.globalAlpha = 0.85;
      ctx.strokeStyle = colors.fg;
      ctx.lineWidth = 1.5;
      ctx.beginPath();
      for (let i = 0; i < sim.cells.length; i += 1) {
        const x = (i % cols) * cellSize, y = Math.floor(i / cols) * cellSize;
        if (i % cols < cols - 1 && sim.sector[i] !== sim.sector[i + 1]) { ctx.moveTo(x + cellSize, y); ctx.lineTo(x + cellSize, y + cellSize); }
        if (i + cols < sim.cells.length && sim.sector[i] !== sim.sector[i + cols]) { ctx.moveTo(x, y + cellSize); ctx.lineTo(x + cellSize, y + cellSize); }
      }
      ctx.stroke();
      // A blocked strike bounces off the nearest segment wall (outer perimeter if flat).
      const walls: { x: number; y: number; vertical: boolean }[] = [];
      for (let i = 0; i < sim.cells.length; i++) {
        const x = (i % cols) * cellSize, y = Math.floor(i / cols) * cellSize;
        if (i % cols < cols - 1 && sim.sector[i] !== sim.sector[i + 1]) walls.push({ x: x + cellSize, y: y + cellSize / 2, vertical: true });
        if (i + cols < sim.cells.length && sim.sector[i] !== sim.sector[i + cols]) walls.push({ x: x + cellSize / 2, y: y + cellSize, vertical: false });
      }
      for (const bounce of sim.wallBounces) {
        const t = (sim.day - bounce.at) / flash;
        if (t < 0 || t >= 1) continue;
        const cx = (bounce.cell % cols + 0.5) * cellSize, cy = (Math.floor(bounce.cell / cols) + 0.5) * cellSize;
        const wall = walls.reduce((best, point) => Math.hypot(point.x - cx, point.y - cy) < Math.hypot(best.x - cx, best.y - cy) ? point : best, { x: cx, y: 0, vertical: false });
        ctx.globalAlpha = 1 - t; ctx.strokeStyle = colors.patched; ctx.lineWidth = 3;
        ctx.beginPath(); ctx.moveTo(wall.x - cellSize * .4, wall.y - cellSize);
        ctx.lineTo(wall.x, wall.y); ctx.lineTo(wall.x + cellSize * (.4 + t), wall.y - cellSize * (1 + t)); ctx.stroke();
        ctx.beginPath();
        if (wall.vertical) { ctx.moveTo(wall.x, wall.y - cellSize); ctx.lineTo(wall.x, wall.y + cellSize); }
        else { ctx.moveTo(wall.x - cellSize, wall.y); ctx.lineTo(wall.x + cellSize, wall.y); }
        ctx.stroke();
      }
      // SOC: dispatch line to the incident, the crew, and a burst where they land
      const ctr = (v: number) => v * cellSize + cellSize / 2;
      for (const crew of sim.crews) {
        const fire = crew.fire ? sim.fires.find((f) => f.id === crew.fire) : undefined;
        if (fire) {
          ctx.globalAlpha = 0.8;
          ctx.strokeStyle = colors.crew;
          ctx.lineWidth = 1.5;
          ctx.setLineDash([4, 3]);
          ctx.beginPath();
          ctx.moveTo(ctr(crew.x), ctr(crew.y));
          ctx.lineTo(ctr(fire.origin % cols), ctr(Math.floor(fire.origin / cols)));
          ctx.stroke();
          ctx.setLineDash([]);
        }
        ctx.globalAlpha = 1;
        ctx.fillStyle = colors.crew;
        ctx.beginPath();
        ctx.arc(ctr(crew.x), ctr(crew.y), Math.max(3, cellSize * (fire ? 0.36 : 0.28)), 0, Math.PI * 2);
        ctx.fill();
      }
      const burstLife = 20 * Math.max(1, speedRef.current / 4);
      for (const b of sim.bursts) {
        const t = (sim.day - b.at) / burstLife;
        if (t < 0 || t > 1) continue;
        ctx.globalAlpha = 1 - t;
        ctx.strokeStyle = b.saved ? colors.crew : colors.muted;
        ctx.lineWidth = 2.5;
        ctx.beginPath();
        ctx.arc(ctr(b.x), ctr(b.y), cellSize * (0.5 + 2.2 * t), 0, Math.PI * 2);
        ctx.stroke();
      }
      ctx.globalAlpha = 1;
      // label each fire with its outcome
      ctx.font = `700 ${Math.max(10, cellSize * 0.5)}px Manrope, sans-serif`;
      ctx.textBaseline = "bottom";
      for (const fire of sim.fires) {
        if (sim.day - fire.start > 45 * Math.max(1, speedRef.current / 4)) continue;
        const late = fire.crew >= 0 ? " · SOC too late" : "";
        const label = fire.kind === "large" ? `LARGE publicly known breach${late}` : fire.kind === "reported" ? `Publicly known breach${late}` : fire.kind === "small" ? "Small breach · below reporting line" : fire.crew >= 0 ? (fire.arrived ? "SOC stopped it · no data loss" : "Incident · SOC on the way…") : "Incident · no data loss";
        const ox = Math.max(2, Math.min(w - ctx.measureText(label).width - 2, (fire.origin % cols) * cellSize));
        const oy = Math.max(14, Math.floor(fire.origin / cols) * cellSize - 2);
        ctx.fillStyle = fire.kind === "contained" ? colors.crew : colors.fg;
        ctx.fillText(label, ox, oy);
      }
    };

    if (reduced) {
      const sim = simRef.current;
      if (sim) { while (sim.day < 365 * 20) stepSim(sim, 1); draw(); setStats(simStats(sim)); }
      return () => ro.disconnect();
    }

    let raf = 0;
    let visible = true;
    let last = performance.now();
    let acc = 0;
    let statAcc = 0;
    const io = new IntersectionObserver(([entry]) => { visible = Boolean(entry?.isIntersecting); last = performance.now(); });
    io.observe(canvas);
    const tick = (now: number) => {
      raf = requestAnimationFrame(tick);
      const dtSec = Math.min(0.1, (now - last) / 1000);
      last = now;
      const sim = simRef.current;
      if (!visible || !sim) return;
      const step = speedRef.current > 10 ? 1 : 0.5;
      acc += dtSec * (365 / 12) * speedRef.current; // 1x = one sim-year per 12 s
      while (acc >= step) { stepSim(sim, step); acc -= step; }
      draw();
      statAcc += dtSec;
      if (statAcc > 0.25) { statAcc = 0; setStats(simStats(sim)); }
    };
    raf = requestAnimationFrame(tick);
    return () => { cancelAnimationFrame(raf); ro.disconnect(); io.disconnect(); };
  }, []);

  const s = stats;
  const row = (label: string, seen: string, model: string, note?: string) => (
    <tr key={label}><td>{label}</td><td>{seen}{note ? <small> {note}</small> : null}</td><td>{model}</td></tr>
  );
  return (
    <div className="company-canvas-wrap">
      <div className="canvas-toolbar">
        <span>Run {runId} · Year {s?.year ?? 1}</span>
        <div>
          {[1, 10, 100].map((x) => <Button key={x} size="sm" variant={speed === x ? "default" : "outline"} onClick={() => setSpeed(x)}>{x}×</Button>)}
          <Button size="sm" variant="outline" onClick={() => { seedRef.current = newSeed(); setRunId((n) => n + 1); }}><RefreshCw className="size-3.5" /> Restart</Button>
        </div>
      </div>
      <canvas ref={canvasRef} className="company-canvas" aria-label="Animated replay: faint flashes never reach you; patched systems shrug off strikes; reached attacks face hardening and SOC before becoming small or large breaches" />
      <p className="canvas-note">Each run is one possible history. Big fires are rare: about 2% a year for a mid-size company at default settings. Restart to see another history; switch to 100× to see the averages.</p>
      <div className="canvas-legend">
        <span><i className="tree-dot" /> vendor system</span>
        <span><i className="patch-dot" /> your own code</span>
        <span><i className="vulnerable-dot" /> vulnerable system: blue ring = patch countdown (dashed = never patched)</span>
        <span><i className="ring-dot" /> patched in time</span>
        <span><Zap className="bolt-vuln" aria-hidden="true" /> orange bolt: vulnerability (patch race)</span>
        <span><Zap className="bolt-cred" aria-hidden="true" /> gold bolt: stolen credentials (MFA check; gold ring = stopped)</span>
        <span><Zap className="bolt-phish" aria-hidden="true" /> pink bolt: phishing (email / endpoint check; pink ring = stopped)</span>
        <span><Shield className="bolt-phish" aria-hidden="true" /> pink bolt: pretexting (identity / verification check)</span>
        <span><Sparkles className="spark-other" aria-hidden="true" /> grey spark: residual — other routes, errors &amp; insider misuse (model bucket)</span>
        <span><Shield className="blocked-symbol" aria-hidden="true" /> blocked by hardening: strike bounces off a wall</span>
        <span><ArrowUpRight className="missed-symbol" aria-hidden="true" /> faint flash, no ring: never reached you (not exposed / not targeted)</span>
        <span><Flame className="small-flame" aria-hidden="true" /> amber tiny flame: small breach, below reporting line</span>
        <span><Flame className="reported-flame" aria-hidden="true" /> red spreading fire: publicly known breach</span>
        <span><i className="burned-dot" /> burned, rebuilding</span>
        <span><i className="crew-dot" /> SOC crew: dashed line = racing to an incident</span>
        <span><i className="segment-dot" /> network segment walls (Isolation &amp; hardening)</span>
      </div>
      <p className="canvas-note reporting-note">Registries see only fires big enough to be reported. Below that line there are far more small ones: in US healthcare, about 100 small breaches for every reported one. A low chance of a reported breach does not mean a low chance of being hacked; what your forest decides is whether a strike stays small.</p>
      <p className="canvas-note">The healthcare count includes all causes, mostly errors; it is not the hacking-only reporting ratio used in this scenario.</p>
      {s && (
        <>
          <p className="canvas-funnel">
            {s.counts.strikes} strikes ({s.counts.bySource.vendor + s.counts.bySource.own} vulnerability · {s.counts.bySource.cred} credentials · {s.counts.bySource.phish} phishing · {s.counts.bySource.pretext} pretexting · {s.counts.bySource.other} other) → {s.counts.patched} hit patched systems · {s.counts.stopped} stopped by MFA / email checks · {s.counts.unreached} never reached you (not exposed / not targeted) · {s.counts.blocked} blocked by hardening · <b>{s.counts.contained + s.counts.small + s.counts.reported + s.counts.large} incidents:</b> {s.counts.contained} contained by SOC, {s.counts.small} small breaches, <b>{s.counts.reported + s.counts.large} reported breaches</b> ({s.counts.large} large)
          </p>
          <table className="canvas-compare">
            <thead><tr><th /><th>On the canvas</th><th>Formulas</th></tr></thead>
            <tbody>
              {(Object.keys(EVENT_LABELS) as (keyof typeof EVENT_LABELS)[]).map((key) => row(`${EVENT_LABELS[key]} / year`, s.years ? rate(s.rates[key].lambda) : "—", rate(result.rates[key].lambda)))}
              {row("Reported breach: chance this year", s.years ? pct(s.pYear) : "—", pct(result.pYear))}
              {row("Reported breach: chance within 5 years", s.windows ? pct(s.p5) : "—", pct(result.p5))}
              {row("Vulnerabilities' share of reported breaches", s.counts.reported + s.counts.large ? exactPct(s.vulnShare) : "—", pct(result.vulnShareOfTotal))}
              {row("Large share among reported breaches", s.counts.reported + s.counts.large ? exactPct(s.largeShare) : "—", pct(result.largeShare))}
            </tbody>
          </table>
          <p className="canvas-note">Strikes arrive at the model’s real yearly rate and every one runs the same funnel as the formulas, so the canvas column converges to the formula column. A few years are noisy — switch to 100× and watch it settle.</p>
        </>
      )}
    </div>
  );
}

function MyCompany() {
  const [c, setC] = useState<CompanyInputs>(DEFAULT_COMPANY);
  const r = useMemo(() => computeRisk(c), [c]);
  const range = useMemo(() => riskRange(c), [c]);
  const [showRange, setShowRange] = useState(true);
  const set = <K extends keyof CompanyInputs>(key: K, value: number) => setC((prev) => ({ ...prev, [key]: value }));
  const vendorGrowth = c.vendorGrowth ?? DEFAULT_COMPANY.vendorGrowth;
  const ai = aiAmplifiers(c);
  const scenarioResults = AI_SCENARIOS.map((scenario) => ({ scenario, result: computeRisk(applyAIScenario(c, scenario)) }));
  const toggleAdvanced = (enabled: boolean) => setC((prev) => {
    const a = aiAmplifiers(prev);
    return { ...prev, advancedAI: enabled, aiVuln: a.vuln, aiCred: a.cred, aiPhish: a.phish, aiEntry: a.entry };
  });

  const lanes = [
    { name: "Race 1 · vendor software", sub: `${Math.round(VENDOR_ZERO_DAY_SHARE * 100)}% zero-days, then your patch (${c.patchDays} d) vs CISA listing (median exploit delay: ${NDAY_MEDIAN_DAYS} days, n-day)`, ch: r.vendor },
    { name: "Race 2 · your own code", sub: `baseline attacker win share ${Math.round(OWN_BASE_ATTACKER_WIN * 100)}% (assumption), then attacker AI vs AppSec + bounty`, ch: r.own },
  ];
  const max = Math.max(0.01, r.vendor.lightning, r.own.lightning);
  const share = (a: number, b: number) => `${(b > 0 ? 100 * a / b : 0).toLocaleString("en-US", { maximumFractionDigits: 1 })}%`;
  const tail = (ch: CompanyResult["cred"]): [string, number][] => [
    [`Reached something that matters (${share(ch.reached, ch.winsRace)})`, ch.reached],
    [`Past hardening (${share(ch.pastHardening, ch.reached)})`, ch.pastHardening],
    [`Not contained → reported breach (${pct(ch.pastHardening > 0 ? ch.breaches / ch.pastHardening : 0)} = reported share × not contained)`, ch.breaches],
  ];
  const extraFunnels: { key: "cred" | "phish" | "pretext"; name: string; steps: [string, number][] }[] = [
    { key: "cred", name: "Credential abuse", steps: [["Stolen credentials tried on you", r.cred.lightning], [`Passed MFA (${share(r.cred.winsRace, r.cred.lightning)})`, r.cred.winsRace], ...tail(r.cred)] },
    { key: "phish", name: "Phishing", steps: [["Lures that reached a user", r.phish.lightning], [`Got past email & endpoint checks (${share(r.phish.winsRace, r.phish.lightning)})`, r.phish.winsRace], ...tail(r.phish)] },
    { key: "pretext", name: "Pretexting · calls, chat, help-desk tricks", steps: [["Pretexting attempts", r.pretext.lightning], [`Passed identity / verification (${share(r.pretext.winsRace, r.pretext.lightning)})`, r.pretext.winsRace], ...tail(r.pretext)] },
  ];
  const parts: Record<keyof typeof EVENT_LABELS, Record<keyof typeof CHANNEL_LABELS, number>> = {
    reached: { vuln: r.vendor.reached + r.own.reached, cred: r.cred.reached, phish: r.phish.reached, pretext: r.pretext.reached, other: 0 },
    incidents: { vuln: r.vendor.pastHardening + r.own.pastHardening, cred: r.cred.pastHardening, phish: r.phish.pastHardening, pretext: r.pretext.pastHardening, other: r.other.incidents },
    any: { vuln: r.vendor.anyBreaches + r.own.anyBreaches, cred: r.cred.anyBreaches, phish: r.phish.anyBreaches, pretext: r.pretext.anyBreaches, other: r.other.anyBreaches },
    reported: r.channels,
  };

  return (
    <section id="company" className="story-section">
      <SectionIntro number="01" question="Will lightning strike your company?">
        Every year some exploited vulnerabilities land on software you run — that’s the lightning. Then two races decide what happens. In vendor software, can you patch before the exploit arrives? In your own code, do you find the bug before attackers do? Stolen passwords and phishing lures are lightning too, checked first by your MFA and email defences. Whatever gets through still has to beat your hardening and your detection team. Set up your company and watch the odds.
      </SectionIntro>
      <CompanyCanvas inputs={c} result={r} />
      <div className="forest-layout">
        <div>
          <div className="preset-row">
            {Object.entries(COMPANY_PRESETS).map(([name, preset]) => <Button key={name} size="sm" variant="outline" onClick={() => setC((prev) => ({ ...preset, size: prev.size ?? "mid" }))}>{name}</Button>)}
          </div>
          <p className="preset-explainer">Vulnerabilities are one of five channels. Within them, at 40% in-house code patching matters most; at 80% in-house and attacker AI ×5 without AppSec, your own code takes over. Across all channels, identity (MFA) moves the total most.</p>
          <p className="controls-disclaimer">Controls are deliberate simplifications: each slider stands for a whole family of practices, and how much it helps is an assumption. Use them to compare, not to rate real products or programmes.</p>
          <div className="side-blocks defence-flow">
            <div className="ad-block" data-ch="all">
              <div className="ad-head"><span>All channels</span><small>applies to every channel</small></div>
            <div className="size-select" role="group" aria-label="Company size">
            <span>Company size</span>
            <div className="preset-row">
              {SIZE_OPTIONS.map(([key, label]) => <Button key={key} size="sm" variant={(c.size ?? "mid") === key ? "default" : "outline"} aria-pressed={(c.size ?? "mid") === key} onClick={() => setC((prev) => ({ ...prev, size: key }))}>{label}</Button>)}
            </div>
            <small>Mid-size is mapped to IRIS's 'typical organisation' baseline (9.3% a year, IRIS 2025, a conservative upper-bound estimate) as a modelling choice; small and very large use IRIS 2020 figures by size.</small>
          </div>
              <h4 className="channel-side-heading"><Zap aria-hidden="true" /> What comes at you</h4>
              <label className="ai-mode-toggle"><Switch checked={c.advancedAI ?? false} onCheckedChange={toggleAdvanced} aria-label="Advanced: set AI per channel" /><span>Advanced: set AI per channel</span></label>
              {!c.advancedAI ? <Control tag="Scenario assumption" label="Attacker AI" value={`×${c.threat.toFixed(1)}`} min={1} max={6} step={0.1} current={c.threat} onChange={(v) => set("threat", v)} icon={<Zap />} /> : null}
              <p className="channel-control-note ai-channel-effects" aria-live="polite">Vulnerabilities: exploits ×{Math.sqrt(ai.vuln).toFixed(1)} faster, own-code coverage ×{Math.sqrt(ai.vuln).toFixed(1)} and discovery pace ×{ai.vuln.toFixed(1)} · credentials ×{Math.pow(ai.cred, M_EXP_CRED).toFixed(1)} · phishing ×{Math.pow(ai.phish, M_EXP_PHISH).toFixed(1)} · after entry: hardening bypass ×{Math.pow(ai.entry, 0.3).toFixed(1)} (capped), SOC containment ÷{Math.pow(ai.entry, 0.3).toFixed(1)}. Scenario elasticities; other reported breaches stay fixed.</p>
            </div>
            <div className="ad-block" data-ch="vuln">
              <div className="ad-head"><span>Vulnerabilities · two races</span><b>{exactPct(r.channels.vuln / r.lambda)} of your breaches</b></div>
              <h4 className="channel-side-heading"><Zap aria-hidden="true" /> What comes at you</h4>
              <Control tag="Scenario assumption" label="Exploited vendor vulns in your stack / yr" value={`${c.vendorVulns}`} min={1} max={30} step={1} current={c.vendorVulns} onChange={(v) => set("vendorVulns", v)} icon={<Zap />} />
              <Control tag="Scenario assumption" note="Vulnpocalypse = more exploited vendor bugs, not more CVEs. The data so far: CVEs ×3, exploitation flat. This slider changes only the vulnerability channel; everything else stays as it is." label="Vendor exploitation growth" value={`×${vendorGrowth.toFixed(1)}`} min={1} max={3} step={0.1} current={vendorGrowth} onChange={(v) => set("vendorGrowth", v)} icon={<Zap />} />
               {c.advancedAI ? <Control tag="Scenario assumption" note="Exploit speed and own-code coverage/pace inside the two races." label="Vulnerabilities AI amplifier" value={`×${ai.vuln.toFixed(1)}`} min={1} max={6} step={0.1} current={ai.vuln} onChange={(v) => set("aiVuln", v)} icon={<Zap />} /> : null}
               <Control tag="Scenario assumption" note="AI makes probing custom code cheap, so attackers try it more often. ×1 = today's attention." label="Attacker focus on your own code" value={`×${(c.ownFocus ?? 1).toFixed(1)}`} min={1} max={5} step={0.1} current={c.ownFocus ?? 1} onChange={(v) => set("ownFocus", v)} icon={<Zap />} />
               <h4 className="channel-side-heading"><Shield aria-hidden="true" /> What you control</h4>
               <Control tag="Scenario assumption" note="Your own code looks safer today mostly because fewer attackers look at it. Raise attacker focus or attacker AI to see what happens when they do." label="Built in-house vs vendors" value={`${Math.round(c.inHouse * 100)}% / ${Math.round((1 - c.inHouse) * 100)}%`} min={0} max={1} step={0.05} current={c.inHouse} onChange={(v) => set("inHouse", v)} icon={<Shield />} />
              <Control tag="Observed: Verizon DBIR 2026, KEV remediation median, default 43 d" label="Days to patch (median)" value={`${c.patchDays} days`} min={1} max={180} step={1} current={c.patchDays} onChange={(v) => set("patchDays", v)} icon={<Shield />} />
              <Control tag="Scenario assumption" label="Share of affected systems never patched (assumption)" value={`${Math.round(c.neverPatched * 100)}%`} min={0} max={0.6} step={0.01} current={c.neverPatched} onChange={(v) => set("neverPatched", v)} icon={<Shield />} />
              <Control tag="Scenario assumption" label="AI SAST / DAST" value={APPSEC_LABELS[c.appsec] ?? ""} min={0} max={3} step={1} current={c.appsec} onChange={(v) => set("appsec", v)} icon={<Shield />} />
              <Control tag="Scenario assumption: bounty curve" label="Bug bounty budget" value={c.bountyK ? `$${c.bountyK}k / year` : "none"} min={0} max={1000} step={25} current={c.bountyK} onChange={(v) => set("bountyK", v)} icon={<Shield />} />
            </div>
            <div className="ad-block" data-ch="cred">
              <div className="ad-head"><span>Credential abuse</span><b>{exactPct(r.channels.cred / r.lambda)} of your breaches</b></div>
              <h4 className="channel-side-heading"><Zap aria-hidden="true" /> What comes at you</h4>
              <Control tag="Scenario assumption" note="How often your users’ credentials leak — infostealer logs, password reuse, breaches elsewhere." label="Credential exposure" value={`×${(c.credentialExposure ?? 1).toFixed(1)}`} min={0.5} max={3} step={0.1} current={c.credentialExposure ?? 1} onChange={(v) => set("credentialExposure", v)} icon={<Zap />} />
              {c.advancedAI ? <Control tag="Scenario assumption" note={`Incoming credential attempts ×a^0.3 = ×${Math.pow(ai.cred, M_EXP_CRED).toFixed(1)}.`} label="Stolen credentials AI amplifier" value={`×${ai.cred.toFixed(1)}`} min={1} max={6} step={0.1} current={ai.cred} onChange={(v) => set("aiCred", v)} icon={<Zap />} /> : null}
              <h4 className="channel-side-heading"><Shield aria-hidden="true" /> What you control</h4>
              <Control tag="Scenario assumption: credentials ×1.6/1/0.4/0.15, phishing ×1.3/1/0.7/0.35, pretexting ×1.2/1/0.8/0.6" label="Identity" value={IDENTITY_LABELS[c.identity ?? 1] ?? ""} min={0} max={3} step={1} current={c.identity ?? 1} onChange={(v) => set("identity", v)} icon={<Shield />} />
              <Control tag="Scenario assumption · shared with Phishing" note="Fewer infostealers on managed devices: credentials ×1.15 / ×1 / ×0.8. Device coverage also feeds EDR." label="Device management & BYOD" value={`${DEVICE_LABELS[c.deviceManagement ?? 1]} · ${exactPct(DEVICE_COVERAGE[c.deviceManagement ?? 1] ?? 0.75)} coverage`} min={0} max={2} step={1} current={c.deviceManagement ?? 1} onChange={(v) => set("deviceManagement", v)} icon={<Shield />} />
            </div>
            <div className="ad-block" data-ch="phish">
              <div className="ad-head"><span>Social engineering · phishing & pretexting</span><b>{exactPct((r.channels.phish + r.channels.pretext) / r.lambda)} of your breaches</b></div>
              <h4 className="channel-side-heading"><Zap aria-hidden="true" /> What comes at you</h4>
              <Control tag="Scenario assumption" note="How hard you are targeted — sector, brand, size." label="Phishing pressure" value={`×${(c.phishingPressure ?? 1).toFixed(1)}`} min={0.5} max={3} step={0.1} current={c.phishingPressure ?? 1} onChange={(v) => set("phishingPressure", v)} icon={<Zap />} />
              {c.advancedAI ? <Control tag="Scenario assumption" note={`Incoming phishing lures ×a^0.5 = ×${Math.pow(ai.phish, M_EXP_PHISH).toFixed(1)}.`} label="Phishing AI amplifier" value={`×${ai.phish.toFixed(1)}`} min={1} max={6} step={0.1} current={ai.phish} onChange={(v) => set("aiPhish", v)} icon={<Zap />} /> : null}
              <h4 className="channel-side-heading"><Shield aria-hidden="true" /> What you control</h4>
              <p className="channel-control-note">Identity also affects phishing. Pretexting (calls, chat, help-desk tricks) has a separate rate: Identity ×1.2 / ×1 / ×0.8 / ×0.6, then hardening and SOC. Email filtering, training and EDR do not affect pretexting.</p>
              <Control tag="Scenario assumption" label="Email filtering" value={FILTERING_LABELS[c.emailFiltering ?? 1] ?? ""} min={0} max={2} step={1} current={c.emailFiltering ?? 1} onChange={(v) => set("emailFiltering", v)} icon={<Shield />} />
              <Control tag="Scenario assumption" note="Evidence for training is weak (UCSD Health trial, 19,500 employees); technical controls do more." label="Awareness & training" value={TRAINING_LABELS[c.training ?? 1] ?? ""} min={0} max={2} step={1} current={c.training ?? 1} onChange={(v) => set("training", v)} icon={<Shield />} />
              <Control tag="Scenario assumption · effectiveness 0 / 0.2 / 0.5 / 0.65" note={`Phishing ×${endpointMultiplier(c.edr ?? 1, c.deviceManagement ?? 1).toFixed(2)} = (1 − effectiveness × coverage) / (1 − 0.2 × 0.75).`} label="EDR" value={EDR_LABELS[c.edr ?? 1] ?? ""} min={0} max={3} step={1} current={c.edr ?? 1} onChange={(v) => set("edr", v)} icon={<Shield />} />
              <Control tag="Scenario assumption · shared with Stolen credentials" note="Coverage feeds EDR; this same setting also scales stolen-credential risk." label="Device management & BYOD" value={`${DEVICE_LABELS[c.deviceManagement ?? 1]} · ${exactPct(DEVICE_COVERAGE[c.deviceManagement ?? 1] ?? 0.75)} coverage`} min={0} max={2} step={1} current={c.deviceManagement ?? 1} onChange={(v) => set("deviceManagement", v)} icon={<Shield />} />
            </div>
            <div className="ad-block" data-ch="other">
              <div className="ad-head"><span>Residual: other routes, errors &amp; insider misuse (model bucket) · fixed</span><b>{exactPct(r.channels.other / r.lambda)} of your breaches</b></div>
              <h4 className="channel-side-heading"><Zap aria-hidden="true" /> What comes at you</h4>
              <p className="channel-control-note">Residual: other routes, errors &amp; insider misuse (model bucket) · {rate(r.channels.other)} reported breaches / yr.</p>
              <h4 className="channel-side-heading"><Shield aria-hidden="true" /> What you control</h4>
              <p className="channel-control-note">No channel-specific controls here. The publicly known rate is fixed for the selected company size.</p>
              <p className="channel-control-note">The first four shares are Verizon's; the residual is created by this model so the total matches the IRIS baseline. Verizon's shares exclude error and misuse breaches.</p>
            </div>
            <div className="ad-block" data-ch="all" data-common="true">
              <div className="ad-head"><span>Common defences — after the attacker is in</span></div>
              {c.advancedAI ? <Control tag="Scenario assumption" note="Hardening bypass and SOC outpacing across the attack channels." label="After entry AI amplifier" value={`×${ai.entry.toFixed(1)}`} min={1} max={6} step={0.1} current={ai.entry} onChange={(v) => set("aiEntry", v)} icon={<Zap />} /> : null}
              <Control tag="Scenario assumption: h_H, q_H" note="Firebreaks · segmentation, least privilege, blocks lateral movement." label="Isolation & hardening" value={HARDENING_LABELS[c.hardening] ?? ""} min={0} max={4} step={1} current={c.hardening} onChange={(v) => set("hardening", v)} icon={<Shield />} />
              <Control tag="Calibrated: c_S" note="Firefighters · detect, respond and contain." label="Detect & respond (SOC)" value={SOC_LABELS[c.soc] ?? ""} min={0} max={3} step={1} current={c.soc} onChange={(v) => set("soc", v)} icon={<Shield />} />
              <Control tag="Scenario assumption: g_G" note="Fuel · less fuel — size only." label="Data governance / privacy" value={GOV_LABELS[c.governance] ?? ""} min={0} max={3} step={1} current={c.governance} onChange={(v) => set("governance", v)} icon={<Shield />} />
            </div>
            <div className="ad-block" data-ch="all">
              <div className="ad-head"><span>Reporting assumption</span></div>
              <Control tag="Scenario assumption (no public data for hacking alone; HHS small-breach reports are mostly errors, not hacking)" label="Small breaches below the reporting line" value={`${Math.round((c.smallBreachShare ?? 0.7) * 100)}% · r = ${exactPct(r.reportedShare)} reported`} min={0.4} max={0.9} step={0.01} current={c.smallBreachShare ?? 0.7} onChange={(v) => set("smallBreachShare", v)} icon={<Flame />} />
            </div>
          </div>
          <div className="channel-funnels">
            <div className="funnel-group" data-ch="vuln">
              <div className="funnel-group-head"><strong>Vulnerability channel: two races</strong><b>{exactPct(r.channels.vuln / r.lambda)} of your breaches</b></div>
          <div className="race-lanes">
            {lanes.map(({ name, sub, ch }, lane) => (
              <div key={name} className="race-lane">
                <div className="race-head"><strong>{name}</strong><small>{sub}</small></div>
                {[
                  ["Lightning hits you", ch.lightning],
                  [lane === 0 ? `Exploited before you patch (${pct(ch.raceP)})` : `Attacker finds it first and it stays open (×${ch.raceP.toFixed(2)} vs no AppSec)`, ch.winsRace],
                  [`Reached you (${(ch.winsRace > 0 ? 100 * ch.reached / ch.winsRace : 0).toLocaleString("en-US", { maximumFractionDigits: 1 })}%)`, ch.reached],
                  [`Past hardening (${(ch.reached > 0 ? 100 * ch.pastHardening / ch.reached : 0).toLocaleString("en-US", { maximumFractionDigits: 1 })}%)`, ch.pastHardening],
                  [`Not contained → reported breach (${pct(ch.pastHardening > 0 ? ch.breaches / ch.pastHardening : 0)} = reported share × not contained)`, ch.breaches],
                ].map(([label, value]) => (
                  <div key={label as string} className="race-row">
                    <span>{label}</span>
                    <div className="race-bar"><i style={{ width: `${Math.max(0.5, (value as number) / max * 100)}%` }} /></div>
                    <b>{rate(value as number)}/yr</b>
                  </div>
                ))}
              </div>
            ))}
            <p className="race-scale-note">Each channel's bars use its own scale; the rates on the right are comparable.</p>
            </div>
            {extraFunnels.map(({ key, name, steps }) => {
              const fmax = Math.max(0.01, ...steps.map(([, v]) => v));
              return (
                <div key={key} className="funnel-group" data-ch={key}>
                  <div className="funnel-group-head"><strong>{name}</strong><b>{exactPct(r.channels[key] / r.lambda)} of your breaches</b></div>
                  {steps.map(([label, value]) => (
                    <div key={label} className="race-row">
                      <span>{label}</span>
                      <div className="race-bar"><i style={{ width: `${Math.max(0.5, value / fmax * 100)}%` }} /></div>
                      <b>{rate(value)}/yr</b>
                    </div>
                  ))}
                </div>
              );
            })}
            <div className="funnel-group" data-ch="other">
              <div className="funnel-group-head"><strong>Residual: other routes, errors &amp; insider misuse (model bucket)</strong><b>{rate(r.channels.other)}/yr · fixed · {exactPct(r.channels.other / r.lambda)} of your breaches</b></div>
            </div>
            <p className="channel-sum">Channels add up to your total: {rate(r.channels.vuln)} + {rate(r.channels.cred)} + {rate(r.channels.phish)} + {rate(r.channels.pretext)} + {rate(r.channels.other)} = {rate(r.lambda)} / yr</p>
          </div>
          </div>
          <p className="patch-note">KEV listing is an upper bound on when exploitation starts; real attacks often start earlier. Observed (CVEs published 2023–2025 in CISA KEV, snapshot 30 Sep 2026, n = 522): 31% were listed on or before publication day (zero-days; 95% interval 28–36%, Beta posterior). 19% (17–21%) for all KEV entries added since 2022. The rest took a median 36 days (n = 358).</p>
        </div>
        <aside className="forest-stats">
          <div className="ai-scenario-strip" role="group" aria-label="AI scenario comparison">
            <p className="scenario-heading">Publicly known breach chance this year · your current defences</p>
            <div className="ai-scenario-options">
              {scenarioResults.map(({ scenario, result }) => <Button key={scenario.id} variant={isAIScenario(c, scenario) ? "default" : "outline"} aria-pressed={isAIScenario(c, scenario)} onClick={() => setC((prev) => applyAIScenario(prev, scenario))} className="ai-scenario-option">
                <span>{scenario.label}</span><strong>{(result.pYear * 100).toFixed(1)}%</strong>
                <small>{scenario.id === "today" ? "AI ×1 · k_v ×1" : scenario.id === "vulnpocalypse" ? "k_v ×2.2 · AI ×1" : scenario.id === "phishing" ? "Phishing amplifier ×6 only" : "Master AI ×6 · k_v ×2.2"}</small>
                {scenario.id === "vulnpocalypse" ? <small>Vulnerabilities {Math.round(result.vulnShareOfTotal * 100)}%</small> : scenario.id === "phishing" ? <small>Phishing {Math.round(result.channels.phish / result.lambda * 100)}%</small> : null}
              </Button>)}
            </div>
            <p className="scenario-question">Which matters more for you — more exploited bugs or better phishing? With today's defaults they weigh about the same; your defences decide which one dominates.</p>
          </div>
          <p className="patch-note">Only the top line is anchored to data (IRIS); the channel mix follows DBIR 2026; everything below the top line follows from model assumptions.</p>
          <div className="results-grid" aria-label="Company risk results">
            <div className="results-title">All causes</div>
            <div className="results-head"><span>Outcome</span><span>Rate / yr</span><span>Chance this year</span><span>Within 5 years</span></div>
            {(Object.keys(EVENT_LABELS) as (keyof typeof EVENT_LABELS)[]).map((key) => (
              <div className="results-row" key={key} data-reported={key === "reported"}>
                <b>{EVENT_LABELS[key]}</b><strong>{rate(r.rates[key].lambda)}</strong><strong>{pct(r.rates[key].pYear)}</strong>
                <strong>{pct(r.rates[key].p5)}{key === "reported" && showRange ? <small> {pct(range.p5[0])}–{pct(range.p5[1])}</small> : null}</strong>
                <div className="channel-bar row-bar" aria-hidden="true">{(Object.keys(CHANNEL_LABELS) as (keyof typeof CHANNEL_LABELS)[]).map((k) => <i key={k} data-ch={k} style={{ width: `${100 * parts[key][k] / Math.max(1e-12, r.rates[key].lambda)}%` }} />)}</div>
              </div>
            ))}
          </div>
          <p className="patch-note">Calibrated to Cyentia IRIS: annual chance of a publicly known cyber event for an organisation of this size. The definition and denominator matter: per-entity rates across all HIPAA-covered organisations, most of them tiny, are far lower.</p>
          <div className="channel-breakdown" aria-label="Where your breaches come from">
            <span>Where your publicly known breaches come from · all causes</span>
            <div className="channel-bar">{(Object.keys(CHANNEL_LABELS) as (keyof typeof CHANNEL_LABELS)[]).map((k) => <i key={k} data-ch={k} style={{ width: `${100 * r.channels[k] / r.lambda}%` }} />)}</div>
            <ul>{(Object.keys(CHANNEL_LABELS) as (keyof typeof CHANNEL_LABELS)[]).map((k) => <li key={k}><i data-ch={k} />{CHANNEL_LABELS[k]} <b>{exactPct(r.channels[k] / r.lambda)}</b> · {rate(r.channels[k])}/yr</li>)}</ul>
            <p><b>Vulnerabilities' share of your breaches: {exactPct(r.vulnShareOfTotal)}</b>. Defaults follow Verizon DBIR 2026 “Select initial access vectors in non-Error, non-Misuse breaches” (data 1 Nov 2024 – 31 Oct 2025): vulnerabilities 31%, phishing 16%, pretexting 6%, credential abuse 13%. The model residual is 34%. The first four shares are Verizon's; the residual is created by this model so the total matches the IRIS baseline. Verizon's shares exclude error and misuse breaches. Phishing and pretexting are separate in the maths, sharing the Social engineering colour group. AI scales phishing by a<sub>phish</sub><sup>0.5</sup> and credentials by a<sub>cred</sub><sup>0.3</sup>; pretexting receives only the modest Identity multiplier and common hardening/SOC gates. The residual publicly known rate stays fixed.</p>
          </div>
          <p className="patch-note">DBIR 2026 data end in October 2025, before the 2026 CVE surge.</p>
          <Button type="button" variant="ghost" size="sm" className="range-toggle" onClick={() => setShowRange((v) => !v)}>Assumptions range: {showRange ? "on" : "off"}</Button>
          <p className="patch-note">Reported rate: vendor {rate(r.vendor.breaches)} · own {rate(r.own.breaches)} · credentials {rate(r.cred.breaches)} · phishing {rate(r.phish.breaches)} · pretexting {rate(r.pretext.breaches)} · residual {rate(r.other.breaches)} / yr. Large share among reported breaches: {pct(r.largeShare)}; chance of a large reported breach within 5 years: {pct(r.pLarge5)}.</p>
          <div className="all-cause-check reality-check">
            <span>Reality check · model vs data</span>
            <p><b>Publicly known significant cyber events, all causes</b>: model {pct(r.pYear)} / yr vs Cyentia IRIS {pct(IRIS_TARGET[(c.size ?? "mid")])}.</p>
            <p><b>Attacks via vulnerabilities, credential abuse, phishing and pretexting</b>: model {pct(r.rates.reached.pYear)} / yr vs UK Cyber Security Breaches Survey 2025/26 {UK_ATTACK_TARGET[(c.size ?? "mid")]}. The survey also counts blocked phishing attempts, so it should be higher.</p>
            <p>Scenario check, not a validation.</p>
            {(c.size ?? "mid") === "small" ? <p>Credentials and phishing use the DBIR mix for all sizes; small firms are attacked mostly by phishing, so the model likely understates their attack rate.</p> : null}
          </div>
          {r.saturated ? <p className="range-note">Scenario limit: reach and hardening probabilities are capped at 100%. At these extreme settings the reported rate need not equal the earlier combined-gate model.</p> : null}
          <p className="framing-note">Read these as comparisons between settings, not as a forecast of your company's real breach probability. The shape comes from data; the levels depend on calibration and assumptions.</p>
          <p className="range-note">Range: Low = z<sub>v</sub> 0.19, e × 0.5, elasticities 0; High = z<sub>v</sub> 0.31, e × 2, elasticities 1 / 1 / 0.5 / 0.5. The "never patched" share always follows your slider. The level mostly comes from calibration (e) and, for attacker AI, from the elasticities; the shape comes from the data. Compare settings, not single numbers.</p>
          <div className="formula-box">
            <p><span><b>λ total</b> = λ<sub>vuln</sub> + λ<sub>cred</sub> + λ<sub>phish</sub> + λ<sub>pretext</sub> + λ<sub>residual</sub> = {rate(r.channels.vuln)} + {rate(r.channels.cred)} + {rate(r.channels.phish)} + {rate(r.channels.pretext)} + {rate(r.channels.other)} = {rate(r.lambda)}</span></p>
            <p><span><b>λ<sub>vuln</sub></b> = (L<sub>v</sub>·p<sub>v</sub> + L<sub>o</sub>·R<sub>o</sub>)·e<sub>reach</sub>·h·(1−c<sub>eff</sub>)·r</span></p>
            <p><span>e<sub>reach</sub> = min(1, e/r) = {exactPct(r.reachProbability)}; r = {exactPct(r.reportedShare)}</span></p>
            <p><span>m = a<sub>vuln</sub> = ×{ai.vuln.toFixed(1)} inside the races; a<sub>entry</sub> = ×{ai.entry.toFixed(1)} after entry. With advanced mode off, all amplifiers follow master m.</span></p>
            <p><span>h = min(1, h<sub>H</sub>·a<sub>entry</sub><sup>0.3</sup>) = {exactPct(r.hardeningProbability)}</span></p>
            <p><span>c<sub>eff</sub> = c<sub>S</sub>/a<sub>entry</sub><sup>0.3</sup> ∈ [0, c<sub>S</sub>]</span></p>
            <p><span>L<sub>v</sub> = N<sub>v</sub>·(1−f)·k<sub>v</sub>, k<sub>v</sub> = ×{vendorGrowth.toFixed(1)}</span></p>
            <p><span>F = Σ share<sub>i</sub>·0.5<sup>(days<sub>i</sub>/m<sup>0.5</sup>)/D<sub>p</sub></sup> (8 observed n-day bins)</span></p>
            <p><span>p<sub>v</sub> = z<sub>v</sub> + (1−z<sub>v</sub>)·[u + (1−u)·F] = {r.vendor.raceP.toFixed(2)} (Derived)</span></p>
            <p><span>L<sub>o</sub> = N<sub>o</sub>·f·m<sup>0.5</sup> = {r.own.lightning.toFixed(2)}</span></p>
            <p><span>s<sub>o</sub> = m·z<sub>o</sub> / (m·z<sub>o</sub> + D·(1−z<sub>o</sub>))</span></p>
            <p><span>z<sub>o</sub> = {OWN_BASE_ATTACKER_WIN.toFixed(2)} (assumption; article uses 0.19)</span></p>
            <p><span>R<sub>o</sub> = (s<sub>o</sub>/z<sub>o</sub>) / D = ×{r.own.raceP.toFixed(2)} vs no AppSec (Derived)</span></p>
            <p><span>λ<sub>0</sub> = λ at k<sub>v</sub> = 1 and m = 1 = {rate(r.lambdaBaseline)}</span></p>
            <p><span>λ incidents = λ reached · h; λ any = λ incidents · (1−c<sub>eff</sub>)</span></p>
            <p><span>P(any incident, all causes) = 1 − exp(−λ incidents / s), s ∈ [0.12, 0.31]</span></p>
            <p><span>P(year) = 1 − e<sup>−λ</sup> = {pct(r.pYear)}</span></p>
          </div>
          <div className="formula-box">
            <p><span><b>Labels</b></span></p>
            <p><span>Observed: z<sub>v</sub> = 0.31, 95% interval 0.28–0.36 (Beta posterior, n = 522)</span></p>
            <p><span>19% (17–21%) for all KEV entries added since 2022</span></p>
            <p><span>Observed: n-day bins (CISA KEV, CVEs 2023–2025); D<sub>p</sub> 43 d (Verizon DBIR 2026); s 12–31% (EuRepoC; DBIR 2026)</span></p>
            <p><span>Calibrated: e ≈ 0.0075 / 0.0361 / 0.1061 (small / mid-size / very large); full-precision e = {calibratedExposure(c.size ?? "mid").toFixed(6)}. λ target = −ln(1 − p<sub>IRIS</sub>); c<sub>S</sub></span></p>
            <p><span>Scenario assumption: r (no public data for hacking alone; HHS small-breach reports are mostly errors, not hacking)</span></p>
            <p><span>Scenario assumption: u, N<sub>o</sub>, r<sub>A</sub>, bounty curve, h<sub>H</sub>, g<sub>G</sub>, q<sub>H</sub>, z<sub>o</sub>, all m elasticities</span></p>
            <p><span>Derived: λ, p<sub>v</sub>, R<sub>o</sub>, all outputs</span></p>
          </div>
          <div className="formula-box">
            <p><span><b>Assumptions</b> — scenario elasticities (not measured)</span></p>
             <p><span>coverage of own code: L<sub>own</sub> = N<sub>o</sub> · f · focus · m<sup>{(c.advancedAI ? c.ownFocusElasticity ?? 0.5 : 0.5).toFixed(2)}</sup> (more targets and code examined)</span></p>
             {c.advancedAI ? <Control tag="Scenario assumption" note="0.5 = attention grows slower than attacker speed; 1 = in proportion" label="Own-code focus elasticity" value={(c.ownFocusElasticity ?? 0.5).toFixed(2)} min={0} max={1} step={0.05} current={c.ownFocusElasticity ?? 0.5} onChange={(v) => set("ownFocusElasticity", v)} icon={<Zap />} /> : null}
            <p><span>pace in the own-code discovery race: m in s<sub>o</sub> (separate from coverage)</span></p>
            <p><span>exploit from patch: n-day delays / m<sup>0.5</sup></span></p>
            <p><span>hardening bypass: m<sup>0.3</sup></span></p>
            <p><span>outpacing the SOC: c<sub>S</sub>/m<sup>0.3</sup></span></p>
            <p><span><b>Mechanisms</b></span></p>
            <p><span>D appears twice on purpose: defender speed decides who finds a bug first</span></p>
            <p><span>AND how long an attacker-found bug stays open; a bug is fixed as soon as the defender finds it.</span></p>
            <p><span>Bounds: h ≤ 1; c<sub>eff</sub> ∈ [0, c<sub>S</sub>]; p<sub>v</sub>, s ∈ [0, 1]; R<sub>o</sub> is a ratio and can exceed 1.</span></p>
          </div>
          <div className="caption-stack">
            <p>Vendors and outside researchers, increasingly with AI, find bugs in vendor software. Vendor exploitation is about ×1 in the data so far. Move it toward ×2.2 to play the article’s vendor vulnpocalypse scenario; patching still helps, but zero-days remain.</p>
            <p>Matching attackers’ AI only holds your own-code risk steady; hardening and the SOC decide the rest.</p>
            <p>Segmentation and a SOC cut both how often and how big; data governance only how big.</p>
            <p>The rates here are illustrative assumptions, not measured. The point is the shape: two races, then your controls.</p>
          </div>
        </aside>
      </div>
    </section>
  );
}

function Control({ label, value, min, max, step, current, onChange, icon, tag, note }: { tag?: string; note?: string; label: string; value: string; min: number; max: number; step: number; current: number; onChange: (value: number) => void; icon: React.ReactNode }) {
  return (
    <label className="control">
      <span className="control-label"><span>{icon}{label}</span><strong>{value}</strong></span>
      {tag ? <small className="control-tag">{tag}</small> : null}
      <Slider min={min} max={max} step={step} value={[current]} onValueChange={([next]) => onChange(next ?? current)} />
      {note ? <small className="control-tag">{note}</small> : null}
    </label>
  );
}

const REAL_DATA = [
  { x: 1, healthcare: 100 },
  { x: 3, healthcare: 48.9 },
  { x: 10, healthcare: 17.7 },
  { x: 30, healthcare: 5.4 },
  { x: 100, healthcare: 1.13 },
  { x: 300, healthcare: 0.28 },
  { x: 1000, healthcare: 0.14 },
];
const LOSS_DATA = [{ x: 1, losses: 100 }, { x: 10, losses: 18.8 }, { x: 100, losses: 4.2 }];
// Theoretical guides are separate from measured series; never fill missing observations.
const REFERENCE_DATA = [1, 2, 10, 20, 100, 200, 1000].map((x) => ({ x, reference: 100 / x, insurance: 100 * Math.pow(x, -0.74) }));

const INSURANCE_LABEL = "Insurance claims, multi-victim events (Henderson et al., 2026): ×10 larger → 5.5× rarer";

const GIANTS = [
  [1927, 0.141, "Change Healthcare · 192.7M · 2024"],
  [622, 0.283, "Conduent · 62.2M · 2025"], [150, 0.424, "DentaQuest · 15.0M · 2026"],
  [148, 0.566, "Welltok · 14.8M · 2023 · MOVEit"], [139, 0.707, "Aflac · 13.9M · 2025"],
  [115, 0.849, "Optum360 · 11.5M · 2019"], [113, 0.990, "HCA Healthcare · 11.3M · 2023"],
  [103, 1.132, "LabCorp · 10.3M · 2019"],
].map(([x, y, name]) => ({ x: Number(x), y: Number(y), name: String(name), z: 60 }));

function RealData() {
  const [ruler, setRuler] = useState(10);
  return (
    <section id="data" className="story-section">
      <SectionIntro number="02" question="Does the real world leave the same fingerprint?">
        Put breach size on one logarithmic axis and rarity on the other. A straight-ish line is consistent with a power law; a lognormal curve fits these data about as well.
      </SectionIntro>
      <div className="real-chart-wrap">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={REAL_DATA} margin={{ top: 24, right: 18, bottom: 30, left: 10 }}>
            <CartesianGrid stroke="var(--grid)" />
            <XAxis dataKey="x" type="number" scale="log" domain={[1, 2000]} ticks={[1, 10, 100, 1000]} tickFormatter={(v) => `×${v}`} label={{ value: "Times larger than starting size", position: "bottom", offset: 12 }} />
            <YAxis type="number" scale="log" domain={[0.1, 100]} ticks={[0.1, 1, 10, 100]} tickFormatter={(v) => `${v}%`} width={46} />
            <Line data={REFERENCE_DATA} dataKey="reference" name="1/x" stroke="var(--muted-foreground)" strokeDasharray="7 7" dot={false} isAnimationActive={false} />
            <Line data={REFERENCE_DATA} dataKey="insurance" name={INSURANCE_LABEL} stroke="var(--tree)" strokeWidth={2} strokeDasharray="2 5" dot={false} isAnimationActive={false} />
            <Line data={REAL_DATA} type="linear" dataKey="healthcare" name="US healthcare · people (HHS)" stroke="var(--fire)" strokeWidth={3} dot={{ r: 4 }} isAnimationActive={false} />
            <Line data={LOSS_DATA} type="linear" dataKey="losses" name="All sectors · losses (EuRepoC)" stroke="var(--data-cool)" strokeWidth={3} dot={{ r: 4 }} isAnimationActive={false} />
            <Scatter data={GIANTS} name="Named giants" fill="var(--ink)" dataKey="y" shape="diamond" />
            <ZAxis dataKey="z" range={[50, 50]} />
            <ReferenceLine x={ruler} stroke="var(--ink)" strokeWidth={2} label={{ value: `×${ruler}`, fill: "var(--ink)", position: "insideTopRight" }} />
            <Tooltip content={({ active, payload }) => {
              if (!active || !payload?.length) return null;
              const named = payload.find((entry) => entry.payload?.name)?.payload;
               if (named) return <div className="chart-tooltip"><strong>{named.name}</strong><p>×{named.x} · {Number(named.y).toFixed(3)}% at least this large</p></div>;
               return <div className="chart-tooltip">{payload.filter((entry) => entry.value != null).map((entry) => <p key={String(entry.dataKey)}><strong>{entry.name}</strong> {Number(entry.value).toLocaleString("en-US", { maximumFractionDigits: 3 })}%</p>)}</div>;
            }} />
          </ComposedChart>
        </ResponsiveContainer>
      </div>
      <div className="legend-row"><span><i className="legend-fire" />US healthcare, from 100k people (HHS; n = 707; 2016–15 Sep 2026)</span><span><i className="legend-cool" />All sectors, from $10M loss (EuRepoC; n = 48; ends at $1B)</span><span><i className="legend-dash" />1/x guide</span><span><i className="legend-insurance" />{INSURANCE_LABEL}</span></div>
      <p className="patch-note">Three different sources — people affected (HHS registry), dollars lost (EuRepoC), organisations hit — show much the same tail.</p>
      <label className="ruler-control">
        <span><strong>Drag the ruler</strong><b>{ruler}× bigger → about {ruler}× rarer</b></span>
        <Slider min={0} max={3} step={1} value={[[1, 10, 100, 1000].indexOf(ruler)]} onValueChange={([index]) => {
          const next = [1, 10, 100, 1000][index ?? 1];
          if (next !== undefined) setRuler(next);
        }} />
      </label>
    </section>
  );
}

const CONCENTRATION = [
  [0.1, 22], [0.25, 31], [0.5, 42], [1, 57], [2, 67], [5, 79], [10, 88], [20, 94],
] as const;

function concentrationAt(x: number) {
  for (let i = 0; i < CONCENTRATION.length - 1; i += 1) {
    const lower = CONCENTRATION[i]; const upper = CONCENTRATION[i + 1];
    if (!lower || !upper) continue;
    const [x1, y1] = lower; const [x2, y2] = upper;
    if (x >= x1 && x <= x2) return y1 + ((x - x1) / (x2 - x1)) * (y2 - y1);
  }
  return 94;
}

function OnePercent() {
  const [top, setTop] = useState(1);
  const share = concentrationAt(top);
  return (
    <section id="one-percent" className="story-section concentration-section">
      <SectionIntro number="03" question="How much can the biggest 1% decide?">
        Choose a thin slice of the largest breaches. Then see how much of the human impact sits inside it.
      </SectionIntro>
      <div className="concentration-viz">
        <div className="big-answer"><span>Top {top < 1 ? top.toFixed(1) : top.toFixed(top % 1 ? 1 : 0)}% of breaches account for</span><strong>{Math.round(share)}%</strong><span>of all people affected</span></div>
        <div className="share-bar" aria-label={`${Math.round(share)} percent of people affected`}><div style={{ width: `${share}%` }} /></div>
        <label className="wide-control"><span>top X% of breaches</span><Slider min={0.1} max={20} step={0.1} value={[top]} onValueChange={([value]) => setTop(value ?? top)} /></label>
        <div className="range-labels"><span>0.1%</span><Button variant="outline" size="sm" onClick={() => setTop(1)}>Snap to 1%</Button><span>20%</span></div>
      </div>
      <aside className="fact-strip"><span className="fact-number">22%</span><p>The single largest breach — Change Healthcare — accounts for <strong>22% of all people counted in reported US healthcare hacking breaches, 2016 to 15 Sep 2026</strong> (one person can be counted more than once).</p></aside>
    </section>
  );
}

type FuturePoint = { future: number; year: number; size: number };

function poisson(lambda: number, rng: Rng) {
  const limit = Math.exp(-lambda);
  let product = 1; let count = 0;
  do { count += 1; product *= rng(); } while (product > limit);
  return count - 1;
}

function FuturesCanvas({ points }: { points: FuturePoint[] }) {
  const ref = useRef<HTMLCanvasElement>(null);
  useEffect(() => {
    const canvas = ref.current; if (!canvas) return;
    const ctx = canvas.getContext("2d"); if (!ctx) return;
    const width = canvas.clientWidth; const height = canvas.clientHeight; const dpr = Math.min(window.devicePixelRatio || 1, 2);
    canvas.width = width * dpr; canvas.height = height * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    const css = getComputedStyle(document.documentElement);
    ctx.fillStyle = css.getPropertyValue("--future-ground"); ctx.fillRect(0, 0, width, height);
    const rows = 40; const columns = 25; const cellW = width / columns; const cellH = height / rows;
    ctx.strokeStyle = css.getPropertyValue("--future-grid"); ctx.lineWidth = 0.5;
    for (let i = 1; i < 5; i += 1) { const x = (i / 5) * width; ctx.beginPath(); ctx.moveTo(x, 0); ctx.lineTo(x, height); ctx.stroke(); }
    points.forEach((point) => {
      const row = point.future % rows; const block = Math.floor(point.future / rows); const within = point.year - 2027;
      const x = (block * 5 + within + 0.5) * cellW; const y = (row + 0.5) * cellH;
      ctx.fillStyle = point.size >= 100_000_000 ? css.getPropertyValue("--fire") : css.getPropertyValue("--data-cool");
      const radius = Math.max(0.7, Math.min(3.6, Math.log10(point.size / 1_000_000 + 1)));
      ctx.beginPath(); ctx.arc(x, y, radius, 0, Math.PI * 2); ctx.fill();
    });
  }, [points]);
  return <canvas ref={ref} className="futures-canvas" aria-label="One thousand simulated futures shown as compact timelines" />;
}

function ThousandFutures() {
  const [baseline, setBaseline] = useState(19);
  const [g, setG] = useState(1);
  const [share, setShare] = useState(0.12);
  const [seed, setSeed] = useState(34);
  const k = (1 - share) + share * g;
  const { points, probability } = useMemo(() => {
    const rng = mulberry32(seed + Math.round(k * 1000)); const all: FuturePoint[] = []; let futuresWithGiant = 0;
    for (let future = 0; future < 1000; future += 1) {
      let giantBy2031 = false;
      for (let year = 2027; year <= 2031; year += 1) {
        const count = poisson(baseline * k, rng);
        for (let i = 0; i < count; i += 1) {
          const size = Math.min(340_000_000, 1_000_000 * Math.pow(Math.max(rng(), 0.000001), -1 / 1.03));
          if (size >= 100_000_000 && year < 2031) giantBy2031 = true;
          if (size >= 7_000_000) all.push({ future, year, size });
        }
      }
      if (giantBy2031) futuresWithGiant += 1;
    }
    return { points: all, probability: futuresWithGiant / 10 };
  }, [baseline, g, share, seed, k]);

  const applyPreset = (name: "Rain" | "Vulnpocalypse" | "Extreme") => {
    if (name === "Rain") { setG(1); setShare(0.12); }
    if (name === "Vulnpocalypse") { setG(2.2); setShare(0.31); }
    if (name === "Extreme") { setG(5.7); setShare(0.31); }
  };

  return (
    <section id="futures" className="story-section futures-section">
      <SectionIntro number="04" question="What happens across a thousand possible futures?">
        Each row is one possible 2027–2030 (four years, to the start of 2031); every dot is a breach of 7 million people or more (smaller ones are simulated but not drawn).
      </SectionIntro>
      <div className="future-answer"><span>Chance of at least one 100M+ breach<br />by the start of 2031</span><strong>{probability.toFixed(0)}%</strong></div>
      <div className="year-labels"><span>2027</span><span>2028</span><span>2029</span><span>2030</span><span>2031</span></div>
      <FuturesCanvas points={points} />
      <div className="future-controls">
        <Control
          label="Baseline: breaches of 1M+ people a year (λ₁)"
          value={`${baseline}`}
          min={10} max={40} step={1}
          current={baseline} onChange={setBaseline}
          icon={<span className="hub-icon">λ</span>}
          note="US healthcare, 2021–2026 average; yearly counts ranged from 10 to 37 and the level has risen since 2016"
        />
        <Control label="Exploitation growth (g)" value={`×${g.toFixed(1)}`} min={1} max={6} step={0.1} current={g} onChange={setG} icon={<Zap />} />
        <Control label="Breaches starting with a vulnerability (s)" value={`${Math.round(share * 100)}%`} min={0.12} max={0.31} step={0.01} current={share} onChange={setShare} icon={<span className="hub-icon">%</span>} />
      </div>
      <div className="scenario-summary"><span>Risk multiplier <strong>k = (1 − s) + s·g = {k.toFixed(2)}</strong></span><Button variant="ghost" size="sm" onClick={() => setSeed((v) => v + 1)}><RefreshCw />Run again</Button></div>
      <p className="patch-note">Each year’s count ~ Poisson(λ₁ × k). g is exploitation growth.</p>
      <div className="preset-row centered">{(["Rain", "Vulnpocalypse", "Extreme"] as const).map((name) => <Button key={name} variant="outline" onClick={() => applyPreset(name)}>{name}</Button>)}</div>
    </section>
  );
}

const NAV = [["company", "My company"], ["data", "Real data"], ["one-percent", "The 1%"], ["futures", "Futures"]] as const;

export function BreachStory() {
  return (
    <main>
      <nav className="story-nav" aria-label="Story sections">
        <a href="#top" className="story-mark"><Flame />HEAVY TAILS</a>
        <div>{NAV.map(([id, label], index) => <a key={id} href={`#${id}`}><span>{index + 1}</span>{label}</a>)}</div>
      </nav>
      <header id="top" className="story-hero">
        <div className="hero-kicker"><span>AN INTERACTIVE EXPERIMENT</span><span>4 QUESTIONS · REAL DATA</span></div>
        <h1>The Forest Fire<br />of Cyber Breaches</h1>
        <p>Why one breach can outweigh a thousand.</p>
        <a href="#company" className="start-link">Start with your company <ArrowDown /></a>
        <div className="hero-rules" aria-hidden="true"><i /><i /><i /><i /><i /></div>
      </header>
      <MyCompany />
      <RealData />
      <OnePercent />
      <ThousandFutures />
      <footer className="methods">
        <div><span className="section-number">METHODS</span><h2>What’s measured — and what’s modelled?</h2></div>
        <div className="methods-grid">
          <div><strong>Measured</strong><p>Breach sizes and counts: US healthcare from the HHS registry; documented losses across sectors from EuRepoC.</p></div>
          <div><strong>Modelled</strong><p>The “my company” risk calculator and the thousand futures. They are thought experiments, not forecasts. The calculator shows how risk is structured and how it shifts when you change one setting. Absolute probabilities depend mainly on the calibration constant e and, for attacker AI, on the scenario elasticities.</p></div>
          <div><strong>Inferred</strong><p>MOVEit’s role was checked by victim name for the largest 2023 breaches; public registries do not connect most breaches to a specific vulnerability.</p></div>
        </div>
        <p className="methods-note">Breach sizes and yearly counts are US healthcare only. The company calculator uses Verizon DBIR 2026 “Select initial access vectors in non-Error, non-Misuse breaches” (1 Nov 2024 – 31 Oct 2025): vulnerabilities 31%, phishing 16%, pretexting 6%, credential abuse 13%; residual 34% is a model bucket, not a Verizon vector share. Its publicly known event rate is calibrated to Cyentia IRIS; the residual includes other entry routes, errors and insider misuse. Breaches of any size, incidents and attacks follow from scenario assumptions.</p>
        <div className="methods-note"><strong>Limits</strong><p>Cascades through suppliers and shared platforms are not modelled. Of the four largest cascades of 2020–2024 in insurance data, only MOVEit clearly ran through a CVE; Change Healthcare began with stolen credentials, CDK Global’s entry route is unconfirmed, and CrowdStrike was a faulty update.</p></div>
        <div className="methods-note"><strong>Sources</strong><p>HHS OCR breach registry · EuRepoC · CISA KEV · Verizon DBIR 2026 · Henderson et al., 2026 · <a href="https://www.cyentia.com/iris/" target="_blank" rel="noreferrer">Cyentia IRIS 2025</a> (and IRIS 2020) · <a href="https://www.gov.uk/government/collections/cyber-security-breaches-survey" target="_blank" rel="noreferrer">UK Cyber Security Breaches Survey 2025/26</a></p></div>
        <a className="article-link" href="https://asintsov.com/notes/2026-10-05-vulnpocalypse-is-a-race/" target="_blank" rel="noreferrer">Read the full article <span>↗</span></a>
      </footer>
    </main>
  );
}
