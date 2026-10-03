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
import { ArrowDown, Flame, RefreshCw, Shield, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Slider } from "@/components/ui/slider";
import { riskRange, NDAY_MEDIAN_DAYS, DEFAULT_COMPANY, OWN_BASE_ATTACKER_WIN, VENDOR_ZERO_DAY_SHARE, computeRisk, type CompanyInputs, type CompanyResult } from "@/lib/company-risk";
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

function CompanyCanvas({ inputs, result }: { inputs: CompanyInputs; result: CompanyResult }) {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const simRef = useRef<Sim | null>(null);
  const params = simParams(inputs, result);
  const paramsKey = JSON.stringify(params);
  const paramsRef = useRef(params);
  paramsRef.current = params;
  const gridRef = useRef({ cols: 26, rows: 14 });
  const [speed, setSpeed] = useState(1);
  const speedRef = useRef(1);
  speedRef.current = speed;
  const [runId, setRunId] = useState(0);
  const [stats, setStats] = useState<SimStats | null>(null);

  // any slider change or the Restart button starts a fresh, seeded run
  useEffect(() => {
    const { cols, rows } = gridRef.current;
    simRef.current = createSim(cols, rows, 7, paramsRef.current);
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
    const colors = { tree: col("--tree"), patched: col("--patched"), fire: col("--fire"), cool: col("--data-cool"), muted: col("--muted-foreground"), fg: col("--foreground") };

    const narrow = canvas.clientWidth < 520;
    const cols = narrow ? 18 : 26;
    const rows = narrow ? 12 : 14;
    if (gridRef.current.cols !== cols) {
      gridRef.current = { cols, rows };
      simRef.current = createSim(cols, rows, 7, paramsRef.current);
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
        if (cell.state === OK) { ctx.globalAlpha = 0.38; ctx.fillStyle = cell.own ? colors.cool : colors.tree; }
        else if (cell.state === VULN) { ctx.globalAlpha = 0.55; ctx.fillStyle = colors.fire; }
        else if (cell.state === BURNING) { ctx.globalAlpha = 0.6 + 0.35 * Math.abs(Math.sin(sim.day * 0.8 + i)); ctx.fillStyle = colors.fire; }
        else { ctx.globalAlpha = 0.45; ctx.fillStyle = colors.muted; }
        ctx.fillRect(x + pad, y + pad, cellSize - 2 * pad, cellSize - 2 * pad);
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
          ctx.strokeStyle = cell.outcome === "patched" ? colors.patched : colors.fire;
          ctx.lineWidth = 1.6;
          const cx = x + cellSize / 2;
          ctx.beginPath();
          ctx.moveTo(cx - cellSize * 0.3, 0);
          ctx.lineTo(cx + cellSize * 0.15, y * 0.5);
          ctx.lineTo(cx - cellSize * 0.1, y * 0.5);
          ctx.lineTo(cx, y + cellSize / 2);
          ctx.stroke();
          // patched / blocked: a shield ring, nothing happens
          if (cell.state === OK && (cell.outcome === "patched" || cell.outcome === "blocked")) {
            ctx.strokeStyle = colors.patched;
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
      // SOC: dispatch line to the incident, the crew, and a burst where they land
      const ctr = (v: number) => v * cellSize + cellSize / 2;
      for (const crew of sim.crews) {
        const fire = crew.fire ? sim.fires.find((f) => f.id === crew.fire) : undefined;
        if (fire) {
          ctx.globalAlpha = 0.8;
          ctx.strokeStyle = colors.patched;
          ctx.lineWidth = 1.5;
          ctx.setLineDash([4, 3]);
          ctx.beginPath();
          ctx.moveTo(ctr(crew.x), ctr(crew.y));
          ctx.lineTo(ctr(fire.origin % cols), ctr(Math.floor(fire.origin / cols)));
          ctx.stroke();
          ctx.setLineDash([]);
        }
        ctx.globalAlpha = 1;
        ctx.fillStyle = colors.patched;
        ctx.beginPath();
        ctx.arc(ctr(crew.x), ctr(crew.y), Math.max(3, cellSize * (fire ? 0.36 : 0.28)), 0, Math.PI * 2);
        ctx.fill();
      }
      const burstLife = 20 * Math.max(1, speedRef.current / 4);
      for (const b of sim.bursts) {
        const t = (sim.day - b.at) / burstLife;
        if (t < 0 || t > 1) continue;
        ctx.globalAlpha = 1 - t;
        ctx.strokeStyle = b.saved ? colors.patched : colors.muted;
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
        const label = fire.kind === "large" ? `LARGE BREACH — crossed segments${late}` : fire.kind === "small" ? `small breach — segment lost${late}` : fire.crew >= 0 ? (fire.arrived ? "SOC stopped it" : "SOC on the way…") : "contained";
        const ox = Math.min(w - ctx.measureText(label).width - 2, Math.max(2, (fire.origin % cols) * cellSize));
        const oy = Math.max(14, Math.floor(fire.origin / cols) * cellSize - 2);
        ctx.fillStyle = fire.kind === "contained" ? colors.patched : colors.fg;
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
    <tr><td>{label}</td><td>{seen}{note ? <small> {note}</small> : null}</td><td>{model}</td></tr>
  );
  return (
    <div className="company-canvas-wrap">
      <div className="canvas-toolbar">
        <span>Year {s?.year ?? 1}</span>
        <div>
          {[1, 10, 100].map((x) => <Button key={x} size="sm" variant={speed === x ? "default" : "outline"} onClick={() => setSpeed(x)}>{x}×</Button>)}
          <Button size="sm" variant="outline" onClick={() => setRunId((n) => n + 1)}><RefreshCw className="size-3.5" /> Restart</Button>
        </div>
      </div>
      <canvas ref={canvasRef} className="company-canvas" aria-label="Animated replay: faint flashes never reach you; patched systems shrug off strikes; reached attacks face hardening and SOC before becoming small or large breaches" />
      <div className="canvas-legend">
        <span><i className="tree-dot" /> vendor system</span>
        <span><i className="patch-dot" /> your own code</span>
        <span><i className="fire-dot" /> hit by lightning: blue ring = patch countdown (dashed = never patched)</span>
        <span><i className="ring-dot" /> patched in time / stopped by hardening</span>
        <span><i className="tree-dot" /> faint flash, no ring: never reached you (not exposed / not targeted)</span>
        <span><i className="fire-dot" /> breach spreading</span>
        <span><i className="burned-dot" /> burned, rebuilding</span>
        <span><i className="crew-dot" /> SOC crew: dashed line = racing to an incident</span>
        <span><i className="segment-dot" /> network segment walls (Isolation &amp; hardening)</span>
      </div>
      {s && (
        <>
          <p className="canvas-funnel">
            {s.counts.strikes} strikes → {s.counts.patched} hit patched systems · {s.counts.unreached} never reached you (not exposed / not targeted) · {s.counts.blocked} blocked by hardening · {s.counts.contained} contained by SOC · <b>{s.counts.small} small + {s.counts.large} large breaches</b>
          </p>
          <table className="canvas-compare">
            <thead><tr><th /><th>On the canvas</th><th>Formulas</th></tr></thead>
            <tbody>
              {row("Breaches per year", s.years ? rate(s.perYear) : "—", rate(result.lambda), s.years ? `(${s.years} years)` : undefined)}
              {row("Chance of a breach in a year", s.years ? pct(s.pYear) : "—", pct(result.pYear), s.years ? `(${s.yearsHit} of ${s.years} years)` : undefined)}
              {row("Chance within 5 years", s.windows ? pct(s.p5) : "—", pct(result.p5), s.windows ? `(${s.windows} windows)` : undefined)}
              {row("Breaches that are large", s.counts.small + s.counts.large ? (s.largeShare === 0 ? "0%" : pct(s.largeShare)) : "—", pct(result.largeShare))}
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

  const lanes = [
    { name: "Race 1 · vendor software", sub: `${Math.round(VENDOR_ZERO_DAY_SHARE * 100)}% zero-days, then your patch (${c.patchDays} d) vs CISA listing (median exploit delay: ${NDAY_MEDIAN_DAYS} days, n-day)`, ch: r.vendor },
    { name: "Race 2 · your own code", sub: `baseline attacker win share ${Math.round(OWN_BASE_ATTACKER_WIN * 100)}% (assumption), then attacker AI vs AppSec + bounty`, ch: r.own },
  ];
  const max = Math.max(0.01, r.vendor.lightning, r.own.lightning);

  return (
    <section id="company" className="story-section">
      <SectionIntro number="01" question="Will lightning strike your company?">
        Every year some exploited vulnerabilities land on software you run — that’s the lightning. Then two races decide what happens. In vendor software, can you patch before the exploit arrives? In your own code, do you find the bug before attackers do? Whatever gets through still has to beat your hardening and your detection team. Set up your company and watch the odds.
      </SectionIntro>
      <CompanyCanvas inputs={c} result={r} />
      <div className="forest-layout">
        <div>
          <div className="preset-row">
            {Object.entries(COMPANY_PRESETS).map(([name, preset]) => <Button key={name} size="sm" variant="outline" onClick={() => setC({ ...preset })}>{name}</Button>)}
          </div>
          <p className="preset-explainer">At 40% in-house code and today’s vendor rate (×1), patching is the main risk. At 80% in-house and attacker AI ×5 without AppSec, your own code becomes the main risk.</p>
          <div className="side-blocks">
            <div className="ad-block" data-side="attack">
              <div className="ad-head"><Zap /><span>Attack</span><small>what comes at you — you can’t patch it away</small></div>
              <Control tag="Scenario assumption" label="Exploited vendor vulns in your stack / yr" value={`${c.vendorVulns}`} min={1} max={30} step={1} current={c.vendorVulns} onChange={(v) => set("vendorVulns", v)} icon={<Zap />} />
              <Control tag="Scenario assumption" label="Vendor exploitation growth" value={`×${vendorGrowth.toFixed(1)}`} min={1} max={3} step={0.1} current={vendorGrowth} onChange={(v) => set("vendorGrowth", v)} icon={<Zap />} />
              <Control tag="Scenario assumption" label="Attacker AI (all stages)" value={`×${c.threat.toFixed(1)}`} min={1} max={6} step={0.1} current={c.threat} onChange={(v) => set("threat", v)} icon={<Zap />} />
              <p className="race-scale-note" style={{ textAlign: "left", margin: "-0.6rem 0 0" }}>Data so far show no rise in vendor exploitation; m above 1 is a scenario. For one scenario, move vendor growth or attacker AI, not both.</p>
            </div>
            <div className="ad-block" data-side="defense">
              <div className="ad-head"><Shield /><span>Defense</span><small>what you control</small></div>
              <Control tag="Scenario assumption" label="Built in-house vs vendors" value={`${Math.round(c.inHouse * 100)}% / ${Math.round((1 - c.inHouse) * 100)}%`} min={0} max={1} step={0.05} current={c.inHouse} onChange={(v) => set("inHouse", v)} icon={<Shield />} />
              <Control tag="Observed: Verizon DBIR 2026, KEV remediation median, default 43 d" label="Days to patch (median)" value={`${c.patchDays} days`} min={1} max={180} step={1} current={c.patchDays} onChange={(v) => set("patchDays", v)} icon={<Shield />} />
              <Control tag="Scenario assumption" label="Share of affected systems never patched (assumption)" value={`${Math.round(c.neverPatched * 100)}%`} min={0} max={0.6} step={0.01} current={c.neverPatched} onChange={(v) => set("neverPatched", v)} icon={<Shield />} />
              <Control tag="Scenario assumption" label="AI SAST / DAST" value={APPSEC_LABELS[c.appsec] ?? ""} min={0} max={3} step={1} current={c.appsec} onChange={(v) => set("appsec", v)} icon={<Shield />} />
              <Control tag="Scenario assumption: bounty curve" label="Bug bounty budget" value={c.bountyK ? `$${c.bountyK}k / year` : "none"} min={0} max={1000} step={25} current={c.bountyK} onChange={(v) => set("bountyK", v)} icon={<Shield />} />
              <Control tag="Scenario assumption: h_H, q_H" label="Isolation & hardening" value={HARDENING_LABELS[c.hardening] ?? ""} min={0} max={4} step={1} current={c.hardening} onChange={(v) => set("hardening", v)} icon={<Shield />} />
              <Control tag="Calibrated: c_S" label="Detect & respond (SOC)" value={SOC_LABELS[c.soc] ?? ""} min={0} max={3} step={1} current={c.soc} onChange={(v) => set("soc", v)} icon={<Shield />} />
              <Control tag="Scenario assumption: g_G" label="Data governance / privacy" value={GOV_LABELS[c.governance] ?? ""} min={0} max={3} step={1} current={c.governance} onChange={(v) => set("governance", v)} icon={<Shield />} />
            </div>
          </div>
          <div className="race-lanes">
            {lanes.map(({ name, sub, ch }, lane) => (
              <div key={name} className="race-lane">
                <div className="race-head"><strong>{name}</strong><small>{sub}</small></div>
                {[
                  ["Lightning hits you", ch.lightning],
                  [lane === 0 ? `Exploited before you patch (${pct(ch.raceP)})` : `Attacker finds it first and it stays open (×${ch.raceP.toFixed(2)} vs no AppSec)`, ch.winsRace],
                  [`Reached you (${pct(ch.winsRace > 0 ? ch.reached / ch.winsRace : 0)})`, ch.reached],
                  [`Past hardening (${pct(ch.reached > 0 ? ch.pastHardening / ch.reached : 0)})`, ch.pastHardening],
                  [`Not contained → breach (${pct(ch.pastHardening > 0 ? ch.breaches / ch.pastHardening : 0)})`, ch.breaches],
                ].map(([label, value]) => (
                  <div key={label as string} className="race-row">
                    <span>{label}</span>
                    <div className="race-bar"><i style={{ width: `${Math.max(0.5, (value as number) / max * 100)}%` }} /></div>
                    <b>{rate(value as number)}/yr</b>
                  </div>
                ))}
              </div>
            ))}
            <p className="race-scale-note">Both funnels share one scale.</p>
          </div>
          <p className="patch-note">KEV listing is an upper bound on when exploitation starts; real attacks often start earlier. Observed (CVEs published 2023–2025 in CISA KEV, snapshot 30 Sep 2026, n = 522): 31% were listed on or before publication day (zero-days; 95% interval 28–36%, Beta posterior). 19% (17–21%) for all KEV entries added since 2022. The rest took a median 36 days (n = 358).</p>
        </div>
        <aside className="forest-stats">
          <div className="metrics-grid">
            <Metric label="Breach this year" value={pct(r.pYear)} />
            <div className="metric">
              <span>Breach within 5 years</span>
              <strong>{pct(r.p5)}{showRange ? <small> ({pct(range.p5[0])}–{pct(range.p5[1])})</small> : null}</strong>
              <button type="button" className="range-toggle" onClick={() => setShowRange((v) => !v)}>Assumptions range: {showRange ? "on" : "off"}</button>
            </div>
            <Metric label="Expected breaches / year" value={rate(r.lambda)} detail={`vendor ${rate(r.vendor.breaches)} · own ${rate(r.own.breaches)}`} />
            <Metric label="Large data breach, 5 years" value={pct(r.pLarge5)} detail={`${pct(r.largeShare)} of breaches turn large`} />
            <div className="metric metric-wide">
              <span>Implied all-cause breach rate</span>
              <strong>{rate(r.allCause[0])}–{rate(r.allCause[1])} / yr</strong>
              <small>Derived from the assumed 12–31% vulnerability share (Observed: EuRepoC; Verizon DBIR 2026), not a validation.</small>
            </div>
          </div>
          <p className="framing-note">Read these as comparisons between settings, not as a forecast of your company's real breach probability. The shape comes from data; the levels depend on calibration and assumptions.</p>
          <p className="range-note">Range: Low = z<sub>v</sub> 0.19, e 0.025, elasticities 0; High = z<sub>v</sub> 0.31, e 0.10, elasticities 1 / 1 / 0.5 / 0.5. The "never patched" share always follows your slider. The level mostly comes from calibration (e) and, for attacker AI, from the elasticities; the shape comes from the data. Compare settings, not single numbers.</p>
          <div className="formula-box">
            <p><span><b>λ</b> = L<sub>v</sub>·p<sub>v</sub>·h·(1−c) + L<sub>o</sub>·R<sub>o</sub>·h·(1−c)</span></p>
            <p><span>h = min(1, e·h<sub>H</sub>·m<sup>0.3</sup>) = {pct(r.vendor.lightning > 0 ? r.vendor.pastHardening / Math.max(r.vendor.winsRace, 1e-12) : r.own.pastHardening / Math.max(r.own.winsRace, 1e-12))}</span></p>
            <p><span>c<sub>eff</sub> = c<sub>S</sub>/m<sup>0.3</sup> ∈ [0, c<sub>S</sub>]</span></p>
            <p><span>L<sub>v</sub> = N<sub>v</sub>·(1−f)·k<sub>v</sub>, k<sub>v</sub> = ×{vendorGrowth.toFixed(1)}</span></p>
            <p><span>F = Σ share<sub>i</sub>·0.5<sup>(days<sub>i</sub>/m<sup>0.5</sup>)/D<sub>p</sub></sup> (8 observed n-day bins)</span></p>
            <p><span>p<sub>v</sub> = z<sub>v</sub> + (1−z<sub>v</sub>)·[u + (1−u)·F] = {r.vendor.raceP.toFixed(2)} (Derived)</span></p>
            <p><span>L<sub>o</sub> = N<sub>o</sub>·f·m<sup>0.5</sup> = {r.own.lightning.toFixed(2)}</span></p>
            <p><span>s<sub>o</sub> = m·z<sub>o</sub> / (m·z<sub>o</sub> + D·(1−z<sub>o</sub>))</span></p>
            <p><span>z<sub>o</sub> = {OWN_BASE_ATTACKER_WIN.toFixed(2)} (assumption; article uses 0.19)</span></p>
            <p><span>R<sub>o</sub> = (s<sub>o</sub>/z<sub>o</sub>) / D = ×{r.own.raceP.toFixed(2)} vs no AppSec (Derived)</span></p>
            <p><span>λ<sub>0</sub> = λ at k<sub>v</sub> = 1 and m = 1 = {rate(r.lambdaBaseline)}</span></p>
            <p><span>all_cause(s) = λ + λ<sub>0</sub>·(1−s)/s, s ∈ [0.12, 0.31]</span></p>
            <p><span>vulnerability share = λ / all_cause</span></p>
            <p><span>P(year) = 1 − e<sup>−λ</sup> = {pct(r.pYear)}</span></p>
          </div>
          <div className="formula-box">
            <p><span><b>Labels</b></span></p>
            <p><span>Observed: z<sub>v</sub> = 0.31, 95% interval 0.28–0.36 (Beta posterior, n = 522)</span></p>
            <p><span>19% (17–21%) for all KEV entries added since 2022</span></p>
            <p><span>Observed: n-day bins (CISA KEV, CVEs 2023–2025); D<sub>p</sub> 43 d (Verizon DBIR 2026); s 12–31% (EuRepoC; DBIR 2026)</span></p>
            <p><span>Calibrated: e = 0.05, c<sub>S</sub></span></p>
            <p><span>Scenario assumption: u, N<sub>o</sub>, r<sub>A</sub>, bounty curve, h<sub>H</sub>, g<sub>G</sub>, q<sub>H</sub>, z<sub>o</sub>, all m elasticities</span></p>
            <p><span>Derived: λ, p<sub>v</sub>, R<sub>o</sub>, all outputs</span></p>
          </div>
          <div className="formula-box">
            <p><span><b>Assumptions</b> — scenario elasticities (not measured)</span></p>
            <p><span>coverage of own code: L<sub>o</sub> ∝ m<sup>0.5</sup> (more targets and code examined)</span></p>
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
  { x: 1, healthcare: 100, losses: 100, reference: 100 },
  { x: 2, healthcare: 50, losses: 40, reference: 50 },
  { x: 10, healthcare: 20, losses: 18, reference: 10 },
  { x: 20, healthcare: 10, losses: 8, reference: 5 },
  { x: 100, healthcare: 1, losses: 4, reference: 1 },
  { x: 200, healthcare: 0.5, losses: 2, reference: 0.5 },
  { x: 1000, healthcare: 0.1, losses: 0.2, reference: 0.1 },
].map((point) => ({ ...point, insurance: 100 * Math.pow(point.x, -0.74) }));

const INSURANCE_LABEL = "Insurance claims, multi-victim events (Henderson et al., 2026): ×10 larger → 5.5× rarer";

const GIANTS = [
  [1927, 0.07, "Change Healthcare · 192.7M · 2024"],
  [622, 0.2, "Conduent · 62.2M · 2025"], [150, 0.75, "DentaQuest · 15.0M · 2026"],
  [148, 0.9, "Welltok · 14.8M · 2023 · MOVEit"], [139, 1.05, "Aflac · 13.9M · 2025"],
  [115, 1.25, "Optum360 · 11.5M · 2019"], [113, 1.48, "HCA Healthcare · 11.3M · 2023"],
  [103, 2, "LabCorp · 10.3M · 2019"],
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
            <XAxis dataKey="x" type="number" scale="log" domain={[1, 2000]} ticks={[1, 2, 10, 20, 100, 200, 1000]} tickFormatter={(v) => `×${v}`} label={{ value: "Times larger than starting size", position: "bottom", offset: 12 }} />
            <YAxis type="number" scale="log" domain={[0.05, 100]} ticks={[0.1, 1, 10, 100]} tickFormatter={(v) => `${v}%`} width={46} />
            <Line dataKey="reference" name="1/x" stroke="var(--muted-foreground)" strokeDasharray="7 7" dot={false} connectNulls />
            <Line dataKey="insurance" name={INSURANCE_LABEL} stroke="var(--tree)" strokeWidth={2} strokeDasharray="9 5" dot={false} isAnimationActive={false} connectNulls />
            <Line dataKey="healthcare" name="US healthcare · people" stroke="var(--fire)" strokeWidth={3} dot={{ r: 4 }} connectNulls />
            <Line dataKey="losses" name="All sectors · losses (EuRepoC)" stroke="var(--data-cool)" strokeWidth={3} dot={{ r: 4 }} connectNulls />
            <Scatter data={GIANTS} name="Named giants" fill="var(--ink)" dataKey="y" shape="diamond" />
            <ZAxis dataKey="z" range={[50, 50]} />
            <ReferenceLine x={ruler} stroke="var(--ink)" strokeWidth={2} label={{ value: `×${ruler}`, fill: "var(--ink)", position: "insideTopRight" }} />
            <Tooltip content={({ active, payload }) => {
              if (!active || !payload?.length) return null;
              const named = payload.find((entry) => entry.payload?.name)?.payload;
              if (named) return <div className="chart-tooltip"><strong>{named.name}</strong></div>;
              return <div className="chart-tooltip">{payload.map((entry) => <p key={String(entry.dataKey)}><strong>{entry.name}</strong> {Number(entry.value).toFixed(2)}%</p>)}</div>;
            }} />
          </ComposedChart>
        </ResponsiveContainer>
      </div>
      <div className="legend-row"><span><i className="legend-fire" />US healthcare, from 100k people (HHS)</span><span><i className="legend-cool" />All sectors, from $10M loss (EuRepoC)</span><span><i className="legend-dash" />1/x guide</span><span><i className="legend-insurance" />{INSURANCE_LABEL}</span></div>
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
        <p className="methods-note">Breach numbers are US healthcare only. Vulnerabilities start only 12–31% of breaches; phishing and stolen passwords cause most of the rest. The company calculator follows that vulnerability channel only; its rates are illustrative assumptions.</p>
        <div className="methods-note"><strong>Limits</strong><p>Cascades through suppliers and shared platforms are not modelled. Of the four largest cascades of 2020–2024 in insurance data, only MOVEit clearly ran through a CVE; Change Healthcare began with stolen credentials, CDK Global’s entry route is unconfirmed, and CrowdStrike was a faulty update.</p></div>
        <a className="article-link" href="#top">Read the full article <span>↗</span></a>
      </footer>
    </main>
  );
}
