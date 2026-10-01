import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import {
  Area,
  CartesianGrid,
  ComposedChart,
  Line,
  LineChart,
  ReferenceLine,
  ResponsiveContainer,
  Scatter,
  ScatterChart,
  Tooltip,
  XAxis,
  YAxis,
  ZAxis,
} from "recharts";
import { ArrowDown, CloudRain, Flame, Play, RefreshCw, Sparkles, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Slider } from "@/components/ui/slider";

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

function gaussian(rng: Rng) {
  const u = Math.max(rng(), Number.EPSILON);
  const v = rng();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
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
    const [x1, p1] = CCDF[i];
    const [x2, p2] = CCDF[i + 1];
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

type DrawPoint = { n: number; value: number; average: number };

function GuessAverage() {
  const [normal, setNormal] = useState<DrawPoint[]>([]);
  const [breach, setBreach] = useState<DrawPoint[]>([]);
  const seedRef = useRef(1217);

  const draw = (count: number) => {
    const rng = mulberry32(seedRef.current++);
    const extend = (existing: DrawPoint[], sampler: () => number) => {
      let sum = existing.reduce((acc, point) => acc + point.value, 0);
      const next = [...existing];
      for (let i = 0; i < count; i += 1) {
        const value = sampler();
        sum += value;
        next.push({ n: next.length + 1, value, average: sum / (next.length + 1) });
      }
      return next;
    };
    setNormal((items) => extend(items, () => 170 + gaussian(rng) * 10));
    setBreach((items) => extend(items, () => sampleBreach(rng)));
  };

  const reset = () => {
    setNormal([]);
    setBreach([]);
  };

  return (
    <section id="average" className="story-section">
      <SectionIntro number="01" question="Can you guess the average?">
        Draw from two worlds. In one, every new observation behaves. In the other, a giant can arrive at any moment.
      </SectionIntro>
      <div className="guess-grid">
        <AveragePanel title="Normal world" subtitle="Human heights · mean 170 cm · SD 10" data={normal} normal />
        <AveragePanel title="Breach world" subtitle="US healthcare hacking breaches · 2016–2026" data={breach} />
      </div>
      <div className="button-row centered">
        <Button onClick={() => draw(10)}><Sparkles />Draw 10 more</Button>
        <Button variant="outline" onClick={() => draw(1000)}>Draw 1,000</Button>
        <Button variant="ghost" size="icon" onClick={reset} aria-label="Reset draws" title="Reset draws"><RefreshCw /></Button>
      </div>
      {breach.length ? (
        <aside className="reveal animate-fade-in">
          <Flame aria-hidden="true" />
          <p><strong>In heavy-tailed worlds, the average never settles.</strong> One event can outweigh everything before it.</p>
        </aside>
      ) : (
        <p className="prompt"><ArrowDown /> Draw a sample. Watch the two orange lines.</p>
      )}
    </section>
  );
}

function AveragePanel({ title, subtitle, data, normal = false }: { title: string; subtitle: string; data: DrawPoint[]; normal?: boolean }) {
  const shown = data.length > 260 ? data.slice(-260) : data;
  const average = data.at(-1)?.average;
  const largest = data.reduce((max, point) => Math.max(max, point.value), 0);
  return (
    <article className="chart-panel">
      <div className="panel-heading">
        <div><h3>{title}</h3><p>{subtitle}</p></div>
        <strong>{average ? (normal ? `${average.toFixed(1)} cm` : compact.format(average)) : "—"}</strong>
      </div>
      <div className="chart-shell">
        {shown.length ? (
          <ResponsiveContainer width="100%" height="100%">
            <ComposedChart data={shown} margin={{ top: 14, right: 8, bottom: 8, left: 0 }}>
              <CartesianGrid vertical={false} stroke="var(--grid)" />
              <XAxis dataKey="n" tickLine={false} axisLine={false} tick={{ fontSize: 11 }} />
              <YAxis scale={normal ? "linear" : "log"} domain={normal ? [130, 210] : [500, 200_000_000]} tickFormatter={(v) => normal ? `${v}` : compact.format(v)} width={48} tickLine={false} axisLine={false} tick={{ fontSize: 10 }} />
              <Scatter dataKey="value" fill={normal ? "var(--data-cool)" : "var(--fire)"} fillOpacity={0.48} />
              <Line type="monotone" dataKey="average" stroke="var(--ink)" strokeWidth={2.5} dot={false} isAnimationActive={false} />
              <Tooltip formatter={(value) => normal ? `${Number(value).toFixed(1)} cm` : `${fmt.format(Number(value))} people`} labelFormatter={(label) => `Draw ${label}`} />
            </ComposedChart>
          </ResponsiveContainer>
        ) : <div className="empty-chart"><span>?</span><p>Your draws will appear here</p></div>}
      </div>
      <div className="mini-facts"><span>{fmt.format(data.length)} draws</span><span>Largest: {largest ? (normal ? `${largest.toFixed(0)} cm` : compact.format(largest)) : "—"}</span></div>
    </article>
  );
}

type FireSettings = { lightning: number; growth: number; rain: number; suppliers: number };
type FireStats = { fires: number; largest: number; sizes: number[] };

const FIRE_PRESETS: Record<string, FireSettings> = {
  "2025": { lightning: 1, growth: 0.021, rain: 0.0035, suppliers: 0 },
  "AI flood with rain": { lightning: 12, growth: 0.021, rain: 0.025, suppliers: 0 },
  "AI flood, no rain": { lightning: 12, growth: 0.021, rain: 0.001, suppliers: 0 },
  "One shared supplier": { lightning: 1, growth: 0.021, rain: 0.0035, suppliers: 1 },
};

function ForestFire() {
  const canvasRef = useRef<HTMLCanvasElement>(null);
  const stateRef = useRef<Uint8Array>(new Uint8Array());
  const hubsRef = useRef<number[][]>([]);
  const activeHubRef = useRef<number[]>([]);
  const settingsRef = useRef<FireSettings>(FIRE_PRESETS["2025"]);
  const [settings, setSettings] = useState<FireSettings>(FIRE_PRESETS["2025"]);
  const [stats, setStats] = useState<FireStats>({ fires: 0, largest: 0, sizes: [] });
  const [running, setRunning] = useState(true);
  const [generation, setGeneration] = useState(0);
  const sizeRef = useRef(86);

  useEffect(() => { settingsRef.current = settings; }, [settings]);

  useEffect(() => {
    const size = window.innerWidth < 640 ? 64 : 96;
    sizeRef.current = size;
    const rng = mulberry32(4029 + generation);
    const cells = new Uint8Array(size * size);
    for (let i = 0; i < cells.length; i += 1) cells[i] = rng() < 0.72 ? 1 : 0;
    stateRef.current = cells;
    setStats({ fires: 0, largest: 0, sizes: [] });
  }, [generation]);

  useEffect(() => {
    const size = sizeRef.current;
    const rng = mulberry32(910 + settings.suppliers * 31 + generation);
    hubsRef.current = Array.from({ length: settings.suppliers }, () =>
      Array.from({ length: 40 }, () => Math.floor(rng() * size * size)),
    );
  }, [settings.suppliers, generation]);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    const rng = mulberry32(8821 + generation);
    let timer = 0;

    const tick = () => {
      const cells = stateRef.current;
      const n = sizeRef.current;
      const next = cells.slice();
      const newIgnitions: number[] = [];
      const lightningTries = Math.max(1, Math.round(settingsRef.current.lightning / 2));
      for (let strike = 0; strike < lightningTries; strike += 1) {
        if (rng() < settingsRef.current.lightning / 12) {
          const hit = Math.floor(rng() * cells.length);
          if (cells[hit] === 1) { next[hit] = 3; newIgnitions.push(hit); }
        }
      }
      activeHubRef.current = [];
      hubsRef.current.forEach((links, hubIndex) => {
        if (links.some((index) => cells[index] === 3 || next[index] === 3)) {
          activeHubRef.current.push(hubIndex);
          links.forEach((index) => { if (cells[index] === 1 || cells[index] === 2) next[index] = 3; });
        }
      });
      for (let i = 0; i < cells.length; i += 1) {
        const value = cells[i];
        if (value === 0 && rng() < settingsRef.current.growth) next[i] = 1;
        else if (value === 1 && rng() < settingsRef.current.rain) next[i] = 2;
        else if (value === 3) {
          next[i] = 0;
          const x = i % n;
          const neighbors = [i - n, i + n, x > 0 ? i - 1 : -1, x < n - 1 ? i + 1 : -1];
          neighbors.forEach((neighbor) => {
            if (neighbor >= 0 && neighbor < cells.length && (cells[neighbor] === 1 || cells[neighbor] === 2)) next[neighbor] = 3;
          });
        }
      }
      stateRef.current = next;

      const burning = Array.from(next).reduce((count, value) => count + (value === 3 ? 1 : 0), 0);
      if (newIgnitions.length && burning) {
        setStats((previous) => {
          const sizes = [...previous.sizes, burning].slice(-500);
          return { fires: previous.fires + newIgnitions.length, largest: Math.max(previous.largest, burning), sizes };
        });
      }
    };

    const draw = () => {
      const cells = stateRef.current;
      const n = sizeRef.current;
      const width = canvas.clientWidth;
      const height = canvas.clientHeight;
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      if (canvas.width !== width * dpr || canvas.height !== height * dpr) {
        canvas.width = width * dpr;
        canvas.height = height * dpr;
      }
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.fillStyle = getComputedStyle(canvas).getPropertyValue("--forest-ground");
      ctx.fillRect(0, 0, width, height);
      const cellW = width / n;
      const cellH = height / n;
      const css = getComputedStyle(canvas);
      const colors = ["transparent", css.getPropertyValue("--tree"), css.getPropertyValue("--patched"), css.getPropertyValue("--fire")];
      for (let i = 0; i < cells.length; i += 1) {
        if (!cells[i]) continue;
        ctx.fillStyle = colors[cells[i]];
        ctx.fillRect((i % n) * cellW, Math.floor(i / n) * cellH, Math.max(1, cellW - 0.35), Math.max(1, cellH - 0.35));
      }
      hubsRef.current.forEach((links, hubIndex) => {
        const hx = width * ((hubIndex + 1) / (hubsRef.current.length + 1));
        const hy = 17;
        if (activeHubRef.current.includes(hubIndex)) {
          ctx.strokeStyle = css.getPropertyValue("--supplier-line");
          ctx.lineWidth = 0.7;
          links.forEach((index) => {
            ctx.beginPath(); ctx.moveTo(hx, hy); ctx.lineTo((index % n) * cellW, Math.floor(index / n) * cellH); ctx.stroke();
          });
        }
        ctx.fillStyle = activeHubRef.current.includes(hubIndex) ? css.getPropertyValue("--fire") : css.getPropertyValue("--supplier");
        ctx.beginPath(); ctx.arc(hx, hy, 6, 0, Math.PI * 2); ctx.fill();
      });
    };

    let frame = 0;
    const loop = () => {
      if (running && frame % 5 === 0) tick();
      draw();
      frame += 1;
      timer = requestAnimationFrame(loop);
    };
    loop();
    return () => cancelAnimationFrame(timer);
  }, [generation, running]);

  const totalBurned = stats.sizes.reduce((a, b) => a + b, 0);
  const topCount = Math.max(1, Math.ceil(stats.sizes.length * 0.01));
  const topShare = totalBurned ? [...stats.sizes].sort((a, b) => b - a).slice(0, topCount).reduce((a, b) => a + b, 0) / totalBurned : 0;
  const minSize = Math.max(1, Math.min(...stats.sizes, 1));
  const alpha = stats.sizes.length > 1 ? 1 + stats.sizes.length / stats.sizes.reduce((sum, size) => sum + Math.log(Math.max(size, minSize) / minSize), 0) : 0;
  const histogram = useMemo(() => {
    const counts = new Map<number, number>();
    stats.sizes.forEach((size) => {
      const bucket = Math.max(1, Math.pow(2, Math.floor(Math.log2(size))));
      counts.set(bucket, (counts.get(bucket) || 0) + 1);
    });
    return [...counts.entries()].map(([size, count]) => ({ size, count })).sort((a, b) => a.size - b.size);
  }, [stats.sizes]);

  const update = <K extends keyof FireSettings>(key: K, value: FireSettings[K]) => setSettings((current) => ({ ...current, [key]: value }));

  return (
    <section id="forest" className="story-section forest-section">
      <SectionIntro number="02" question="What makes a tiny spark become a catastrophe?">
        Grow a digital forest. Trees are unpatched systems. Rain patches them. Lightning is a newly exploited vulnerability.
      </SectionIntro>
      <div className="forest-layout">
        <div>
          <div className="canvas-wrap">
            <canvas ref={canvasRef} className="forest-canvas" aria-label="Live forest fire simulation" />
            <div className="canvas-legend"><span className="tree-dot" />unpatched <span className="patch-dot" />patched <span className="fire-dot" />burning</div>
          </div>
          <div className="button-row forest-actions">
            <Button onClick={() => setRunning((value) => !value)}>{running ? <span className="pause-icon">Ⅱ</span> : <Play />}{running ? "Pause" : "Play"}</Button>
            <Button variant="outline" onClick={() => setGeneration((value) => value + 1)}><RefreshCw />New forest</Button>
          </div>
          <div className="preset-row">
            {Object.entries(FIRE_PRESETS).map(([name, preset]) => <Button key={name} size="sm" variant="outline" onClick={() => setSettings(preset)}>{name}</Button>)}
          </div>
          <div className="controls-grid">
            <Control label="Lightning (CVEs)" value={`×${settings.lightning}`} min={1} max={12} step={1} current={settings.lightning} onChange={(v) => update("lightning", v)} icon={<Zap />} />
            <Control label="Growth" value={`${(settings.growth * 100).toFixed(1)}%`} min={0.005} max={0.05} step={0.001} current={settings.growth} onChange={(v) => update("growth", v)} icon={<Sparkles />} />
            <Control label="Rain (patching)" value={`${(settings.rain * 100).toFixed(1)}%`} min={0} max={0.04} step={0.001} current={settings.rain} onChange={(v) => update("rain", v)} icon={<CloudRain />} />
            <Control label="Shared suppliers" value={`${settings.suppliers}`} min={0} max={5} step={1} current={settings.suppliers} onChange={(v) => update("suppliers", v)} icon={<span className="hub-icon">●</span>} />
          </div>
          {settings.suppliers > 0 ? <p className="supplier-note animate-fade-in">One lightning, many fires — like MOVEit.</p> : null}
        </div>
        <aside className="forest-stats">
          <div className="metrics-grid">
            <Metric label="Fires so far" value={fmt.format(stats.fires)} />
            <Metric label="Largest fire" value={`${fmt.format(stats.largest)} cells`} />
            <Metric label="Area burned by top 1%" value={`${Math.round(topShare * 100)}%`} />
            <Metric label="Fitted power-law α" value={alpha && Number.isFinite(alpha) ? alpha.toFixed(2) : "—"} />
          </div>
          <div className="histogram">
            <div className="panel-heading"><div><h3>Fire sizes</h3><p>log size × log frequency</p></div></div>
            {histogram.length > 1 ? (
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={histogram} margin={{ top: 8, right: 8, bottom: 4, left: 0 }}>
                  <CartesianGrid stroke="var(--grid)" />
                  <XAxis dataKey="size" scale="log" domain={[1, "dataMax"]} type="number" tickFormatter={compact.format} />
                  <YAxis scale="log" domain={[1, "dataMax"]} tickFormatter={compact.format} width={36} />
                  <Line dataKey="count" stroke="var(--fire)" strokeWidth={2.5} dot />
                  <Tooltip />
                </LineChart>
              </ResponsiveContainer>
            ) : <div className="empty-chart compact-empty"><p>Let the forest burn.</p></div>}
          </div>
          <div className="caption-stack">
            <p>12× more lightning barely matters if it rains.</p>
            <p>A single shared supplier creates the biggest fires.</p>
            <p>Fire sizes sketch a line on a log-log plot: a power law.</p>
          </div>
        </aside>
      </div>
    </section>
  );
}

function Control({ label, value, min, max, step, current, onChange, icon }: { label: string; value: string; min: number; max: number; step: number; current: number; onChange: (value: number) => void; icon: React.ReactNode }) {
  return (
    <label className="control">
      <span className="control-label"><span>{icon}{label}</span><strong>{value}</strong></span>
      <Slider min={min} max={max} step={step} value={[current]} onValueChange={([next]) => onChange(next)} />
    </label>
  );
}

const REAL_DATA = [
  { x: 1, healthcare: 100, losses: 100, reference: 100 },
  { x: 3, healthcare: 48.9, reference: 33.33 },
  { x: 10, healthcare: 17.7, losses: 18.8, reference: 10 },
  { x: 30, healthcare: 5.4, reference: 3.33 },
  { x: 100, healthcare: 1.13, losses: 4.2, reference: 1 },
  { x: 300, healthcare: 0.28, reference: 0.333 },
  { x: 1000, healthcare: 0.14, reference: 0.1 },
];

const GIANTS = [
  [1927, 0.07, "Change Healthcare · 192.7M · 2024"], [788, 0.16, "Anthem · 78.8M · 2015"],
  [622, 0.2, "Conduent · 62.2M · 2025"], [150, 0.75, "DentaQuest · 15.0M · 2026"],
  [148, 0.9, "Welltok · 14.8M · 2023 · MOVEit"], [139, 1.05, "Aflac · 13.9M · 2025"],
  [115, 1.25, "Optum360 · 11.5M · 2019"], [113, 1.48, "HCA Healthcare · 11.3M · 2023"],
  [110, 1.72, "Premera · 11.0M · 2015"], [103, 2, "LabCorp · 10.3M · 2019"],
].map(([x, y, name]) => ({ x: Number(x), y: Number(y), name: String(name), z: 60 }));

function RealData() {
  const [ruler, setRuler] = useState(10);
  return (
    <section id="data" className="story-section">
      <SectionIntro number="03" question="Does the real world leave the same fingerprint?">
        Put breach size on one logarithmic axis and rarity on the other. A straight-ish line is the tell.
      </SectionIntro>
      <div className="real-chart-wrap">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={REAL_DATA} margin={{ top: 24, right: 18, bottom: 30, left: 10 }}>
            <CartesianGrid stroke="var(--grid)" />
            <XAxis dataKey="x" type="number" scale="log" domain={[1, 2000]} ticks={[1, 3, 10, 30, 100, 300, 1000]} tickFormatter={(v) => `×${v}`} label={{ value: "Times larger than starting size", position: "bottom", offset: 12 }} />
            <YAxis type="number" scale="log" domain={[0.05, 100]} ticks={[0.1, 1, 10, 100]} tickFormatter={(v) => `${v}%`} width={46} />
            <Line dataKey="reference" name="1/x" stroke="var(--muted-foreground)" strokeDasharray="7 7" dot={false} connectNulls />
            <Line dataKey="healthcare" name="US healthcare · people" stroke="var(--fire)" strokeWidth={3} dot={{ r: 4 }} connectNulls />
            <Line dataKey="losses" name="All sectors · losses" stroke="var(--data-cool)" strokeWidth={3} dot={{ r: 4 }} connectNulls />
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
      <div className="legend-row"><span><i className="legend-fire" />US healthcare, from 100k people</span><span><i className="legend-cool" />All sectors, from $10M loss</span><span><i className="legend-dash" />1/x guide</span></div>
      <label className="ruler-control">
        <span><strong>Drag the ruler</strong><b>{ruler}× bigger → about {ruler}× rarer</b></span>
        <Slider min={0} max={3} step={1} value={[[1, 10, 100, 1000].indexOf(ruler)]} onValueChange={([index]) => setRuler([1, 10, 100, 1000][index])} />
      </label>
    </section>
  );
}

const CONCENTRATION = [
  [0.1, 22], [0.25, 31], [0.5, 42], [1, 57], [2, 67], [5, 79], [10, 88], [20, 94],
] as const;

function concentrationAt(x: number) {
  for (let i = 0; i < CONCENTRATION.length - 1; i += 1) {
    const [x1, y1] = CONCENTRATION[i]; const [x2, y2] = CONCENTRATION[i + 1];
    if (x >= x1 && x <= x2) return y1 + ((x - x1) / (x2 - x1)) * (y2 - y1);
  }
  return 94;
}

function OnePercent() {
  const [top, setTop] = useState(1);
  const share = concentrationAt(top);
  return (
    <section id="one-percent" className="story-section concentration-section">
      <SectionIntro number="04" question="How much can the biggest 1% decide?">
        Choose a thin slice of the largest breaches. Then see how much of the human impact sits inside it.
      </SectionIntro>
      <div className="concentration-viz">
        <div className="big-answer"><span>Top {top < 1 ? top.toFixed(1) : top.toFixed(top % 1 ? 1 : 0)}% of breaches account for</span><strong>{Math.round(share)}%</strong><span>of all people affected</span></div>
        <div className="share-bar" aria-label={`${Math.round(share)} percent of people affected`}><div style={{ width: `${share}%` }} /></div>
        <label className="wide-control"><span>top X% of breaches</span><Slider min={0.1} max={20} step={0.1} value={[top]} onValueChange={([value]) => setTop(value)} /></label>
        <div className="range-labels"><span>0.1%</span><Button variant="outline" size="sm" onClick={() => setTop(1)}>Snap to 1%</Button><span>20%</span></div>
      </div>
      <aside className="fact-strip"><span className="fact-number">22%</span><p>The single largest breach — Change Healthcare — accounts for <strong>22% of everyone affected since 2016.</strong></p></aside>
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
    const css = getComputedStyle(canvas);
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
  const [growth, setGrowth] = useState(1);
  const [share, setShare] = useState(0.12);
  const [seed, setSeed] = useState(710);
  const k = (1 - share) + share * growth;
  const { points, probability } = useMemo(() => {
    const rng = mulberry32(seed + Math.round(k * 1000)); const all: FuturePoint[] = []; let futuresWithGiant = 0;
    for (let future = 0; future < 1000; future += 1) {
      let giantBy2031 = false;
      for (let year = 2027; year <= 2031; year += 1) {
        const count = poisson(18.9 * k, rng);
        for (let i = 0; i < count; i += 1) {
          const size = Math.min(340_000_000, 1_000_000 * Math.pow(Math.max(rng(), 0.000001), -1 / 1.03));
          if (size >= 100_000_000 && year < 2031) giantBy2031 = true;
          if (size >= 7_000_000) all.push({ future, year, size });
        }
      }
      if (giantBy2031) futuresWithGiant += 1;
    }
    return { points: all, probability: futuresWithGiant / 10 };
  }, [growth, share, seed, k]);

  const applyPreset = (name: "Rain" | "Vulnpocalypse" | "Extreme") => {
    if (name === "Rain") { setGrowth(1); setShare(0.12); }
    if (name === "Vulnpocalypse") { setGrowth(2.2); setShare(0.31); }
    if (name === "Extreme") { setGrowth(5.7); setShare(0.31); }
  };

  return (
    <section id="futures" className="story-section futures-section">
      <SectionIntro number="05" question="What happens across a thousand possible futures?">
        Turn up vulnerability exploitation. Each row is one possible 2027–2031; every dot is a breach above seven million people.
      </SectionIntro>
      <div className="future-answer"><span>Chance of at least one 100M+ breach<br />by the start of 2031</span><strong>{probability.toFixed(0)}%</strong></div>
      <div className="year-labels"><span>2027</span><span>2028</span><span>2029</span><span>2030</span><span>2031</span></div>
      <FuturesCanvas points={points} />
      <div className="future-controls">
        <Control label="Exploitation growth" value={`×${growth.toFixed(1)}`} min={1} max={6} step={0.1} current={growth} onChange={setGrowth} icon={<Zap />} />
        <Control label="Breaches starting with a vulnerability" value={`${Math.round(share * 100)}%`} min={0.12} max={0.31} step={0.01} current={share} onChange={setShare} icon={<span className="hub-icon">%</span>} />
      </div>
      <div className="scenario-summary"><span>Risk multiplier <strong>k = {k.toFixed(2)}</strong></span><Button variant="ghost" size="sm" onClick={() => setSeed((v) => v + 1)}><RefreshCw />Run again</Button></div>
      <div className="preset-row centered">{(["Rain", "Vulnpocalypse", "Extreme"] as const).map((name) => <Button key={name} variant="outline" onClick={() => applyPreset(name)}>{name}</Button>)}</div>
    </section>
  );
}

const NAV = [["average", "Average"], ["forest", "Forest"], ["data", "Real data"], ["one-percent", "The 1%"], ["futures", "Futures"]] as const;

export function BreachStory() {
  return (
    <main>
      <nav className="story-nav" aria-label="Story sections">
        <a href="#top" className="story-mark"><Flame />HEAVY TAILS</a>
        <div>{NAV.map(([id, label], index) => <a key={id} href={`#${id}`}><span>{index + 1}</span>{label}</a>)}</div>
      </nav>
      <header id="top" className="story-hero">
        <div className="hero-kicker"><span>AN INTERACTIVE EXPERIMENT</span><span>5 QUESTIONS · REAL DATA</span></div>
        <h1>The Forest Fire<br />of Cyber Breaches</h1>
        <p>Why one breach can outweigh a thousand.</p>
        <a href="#average" className="start-link">Start with a guess <ArrowDown /></a>
        <div className="hero-rules" aria-hidden="true"><i /><i /><i /><i /><i /></div>
      </header>
      <GuessAverage />
      <ForestFire />
      <RealData />
      <OnePercent />
      <ThousandFutures />
      <footer className="methods">
        <div><span className="section-number">METHODS</span><h2>What’s measured — and what’s modelled?</h2></div>
        <div className="methods-grid">
          <div><strong>Measured</strong><p>Breach sizes and counts: US healthcare from the HHS registry; documented losses across sectors from EuRepoC.</p></div>
          <div><strong>Modelled</strong><p>The forest-fire mechanism and the thousand futures. They are thought experiments, not forecasts.</p></div>
        </div>
        <p className="methods-note">Breach numbers are US healthcare only. Vulnerabilities start only 12–31% of breaches; phishing and stolen passwords cause most of the rest.</p>
        <a className="article-link" href="#top">Read the full article <span>↗</span></a>
      </footer>
    </main>
  );
}