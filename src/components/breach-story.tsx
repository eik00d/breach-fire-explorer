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
import { DEFAULT_COMPANY, MEDIAN_DAYS_TO_KEV, OWN_BASE_ATTACKER_WIN, VENDOR_ZERO_DAY_SHARE, computeRisk, type CompanyInputs } from "@/lib/company-risk";

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
  "Fortress": { vendorVulns: 6, neverPatched: 0.02, patchDays: 5, appsec: 3, bountyK: 500, hardening: 4, soc: 3, governance: 3, inHouse: 0.5, threat: 1, vendorGrowth: 1 },
};

const pct = (p: number) => (p < 0.001 ? "<0.1%" : `${(p * 100).toFixed(p < 0.1 ? 1 : 0)}%`);
const rate = (x: number) => x.toFixed(x < 0.1 ? 3 : 2);

function MyCompany() {
  const [c, setC] = useState<CompanyInputs>(DEFAULT_COMPANY);
  const r = useMemo(() => computeRisk(c), [c]);
  const set = <K extends keyof CompanyInputs>(key: K, value: number) => setC((prev) => ({ ...prev, [key]: value }));
  const vendorGrowth = c.vendorGrowth ?? DEFAULT_COMPANY.vendorGrowth;

  const lanes = [
    { name: "Race 1 · vendor software", sub: `${Math.round(VENDOR_ZERO_DAY_SHARE * 100)}% zero-days, then your patch (${c.patchDays} d) vs CISA listing (${MEDIAN_DAYS_TO_KEV} d median)`, ch: r.vendor },
    { name: "Race 2 · your own code", sub: `baseline attacker win share ${Math.round(OWN_BASE_ATTACKER_WIN * 100)}% (assumption), then attacker AI vs AppSec + bounty`, ch: r.own },
  ];
  const max = Math.max(0.01, r.vendor.lightning, r.own.lightning);

  return (
    <section id="company" className="story-section">
      <SectionIntro number="01" question="Will lightning strike your company?">
        Every year some exploited vulnerabilities land on software you run — that’s the lightning. Then two races decide what happens. In vendor software, can you patch before the exploit arrives? In your own code, do you find the bug before attackers do? Whatever gets through still has to beat your hardening and your detection team. Set up your company and watch the odds.
      </SectionIntro>
      <div className="forest-layout">
        <div>
          <div className="preset-row">
            {Object.entries(COMPANY_PRESETS).map(([name, preset]) => <Button key={name} size="sm" variant="outline" onClick={() => setC({ ...preset })}>{name}</Button>)}
          </div>
          <p className="preset-explainer">At 40% in-house code and today’s vendor rate (×1), patching is the main risk. At 80% in-house and attacker AI ×5 without AppSec, your own code becomes the main risk.</p>
          <div className="side-blocks">
            <div className="ad-block" data-side="attack">
              <div className="ad-head"><Zap /><span>Attack</span><small>what comes at you — you can’t patch it away</small></div>
              <Control label="Exploited vendor vulns in your stack / yr" value={`${c.vendorVulns}`} min={1} max={30} step={1} current={c.vendorVulns} onChange={(v) => set("vendorVulns", v)} icon={<Zap />} />
              <Control label="Vendor exploitation growth" value={`×${vendorGrowth.toFixed(1)}`} min={1} max={3} step={0.1} current={vendorGrowth} onChange={(v) => set("vendorGrowth", v)} icon={<Zap />} />
              <Control label="Attacker AI on your own code" value={`×${c.threat.toFixed(1)}`} min={1} max={6} step={0.1} current={c.threat} onChange={(v) => set("threat", v)} icon={<Zap />} />
              <Control label="Built in-house (with AI) vs vendors" value={`${Math.round(c.inHouse * 100)}% / ${Math.round((1 - c.inHouse) * 100)}%`} min={0} max={1} step={0.05} current={c.inHouse} onChange={(v) => set("inHouse", v)} icon={<Zap />} />
            </div>
            <div className="ad-block" data-side="defense">
              <div className="ad-head"><Shield /><span>Defense</span><small>what you control</small></div>
              <Control label="Days to patch (median)" value={`${c.patchDays} days`} min={1} max={180} step={1} current={c.patchDays} onChange={(v) => set("patchDays", v)} icon={<Shield />} />
              <Control label="Never patched" value={`${Math.round(c.neverPatched * 100)}%`} min={0} max={0.6} step={0.01} current={c.neverPatched} onChange={(v) => set("neverPatched", v)} icon={<Shield />} />
              <Control label="AI SAST / DAST" value={APPSEC_LABELS[c.appsec] ?? ""} min={0} max={3} step={1} current={c.appsec} onChange={(v) => set("appsec", v)} icon={<Shield />} />
              <Control label="Bug bounty budget" value={c.bountyK ? `$${c.bountyK}k / year` : "none"} min={0} max={1000} step={25} current={c.bountyK} onChange={(v) => set("bountyK", v)} icon={<Shield />} />
              <Control label="Isolation & hardening" value={HARDENING_LABELS[c.hardening] ?? ""} min={0} max={4} step={1} current={c.hardening} onChange={(v) => set("hardening", v)} icon={<Shield />} />
              <Control label="Detect & respond (SOC)" value={SOC_LABELS[c.soc] ?? ""} min={0} max={3} step={1} current={c.soc} onChange={(v) => set("soc", v)} icon={<Shield />} />
              <Control label="Data governance / privacy" value={GOV_LABELS[c.governance] ?? ""} min={0} max={3} step={1} current={c.governance} onChange={(v) => set("governance", v)} icon={<Shield />} />
            </div>
          </div>
          <div className="race-lanes">
            {lanes.map(({ name, sub, ch }, lane) => (
              <div key={name} className="race-lane">
                <div className="race-head"><strong>{name}</strong><small>{sub}</small></div>
                {[
                  ["Lightning hits you", ch.lightning],
                  [lane === 0 ? `Attacker wins the race (${pct(ch.raceP)})` : `Race outcome (×${ch.raceP.toFixed(2)} vs today)`, ch.winsRace],
                  ["Reachable & past hardening", ch.pastHardening],
                  ["Not contained → breach", ch.breaches],
                ].map(([label, value]) => (
                  <div key={label as string} className="race-row">
                    <span>{label}</span>
                    <div className="race-bar"><i style={{ width: `${Math.max(0.5, (value as number) / max * 100)}%` }} /></div>
                    <b>{rate(value as number)}/yr</b>
                  </div>
                ))}
              </div>
            ))}
          </div>
          <p className="patch-note">Exploits arrive fast: about half of exploited vulnerabilities are added to CISA’s list within two weeks of publication — real exploitation often starts earlier. About 19% are exploited before any patch exists, so no patch speed beats those.</p>
        </div>
        <aside className="forest-stats">
          <div className="metrics-grid">
            <Metric label="Breach this year" value={pct(r.pYear)} />
            <Metric label="Breach within 5 years" value={pct(r.p5)} />
            <Metric label="Expected breaches / year" value={rate(r.lambda)} detail={`vendor ${rate(r.vendor.breaches)} · own ${rate(r.own.breaches)}`} />
            <Metric label="Large data breach, 5 years" value={pct(r.pLarge5)} detail={`${pct(r.largeShare)} of breaches turn large`} />
            <Metric label="Implied all-cause breaches / yr" value={`${rate(r.allCause[0])}–${rate(r.allCause[1])}`} detail="calibration check: λ ÷ 12–31% vulnerability share" />
          </div>
          <div className="formula-box">
            <p><b>λ</b> = L<sub>v</sub>·p<sub>v</sub>·h·(1−c) + L<sub>o</sub>·R<sub>o</sub>·h·(1−c), h = e·h<sub>H</sub></p>
            <p>L<sub>v</sub> = N<sub>v</sub>·(1−f)·k<sub>v</sub>, where k<sub>v</sub> = ×{vendorGrowth.toFixed(1)}</p>
            <p>p<sub>v</sub> = z<sub>v</sub> + (1−z<sub>v</sub>)·[u + (1−u)·D<sub>p</sub>/(D<sub>p</sub>+14)] = {r.vendor.raceP.toFixed(2)}</p>
            <p>L<sub>o</sub> = N<sub>o</sub>·f = {r.own.lightning.toFixed(2)}</p>
            <p>s<sub>o</sub> = m·z<sub>o</sub> / (m·z<sub>o</sub> + D·(1−z<sub>o</sub>)), z<sub>o</sub> = {OWN_BASE_ATTACKER_WIN.toFixed(2)} (assumption)</p>
            <p>R<sub>o</sub> = (s<sub>o</sub>/z<sub>o</sub>) / D = ×{r.own.raceP.toFixed(2)} vs today</p>
            <p>P(year) = 1 − e<sup>−λ</sup> = {pct(r.pYear)}</p>
          </div>
          <div className="caption-stack">
            <p>Vendor exploitation is about ×1 in the data so far. Move it toward ×2.2 to play the article’s vendor vulnpocalypse scenario; patching still helps, but zero-days remain.</p>
            <p>As attackers’ AI grows, your own code gets riskier unless your own bug-finding grows too. Code nobody scans is the biggest risk.</p>
            <p>Segmentation and a SOC cut both how often and how big; data governance only how big.</p>
            <p>The rates here are illustrative assumptions, not measured. The point is the shape: two races, then your controls.</p>
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
      <Slider min={min} max={max} step={step} value={[current]} onValueChange={([next]) => onChange(next ?? current)} />
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
];

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
        Put breach size on one logarithmic axis and rarity on the other. A straight-ish line is the tell.
      </SectionIntro>
      <div className="real-chart-wrap">
        <ResponsiveContainer width="100%" height="100%">
          <ComposedChart data={REAL_DATA} margin={{ top: 24, right: 18, bottom: 30, left: 10 }}>
            <CartesianGrid stroke="var(--grid)" />
            <XAxis dataKey="x" type="number" scale="log" domain={[1, 2000]} ticks={[1, 2, 10, 20, 100, 200, 1000]} tickFormatter={(v) => `×${v}`} label={{ value: "Times larger than starting size", position: "bottom", offset: 12 }} />
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
  const [growth, setGrowth] = useState(1);
  const [share, setShare] = useState(0.12);
  const [seed, setSeed] = useState(34);
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
      <SectionIntro number="04" question="What happens across a thousand possible futures?">
        Each row is one possible 2027–2031; every dot is a breach of 7 million people or more (smaller ones are simulated but not drawn).
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
          <div><strong>Modelled</strong><p>The “my company” risk calculator and the thousand futures. They are thought experiments, not forecasts.</p></div>
          <div><strong>Inferred</strong><p>MOVEit’s role was checked by victim name for the largest 2023 breaches; public registries do not connect most breaches to a specific vulnerability.</p></div>
        </div>
        <p className="methods-note">Breach numbers are US healthcare only. Vulnerabilities start only 12–31% of breaches; phishing and stolen passwords cause most of the rest. The company calculator follows that vulnerability channel only; its rates are illustrative assumptions.</p>
        <a className="article-link" href="#top">Read the full article <span>↗</span></a>
      </footer>
    </main>
  );
}