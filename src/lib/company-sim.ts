// Deterministic event replay behind the Section 01 "company under attack" canvas.
// Every lightning strike walks the same funnel as the calculator, with the same
// probabilities: race (patched in time?) -> hardening -> SOC -> breach (small/large).
// Strikes arrive at the model's real yearly rate, so over many simulated years the
// canvas counts converge to the formulas (λ, P(year), P(5 years), large share).
import type { CompanyInputs, CompanyResult } from "./company-risk";

export type Rng = () => number;

export function mulberry32(seed: number): Rng {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

type Funnel = { strikes: number; win: number; pass: number; escape: number };

export type SimParams = {
  vendor: Funnel;
  own: Funnel;
  largeShare: number;
  spreadPerDay: number; // lateral movement speed: network segmentation / hardening
  crews: number;
  inHouseShare: number;
};

// Visual only: how fast a breach moves laterally at each hardening/segmentation level.
const SEGMENTATION_SPREAD = [1.4, 1.0, 0.7, 0.45, 0.3];

const safe = (a: number, b: number) => (b > 0 ? Math.min(1, a / b) : 0);

function funnel(ch: CompanyResult["vendor"]): Funnel {
  // If the race share exceeds 1 (own code at high attacker AI), raise the strike count
  // so expected race wins stay exactly ch.winsRace.
  const strikes = Math.max(ch.lightning, ch.winsRace);
  return { strikes, win: safe(ch.winsRace, strikes), pass: safe(ch.pastHardening, ch.winsRace), escape: safe(ch.breaches, ch.pastHardening) };
}

export function simParams(c: CompanyInputs, r: CompanyResult): SimParams {
  return {
    vendor: funnel(r.vendor),
    own: funnel(r.own),
    largeShare: r.largeShare,
    spreadPerDay: SEGMENTATION_SPREAD[c.hardening] ?? 1,
    crews: Math.max(0, c.soc),
    inHouseShare: c.inHouse,
  };
}

export const OK = 0;
export const VULN = 1;
export const BURNING = 2;
export const BURNED = 3;

export type Outcome = "patched" | "blocked" | "contained" | "small" | "large";

export type Cell = { state: number; own: boolean; until: number; fire: number; struckAt: number; outcome: Outcome | null };
export type Fire = { id: number; cells: number[]; target: number; kind: Outcome; start: number; origin: number; spreadAcc: number };
export type Crew = { x: number; y: number };

export type Counts = { strikes: number; patched: number; blocked: number; contained: number; small: number; large: number };

export type Sim = {
  cols: number;
  rows: number;
  cells: Cell[];
  fires: Fire[];
  crews: Crew[];
  rng: Rng;
  day: number;
  nextStrike: number;
  nextFire: number;
  counts: Counts;
  breachYears: number[]; // breaches per simulated year (index = year - 1)
  params: SimParams;
};

const totalRate = (p: SimParams) => p.vendor.strikes + p.own.strikes;

function nextGap(sim: Sim) {
  const rate = totalRate(sim.params);
  if (rate <= 0) return Infinity;
  return (-Math.log(1 - sim.rng()) / rate) * 365; // Poisson process, days
}

export function createSim(cols: number, rows: number, seed: number, params: SimParams): Sim {
  const rng = mulberry32(seed);
  const cells: Cell[] = [];
  for (let i = 0; i < cols * rows; i += 1) {
    cells.push({ state: OK, own: rng() < params.inHouseShare, until: 0, fire: 0, struckAt: -Infinity, outcome: null });
  }
  const sim: Sim = {
    cols, rows, cells, fires: [], crews: [], rng, day: 0, nextStrike: 0, nextFire: 1,
    counts: { strikes: 0, patched: 0, blocked: 0, contained: 0, small: 0, large: 0 },
    breachYears: [0], params,
  };
  for (let k = 0; k < params.crews; k += 1) sim.crews.push({ x: cols / 2, y: rows / 2 });
  sim.nextStrike = nextGap(sim);
  return sim;
}

function neighbors(sim: Sim, i: number): number[] {
  const { cols, rows } = sim;
  const x = i % cols;
  const y = Math.floor(i / cols);
  const out: number[] = [];
  if (x > 0) out.push(i - 1);
  if (x < cols - 1) out.push(i + 1);
  if (y > 0) out.push(i - cols);
  if (y < rows - 1) out.push(i + cols);
  return out;
}

function pickCell(sim: Sim, own: boolean) {
  const { cells, rng } = sim;
  for (let t = 0; t < 40; t += 1) {
    const i = Math.floor(rng() * cells.length);
    const c = cells[i];
    if (c && c.state === OK && (c.own === own || t > 20)) return i;
  }
  return -1;
}

function burn(sim: Sim, i: number, fire: Fire) {
  const c = sim.cells[i];
  if (!c) return;
  c.state = BURNING;
  c.fire = fire.id;
  c.until = sim.day + 10 + sim.rng() * 6;
  fire.cells.push(i);
}

function strike(sim: Sim) {
  const { rng, params } = sim;
  const own = rng() < safe(params.own.strikes, totalRate(params));
  const f = own ? params.own : params.vendor;
  // decide the whole funnel up front (same probabilities as the formulas)
  let outcome: Outcome;
  if (rng() >= f.win) outcome = "patched";
  else if (rng() >= f.pass) outcome = "blocked";
  else if (rng() >= f.escape) outcome = "contained";
  else outcome = rng() < params.largeShare ? "large" : "small";

  sim.counts.strikes += 1;
  sim.counts[outcome] += 1;
  if (outcome === "small" || outcome === "large") {
    const y = Math.floor(sim.day / 365);
    sim.breachYears[y] = (sim.breachYears[y] ?? 0) + 1;
  }

  const i = pickCell(sim, own);
  if (i < 0) return;
  const c = sim.cells[i]!;
  c.struckAt = sim.day;
  c.outcome = outcome;
  if (outcome === "patched") return; // lightning hits a patched system: nothing happens
  if (outcome === "blocked") {
    c.state = VULN; // exploit lands, hardening stops it
    c.until = sim.day + 12;
    return;
  }
  const n = sim.cells.length;
  const target = outcome === "contained" ? 1 + Math.floor(rng() * 2)
    : outcome === "small" ? 3 + Math.floor(rng() * 5)
    : Math.min(Math.floor(n * 0.35), 30 + Math.floor(rng() * 40));
  const fire: Fire = { id: sim.nextFire++, cells: [], target, kind: outcome, start: sim.day, origin: i, spreadAcc: 0 };
  sim.fires.push(fire);
  burn(sim, i, fire);
}

export function stepSim(sim: Sim, dt: number) {
  const { cells, rng, params } = sim;
  sim.day += dt;
  const year = Math.floor(sim.day / 365);
  while (sim.breachYears.length <= year) sim.breachYears.push(0);

  while (sim.day >= sim.nextStrike) {
    strike(sim);
    sim.nextStrike += nextGap(sim);
  }

  // lateral movement: speed depends on segmentation, size on the decided outcome
  for (const fire of sim.fires) {
    if (fire.cells.length >= fire.target) continue;
    fire.spreadAcc += params.spreadPerDay * dt * (fire.kind === "large" ? 2 : 1);
    while (fire.spreadAcc >= 1 && fire.cells.length < fire.target) {
      fire.spreadAcc -= 1;
      const frontier = fire.cells.flatMap((k) => neighbors(sim, k)).filter((k) => cells[k]?.state === OK);
      if (!frontier.length) { fire.target = fire.cells.length; break; }
      burn(sim, frontier[Math.floor(rng() * frontier.length)]!, fire);
    }
  }

  // SOC crews head for contained footholds and put them out on arrival
  const contained = sim.fires.filter((f) => f.kind === "contained" && f.cells.some((k) => cells[k]?.state === BURNING));
  sim.crews.forEach((crew, ci) => {
    const fire = contained[ci % Math.max(1, contained.length)];
    const home = { x: ((ci + 1) * sim.cols) / (sim.crews.length + 1), y: sim.rows / 2 };
    const tx = fire ? fire.origin % sim.cols : home.x;
    const ty = fire ? Math.floor(fire.origin / sim.cols) : home.y;
    const dx = tx - crew.x, dy = ty - crew.y, dist = Math.hypot(dx, dy);
    const speed = 4 * dt;
    if (dist > 0.01) { crew.x += (dx / dist) * Math.min(speed, dist); crew.y += (dy / dist) * Math.min(speed, dist); }
    if (fire && dist < 0.6) {
      for (const k of fire.cells) { const c = cells[k]; if (c && c.state === BURNING) { c.state = BURNED; c.until = sim.day + 15; } }
    }
  });

  for (const c of cells) {
    if (c.state === VULN && sim.day >= c.until) c.state = OK;
    else if (c.state === BURNING && sim.day >= c.until) { c.state = BURNED; c.until = sim.day + 40; }
    else if (c.state === BURNED && sim.day >= c.until) { c.state = OK; c.fire = 0; }
  }
  sim.fires = sim.fires.filter((f) => f.cells.some((k) => cells[k]?.state === BURNING) || f.cells.length < f.target && sim.day - f.start < 60);
}

/** Canvas statistics over completed simulated years, for comparison with the formulas. */
export function simStats(sim: Sim) {
  const done = Math.floor(sim.day / 365);
  const years = sim.breachYears.slice(0, done);
  const breaches = years.reduce((a, b) => a + b, 0);
  const yearsHit = years.filter((b) => b > 0).length;
  let windows = 0, windowsHit = 0;
  for (let y = 0; y + 5 <= years.length; y += 1) {
    windows += 1;
    if (years.slice(y, y + 5).some((b) => b > 0)) windowsHit += 1;
  }
  const allBreaches = sim.counts.small + sim.counts.large;
  return {
    year: done + 1,
    years: done,
    perYear: done ? breaches / done : 0,
    pYear: done ? yearsHit / done : 0,
    yearsHit,
    p5: windows ? windowsHit / windows : 0,
    windows,
    largeShare: allBreaches ? sim.counts.large / allBreaches : 0,
    counts: { ...sim.counts },
  };
}
export type SimStats = ReturnType<typeof simStats>;
