// Deterministic event replay behind the Section 01 "company under attack" canvas.
// Every lightning strike walks the same funnel as the calculator, with the same
// probabilities: race (patched in time?) -> hardening -> SOC -> breach (small/large).
// Strikes arrive at the model's real yearly rate, so over many simulated years the
// canvas counts converge to the formulas (λ, P(year), P(5 years), large share).
import { APPSEC_FIND_RATE, BOUNTY_HALF_K, BOUNTY_MAX_RATE, MEDIAN_DAYS_TO_KEV, VENDOR_ZERO_DAY_SHARE, type CompanyInputs, type CompanyResult } from "./company-risk";

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
  vendorPatchDays: number; // patch time slider
  ownFixDays: number; // AppSec + bug bounty: how fast you find and fix your own bugs
  neverPatched: number; // share of vendor systems never patched
  exploitDays: number; // attacker exploit delay, shrinks with attacker AI
  zeroDay: number;
  largeSize: number; // governance: how much data one large breach reaches
  sectors: number; // visual: network segments from the hardening slider
};

// Visual only: how fast a breach moves laterally at each hardening/segmentation level.
const SEGMENTATION_SPREAD = [1.4, 1.0, 0.7, 0.45, 0.3];
// Visual only: how many network segments each hardening level draws.
const SEGMENT_COUNT = [1, 3, 6, 10, 16];
// Visual only: data governance limits how far a large breach reaches.
const GOV_LARGE_SIZE = [70, 50, 35, 22];
const OWN_FIX_BASE_DAYS = 90; // visual fix time for own bugs without AppSec / bounty

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
    spreadPerDay: (SEGMENTATION_SPREAD[c.hardening] ?? 1) * Math.pow(Math.max(1, c.threat), 0.3),
    vendorPatchDays: c.patchDays,
    ownFixDays: OWN_FIX_BASE_DAYS / (1 + (APPSEC_FIND_RATE[c.appsec] ?? 0) + BOUNTY_MAX_RATE * c.bountyK / (c.bountyK + BOUNTY_HALF_K)),
    neverPatched: c.neverPatched,
    exploitDays: MEDIAN_DAYS_TO_KEV / Math.pow(Math.max(1, c.threat), 0.5),
    zeroDay: VENDOR_ZERO_DAY_SHARE,
    largeSize: GOV_LARGE_SIZE[c.governance] ?? 40,
    sectors: SEGMENT_COUNT[c.hardening] ?? 3,
    crews: Math.max(0, c.soc),
    inHouseShare: c.inHouse,
  };
}

export const OK = 0;
export const VULN = 1;
export const BURNING = 2;
export const BURNED = 3;

export type Outcome = "patched" | "blocked" | "contained" | "small" | "large";

export type Cell = { state: number; own: boolean; until: number; fire: number; struckAt: number; vulnAt: number; outcome: Outcome | null; patchAt: number; exploitAt: number; never: boolean };

// Visual only: the standing share of systems sitting in their patch window at any
// moment, so vulnerabilities are visible between strikes. Grows with patch time and
// the never-patched share; the funnel probabilities (and the stats) are untouched.
function vulnShare(p: SimParams, own: boolean) {
  const windowDays = own ? p.ownFixDays : p.vendorPatchDays;
  const base = own ? 0.05 : 0.06 + p.neverPatched * 0.5;
  return Math.min(0.3, base + (windowDays / 365) * 0.5);
}
export type Fire = { id: number; cells: number[]; target: number; kind: Outcome; start: number; origin: number; spreadAcc: number; crew: number; arrived: number; sector: number };
export type Crew = { x: number; y: number; fire: number; hx: number; hy: number };
export type Burst = { x: number; y: number; at: number; saved: boolean };

export type Counts = { strikes: number; patched: number; blocked: number; contained: number; small: number; large: number };

export type Sim = {
  cols: number;
  rows: number;
  cells: Cell[];
  fires: Fire[];
  crews: Crew[];
  sector: number[]; // segment id per cell
  sectorSize: number[];
  bursts: Burst[];
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
    cells.push({ state: OK, own: rng() < params.inHouseShare, until: 0, fire: 0, struckAt: -Infinity, vulnAt: 0, outcome: null, patchAt: Infinity, exploitAt: Infinity, never: false });
  }
  const sim: Sim = {
    cols, rows, cells, fires: [], crews: [], sector: [], sectorSize: [], bursts: [], rng, day: 0, nextStrike: 0, nextFire: 1,
    counts: { strikes: 0, patched: 0, blocked: 0, contained: 0, small: 0, large: 0 },
    breachYears: [0], params,
  };
  makeSectors(sim, params.sectors);
  for (let k = 0; k < params.crews; k += 1) {
    const hx = ((k + 1) * cols) / (params.crews + 1) - 0.5, hy = rows / 2 - 0.5;
    sim.crews.push({ x: hx, y: hy, fire: 0, hx, hy });
  }
  // seed the standing patch backlog so vulnerabilities are visible from the start
  for (let i = 0; i < cells.length; i += 1) {
    const c = cells[i]!;
    if (rng() < vulnShare(params, c.own)) {
      c.state = VULN;
      c.vulnAt = -rng() * 30;
      c.never = !c.own && rng() < params.neverPatched;
      c.patchAt = c.never ? Infinity : rng() * (c.own ? params.ownFixDays : params.vendorPatchDays);
    }
  }
  sim.nextStrike = nextGap(sim);
  return sim;
}

/** Uneven network segments: keep splitting the biggest block at a random cut. */
function makeSectors(sim: Sim, n: number) {
  const { rng, cols, rows } = sim;
  const blocks = [{ x: 0, y: 0, w: cols, h: rows }];
  while (blocks.length < n) {
    blocks.sort((a, b) => b.w * b.h - a.w * a.h);
    const b = blocks.shift()!;
    const cut = 0.25 + rng() * 0.5;
    if (b.w >= b.h && b.w >= 2) {
      const w1 = Math.max(1, Math.min(b.w - 1, Math.round(b.w * cut)));
      blocks.push({ ...b, w: w1 }, { ...b, x: b.x + w1, w: b.w - w1 });
    } else if (b.h >= 2) {
      const h1 = Math.max(1, Math.min(b.h - 1, Math.round(b.h * cut)));
      blocks.push({ ...b, h: h1 }, { ...b, y: b.y + h1, h: b.h - h1 });
    } else { blocks.push(b); break; }
  }
  sim.sector = new Array(cols * rows).fill(0);
  sim.sectorSize = blocks.map((b) => b.w * b.h);
  blocks.forEach((b, id) => {
    for (let y = b.y; y < b.y + b.h; y += 1) for (let x = b.x; x < b.x + b.w; x += 1) sim.sector[y * cols + x] = id;
  });
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
  // strikes aim at systems already sitting in their patch window; fall back to any
  // idle system of the right kind, then any idle system at all
  for (let t = 0; t < 60; t += 1) {
    const i = Math.floor(rng() * cells.length);
    const c = cells[i];
    if (!c) continue;
    if (t < 30 && c.state === VULN && c.outcome === null && c.own === own) return i;
    if (t >= 30 && c.state === OK && (c.own === own || t > 50)) return i;
  }
  return -1;
}

/** A system enters its patch window on its own (visual background churn). */
function makeVuln(sim: Sim, i: number) {
  const c = sim.cells[i];
  if (!c || c.state !== OK) return;
  const windowDays = c.own ? sim.params.ownFixDays : sim.params.vendorPatchDays;
  c.state = VULN;
  c.outcome = null;
  c.vulnAt = sim.day;
  // cap permanent vulnerabilities at the never-patched share of vendor systems,
  // otherwise they accumulate without bound over long runs
  const vendorCells = sim.cells.filter((k) => !k.own);
  const neverNow = vendorCells.filter((k) => k.state === VULN && k.never).length;
  const neverAllowed = neverNow < sim.params.neverPatched * vendorCells.length;
  c.never = !c.own && neverAllowed && sim.rng() < sim.params.neverPatched * 2;
  c.patchAt = c.never ? Infinity : sim.day + windowDays * (0.5 + sim.rng());
  c.exploitAt = Infinity;
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
  // Visual race: a patch countdown (vendor patch days, or own-code fix time from
  // AppSec + bounty) against the exploit (faster with attacker AI). The winner was
  // decided above with the model's probabilities; timings only show it.
  const fixIn = (own ? params.ownFixDays : params.vendorPatchDays) * (0.6 + 0.8 * rng());
  c.state = VULN;
  if (c.vulnAt === 0 && c.patchAt === Infinity) c.vulnAt = sim.day; // freshly struck idle system
  if (outcome === "patched") {
    c.never = false;
    c.patchAt = sim.day + fixIn;
    c.exploitAt = Infinity;
  } else {
    c.never = c.never || (!own && rng() < Math.min(1, params.neverPatched / Math.max(0.01, f.win)));
    const zero = !own && rng() < params.zeroDay;
    c.exploitAt = sim.day + (zero ? 1 : Math.min(fixIn * 0.9, params.exploitDays * (0.3 + rng())));
    c.patchAt = c.never ? Infinity : sim.day + fixIn;
  }
}

function land(sim: Sim, i: number) {
  const { rng } = sim;
  const c = sim.cells[i]!;
  const outcome = c.outcome!;
  c.exploitAt = Infinity;
  if (outcome === "blocked") {
    c.state = OK; // hardening stops the exploit
    c.struckAt = sim.day;
    c.outcome = "blocked";
    return;
  }
  const sector = sim.sector[i] ?? 0;
  const secSize = sim.sectorSize[sector] ?? 1;
  // small breach: lateral movement burns out its own segment (capped in a flat network);
  // large breach: jumps segment walls until it reaches the data governance allows
  const target = outcome === "contained" ? 1
    : outcome === "small" ? Math.min(secSize, 6 + Math.floor(rng() * 14))
    : Math.min(Math.floor(sim.cells.length * 0.5), Math.max(secSize + 4, sim.params.largeSize + Math.floor(rng() * 15)));
  const fire: Fire = { id: sim.nextFire++, cells: [], target, kind: outcome, start: sim.day, origin: i, spreadAcc: 0, crew: -1, arrived: 0, sector };
  sim.fires.push(fire);
  burn(sim, i, fire);
  if (outcome === "contained") sim.cells[i]!.until = sim.day + 60; // smoulders until the crew lands
  // dispatch the nearest idle SOC crew
  const ox = i % sim.cols, oy = Math.floor(i / sim.cols);
  let best = -1, bestD = Infinity;
  sim.crews.forEach((c, k) => { const d = Math.hypot(c.x - ox, c.y - oy); if (c.fire === 0 && d < bestD) { bestD = d; best = k; } });
  if (best >= 0) { fire.crew = best; sim.crews[best]!.fire = fire.id; }
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
      const open = fire.cells.flatMap((k) => neighbors(sim, k)).filter((k) => cells[k]?.state === OK);
      // segment walls hold unless the breach is large
      const inside = open.filter((k) => sim.sector[k] === fire.sector || sim.sector[k] === sim.sector[fire.cells[fire.cells.length - 1]!]);
      const frontier = fire.kind === "large" ? (inside.length && rng() < 0.7 ? inside : open) : open.filter((k) => sim.sector[k] === fire.sector);
      if (!frontier.length) { fire.target = fire.cells.length; break; }
      burn(sim, frontier[Math.floor(rng() * frontier.length)]!, fire);
    }
  }

  // SOC crews jump to the incident they were dispatched to. Contained footholds are
  // still smouldering when they land (the model's SOC win); breaches have already
  // spread, so the crew can only mop up once lateral movement is done.
  sim.crews.forEach((crew) => {
    const fire = sim.fires.find((f) => f.id === crew.fire);
    if (crew.fire && !fire) crew.fire = 0;
    const tx = fire ? fire.origin % sim.cols : crew.hx;
    const ty = fire ? Math.floor(fire.origin / sim.cols) : crew.hy;
    const dx = tx - crew.x, dy = ty - crew.y, dist = Math.hypot(dx, dy);
    const speed = (fire ? 2.5 : 1) * dt;
    if (dist > 0.01) { crew.x += (dx / dist) * Math.min(speed, dist); crew.y += (dy / dist) * Math.min(speed, dist); }
    if (!fire || dist > 0.3) return;
    if (!fire.arrived) fire.arrived = sim.day;
    const done = fire.kind === "contained" || fire.cells.length >= fire.target;
    if (!done) return;
    for (const k of fire.cells) { const c = cells[k]; if (c && c.state === BURNING) { c.state = BURNED; c.until = sim.day + (fire.kind === "contained" ? 8 : 30); } }
    sim.bursts.push({ x: tx, y: ty, at: sim.day, saved: fire.kind === "contained" });
    crew.fire = 0;
  });
  sim.bursts = sim.bursts.filter((b) => sim.day - b.at < 40);

  cells.forEach((c, i) => {
    if (c.state === OK) {
      // background churn: systems drift into their patch window and back out
      const share = vulnShare(params, c.own);
      const windowDays = c.own ? params.ownFixDays : params.vendorPatchDays;
      if (rng() < (share / Math.max(1e-6, 1 - share)) * (dt / Math.max(1, windowDays))) makeVuln(sim, i);
      return;
    }
    if (c.state !== VULN) return;
    if (sim.day >= c.exploitAt) land(sim, i);
    else if (sim.day >= c.patchAt) { c.state = OK; c.patchAt = Infinity; c.outcome = null; }
  });
  for (const c of cells) {
    if (c.state === VULN) continue;
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
