// Deterministic event replay behind the Section 01 "company under attack" canvas.
// Every lightning strike walks the same funnel as the calculator, with the same
// probabilities: race -> exposure / targeting -> hardening -> SOC -> breach.
// Strikes arrive at the model's real yearly rate, so over many simulated years the
// canvas counts converge to the formulas (λ, P(year), P(5 years), large share).
import { aiAmplifiers, APPSEC_FIND_RATE, BOUNTY_HALF_K, BOUNTY_MAX_RATE, MEDIAN_DAYS_TO_KEV, VENDOR_ZERO_DAY_SHARE, type CompanyInputs, type CompanyResult } from "./company-risk";

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

type Funnel = { strikes: number; win: number; reach: number; pass: number; escape: number };

export type SimParams = {
  vendor: Funnel;
  own: Funnel;
  cred: Funnel; // win = passes the MFA check
  phish: Funnel; // win = passes the email / endpoint check
  pretext: Funnel; // win = passes the modest identity / verification check
  other: number; // insiders, errors, physical, unknown: strikes/yr that are breaches of any size
  largeShare: number;
  reportedShare: number;
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
  return { strikes, win: safe(ch.winsRace, strikes), reach: safe(ch.reached, ch.winsRace), pass: safe(ch.pastHardening, ch.reached), escape: safe(ch.anyBreaches, ch.pastHardening) };
}

export function simParams(c: CompanyInputs, r: CompanyResult): SimParams {
  const ai = aiAmplifiers(c);
  return {
    vendor: funnel(r.vendor),
    own: funnel(r.own),
    cred: funnel(r.cred),
    phish: funnel(r.phish),
    pretext: funnel(r.pretext),
    other: r.other.incidents,
    largeShare: r.largeShare,
    reportedShare: r.reportedShare,
    spreadPerDay: (SEGMENTATION_SPREAD[c.hardening] ?? 1) * Math.pow(ai.entry, 0.3),
    vendorPatchDays: c.patchDays,
    ownFixDays: OWN_FIX_BASE_DAYS / (1 + (APPSEC_FIND_RATE[c.appsec] ?? 0) + BOUNTY_MAX_RATE * c.bountyK / (c.bountyK + BOUNTY_HALF_K)),
    neverPatched: c.neverPatched,
    exploitDays: MEDIAN_DAYS_TO_KEV / Math.pow(ai.vuln, 0.5),
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

export type Source = "vendor" | "own" | "cred" | "phish" | "pretext" | "other";
export type Outcome = "stopped" | "patched" | "unreached" | "blocked" | "contained" | "small" | "reported" | "large";

export type Cell = { state: number; own: boolean; until: number; fire: number; struckAt: number; vulnAt: number; src: Source; outcome: Outcome | null; patchAt: number; exploitAt: number; never: boolean };

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

export type Counts = { strikes: number; stopped: number; bySource: Record<Source, number>; reportedBy: Record<Source, number>; patched: number; unreached: number; blocked: number; contained: number; small: number; reported: number; large: number };

export type Sim = {
  cols: number;
  rows: number;
  cells: Cell[];
  fires: Fire[];
  crews: Crew[];
  sector: number[]; // segment id per cell
  sectorSize: number[];
  bursts: Burst[];
  wetFlashes: { cell: number; at: number }[];
  wallBounces: { cell: number; at: number }[];
  eventYears: { reached: number[]; incidents: number[]; any: number[] };
  rng: Rng;
  day: number;
  nextStrike: number;
  nextFire: number;
  counts: Counts;
  breachYears: number[]; // breaches per simulated year (index = year - 1)
  params: SimParams;
};

const totalRate = (p: SimParams) => p.vendor.strikes + p.own.strikes + p.cred.strikes + p.phish.strikes + p.pretext.strikes + p.other;
const zeroSrc = (): Record<Source, number> => ({ vendor: 0, own: 0, cred: 0, phish: 0, pretext: 0, other: 0 });

function nextGap(sim: Sim) {
  const rate = totalRate(sim.params);
  if (rate <= 0) return Infinity;
  return (-Math.log(1 - sim.rng()) / rate) * 365; // Poisson process, days
}

export function createSim(cols: number, rows: number, seed: number, params: SimParams): Sim {
  const rng = mulberry32(seed);
  const cells: Cell[] = [];
  for (let i = 0; i < cols * rows; i += 1) {
    cells.push({ state: OK, own: rng() < params.inHouseShare, until: 0, fire: 0, struckAt: -Infinity, vulnAt: 0, src: "vendor", outcome: null, patchAt: Infinity, exploitAt: Infinity, never: false });
  }
  const sim: Sim = {
    cols, rows, cells, fires: [], crews: [], sector: [], sectorSize: [], bursts: [], wetFlashes: [], wallBounces: [], eventYears: { reached: [0], incidents: [0], any: [0] }, rng, day: 0, nextStrike: 0, nextFire: 1,
    counts: { strikes: 0, stopped: 0, bySource: zeroSrc(), reportedBy: zeroSrc(), patched: 0, unreached: 0, blocked: 0, contained: 0, small: 0, reported: 0, large: 0 },
    breachYears: [0], params,
  };
  makeSectors(sim, params.sectors);
  for (let k = 0; k < params.crews; k += 1) {
    const hx = ((k + 1) * cols) / (params.crews + 1) - 0.5, hy = rows / 2 - 0.5;
    sim.crews.push({ x: hx, y: hy, fire: 0, hx, hy });
  }
  // seed the standing patch backlog so vulnerabilities are visible from the start
  for (let i = 0; i < cells.length; i += 1) {
    const c = cells[i];
    if (!c) continue;
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
    const b = blocks.shift();
    if (!b) break;
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
  let pick = rng() * totalRate(params);
  const order: Source[] = ["vendor", "own", "cred", "phish", "pretext", "other"];
  let src: Source = "other";
  for (const k of order) { const w = k === "other" ? params.other : params[k].strikes; if (pick < w) { src = k; break; } pick -= w; }
  const own = src === "own";
  const f = src === "other" ? params.vendor : params[src];
  // decide the whole funnel up front (same probabilities as the formulas)
  let outcome: Outcome;
  if (src === "other") outcome = rng() >= params.cred.escape ? "contained" : rng() >= params.reportedShare ? "small" : rng() < params.largeShare ? "large" : "reported";
  else if (rng() >= f.win) outcome = src === "vendor" || src === "own" ? "patched" : "stopped";
   else {
     // One uniform draw partitions the old combined gate into two visible outcomes.
     // The probability of progressing remains exactly reach * pass.
     const gate = rng();
     if (gate >= f.reach) outcome = "unreached";
     else if (gate >= f.reach * f.pass) outcome = "blocked";
     else if (rng() >= f.escape) outcome = "contained";
     else if (rng() >= params.reportedShare) outcome = "small";
     else outcome = rng() < params.largeShare ? "large" : "reported";
   }

  sim.counts.strikes += 1;
  sim.counts[outcome] += 1;
  sim.counts.bySource[src] += 1;
  if (outcome === "reported" || outcome === "large") sim.counts.reportedBy[src] += 1;
  const y = Math.floor(sim.day / 365);
  const add = (key: keyof Sim["eventYears"]) => { sim.eventYears[key][y] = (sim.eventYears[key][y] ?? 0) + 1; };
  if (src !== "other" && outcome !== "patched" && outcome !== "stopped" && outcome !== "unreached") add("reached");
  if (["contained", "small", "reported", "large"].includes(outcome)) add("incidents");
  if (["small", "reported", "large"].includes(outcome)) add("any");
  if (outcome === "reported" || outcome === "large") {
    const y = Math.floor(sim.day / 365);
    sim.breachYears[y] = (sim.breachYears[y] ?? 0) + 1;
  }

  if (outcome === "unreached") {
    const idle = sim.cells.flatMap((c, i) => c.state === OK && c.own === own ? [i] : []);
    const cell = idle[Math.floor(rng() * idle.length)];
    if (cell !== undefined) sim.wetFlashes.push({ cell, at: sim.day });
    return;
  }
  if (src !== "vendor" && src !== "own") {
    // credentials / phishing / other land on any idle system; no patch race
    const idle = sim.cells.flatMap((k, j) => k.state === OK ? [j] : []);
    const j = idle[Math.floor(rng() * idle.length)];
    const k = j === undefined ? undefined : sim.cells[j];
    if (j === undefined || !k) return;
    k.struckAt = sim.day; k.src = src; k.outcome = outcome;
    if (outcome === "stopped") return; // failed the MFA / email check: nothing happens
    k.state = VULN; k.vulnAt = sim.day; k.never = false; k.patchAt = Infinity;
    k.exploitAt = sim.day + 2 + rng() * 4;
    return;
  }
  const i = pickCell(sim, own);
  if (i < 0) return;
  const c = sim.cells[i];
  if (!c) return;
  c.struckAt = sim.day;
  c.src = src;
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
  const c = sim.cells[i];
  if (!c || !c.outcome) return;
  const outcome = c.outcome;
  c.exploitAt = Infinity;
  if (outcome === "blocked") {
    c.state = OK; // hardening stops the exploit
    c.struckAt = sim.day;
    c.outcome = "blocked";
    sim.wallBounces.push({ cell: i, at: sim.day });
    return;
  }
  const sector = sim.sector[i] ?? 0;
  const secSize = sim.sectorSize[sector] ?? 1;
  // small breach: lateral movement burns out its own segment (capped in a flat network);
  // large breach: jumps segment walls until it reaches the data governance allows
  const target = outcome === "contained" ? 1
    : outcome === "small" ? 1
    : outcome === "reported" ? Math.min(secSize, 6 + Math.floor(rng() * 14))
    : Math.min(Math.floor(sim.cells.length * 0.5), Math.max(secSize + 4, sim.params.largeSize + Math.floor(rng() * 15)));
  const fire: Fire = { id: sim.nextFire++, cells: [], target, kind: outcome, start: sim.day, origin: i, spreadAcc: 0, crew: -1, arrived: 0, sector };
  sim.fires.push(fire);
  burn(sim, i, fire);
  if (outcome === "small") { c.until = sim.day + 18; return; }
  if (outcome === "contained") c.until = sim.day + 60; // smoulders until the crew lands
  // dispatch the nearest idle SOC crew
  const ox = i % sim.cols, oy = Math.floor(i / sim.cols);
  let best = -1, bestD = Infinity;
  sim.crews.forEach((c, k) => { const d = Math.hypot(c.x - ox, c.y - oy); if (c.fire === 0 && d < bestD) { bestD = d; best = k; } });
  if (best >= 0) { fire.crew = best; const crew = sim.crews[best]; if (crew) crew.fire = fire.id; }
  else if (outcome === "contained") c.until = sim.day + 12;
}

export function stepSim(sim: Sim, dt: number) {
  const { cells, rng, params } = sim;
  sim.day += dt;
  const year = Math.floor(sim.day / 365);
  while (sim.breachYears.length <= year) sim.breachYears.push(0);
  for (const ys of Object.values(sim.eventYears)) while (ys.length <= year) ys.push(0);

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
      const inside = open.filter((k) => sim.sector[k] === fire.sector || sim.sector[k] === sim.sector[fire.cells.at(-1) ?? fire.origin]);
      const frontier = fire.kind === "large" ? (inside.length && rng() < 0.7 ? inside : open) : open.filter((k) => sim.sector[k] === fire.sector);
      if (!frontier.length) { fire.target = fire.cells.length; break; }
      const next = frontier[Math.floor(rng() * frontier.length)];
       if (next !== undefined) burn(sim, next, fire);
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
    for (const k of fire.cells) { const c = cells[k]; if (c && c.state === BURNING) { c.state = fire.kind === "contained" ? OK : BURNED; c.outcome = fire.kind === "contained" ? null : c.outcome; c.until = sim.day + 30; } }
    sim.bursts.push({ x: tx, y: ty, at: sim.day, saved: fire.kind === "contained" });
    crew.fire = 0;
  });
  sim.bursts = sim.bursts.filter((b) => sim.day - b.at < 40);
  sim.wetFlashes = sim.wetFlashes.filter((f) => sim.day - f.at < 200);
  sim.wallBounces = sim.wallBounces.filter((f) => sim.day - f.at < 200);

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
    else if (c.state === BURNING && sim.day >= c.until) {
      const transient = sim.fires.find((f) => f.id === c.fire)?.kind;
      c.state = transient === "small" || transient === "contained" ? OK : BURNED;
      if (c.state === OK) c.outcome = null;
      c.until = sim.day + 40;
    }
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
  const allBreaches = sim.counts.reported + sim.counts.large;
  const summarize = (source: number[]) => {
    const ys = source.slice(0, done);
    let hit5 = 0;
    for (let y = 0; y + 5 <= done; y++) if (ys.slice(y, y + 5).some((n) => n > 0)) hit5++;
    return { lambda: done ? ys.reduce((a, b) => a + b, 0) / done : 0, pYear: done ? ys.filter((n) => n > 0).length / done : 0, p5: windows ? hit5 / windows : 0 };
  };
  return {
    rates: { reached: summarize(sim.eventYears.reached), incidents: summarize(sim.eventYears.incidents), any: summarize(sim.eventYears.any), reported: summarize(sim.breachYears) },
    vulnShare: allBreaches ? (sim.counts.reportedBy.vendor + sim.counts.reportedBy.own) / allBreaches : 0,
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
