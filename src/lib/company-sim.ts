// Deterministic cell simulation behind the Section 01 "company under attack" canvas.
// Purely illustrative: parameters are derived from the same CompanyInputs / CompanyResult
// as the calculator, but this is a visual replay, not a second risk model.
import { OWN_BASE_ATTACKER_WIN, type CompanyInputs, type CompanyResult } from "./company-risk";

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

export type SimParams = {
  strikesPerYear: number; // lightning: L_v + L_o
  ownStrikeShare: number; // fraction of strikes aimed at in-house systems
  vendorIgniteP: number; // p_v: exploit wins the vendor patch race
  ownIgniteP: number; // attacker-win share in own code
  patchDays: number; // median patch time
  neverPatched: number; // share of struck systems that never get patched
  spreadP: number; // per-neighbor ignition probability per sim-day (hardening)
  crews: number; // SOC crews extinguishing fires
  maxFireSize: number; // governance cap on one fire's size
  inHouseShare: number; // fraction of grid cells that are in-house systems
};

const HARDENING_SPREAD = [0.3, 0.2, 0.1, 0.05, 0.02]; // visual spread chance per day
const GOV_FIRE_CAP = [40, 24, 12, 6]; // max cells one fire can reach

export function simParams(c: CompanyInputs, r: CompanyResult): SimParams {
  const lightning = Math.max(0.05, r.vendor.lightning + r.own.lightning);
  return {
    // visual tempo: the model's yearly rate is far too sparse to watch, so strikes
    // are sped up 8x; ratios between settings stay faithful to the model
    strikesPerYear: lightning * 8,
    ownStrikeShare: r.own.lightning / lightning,
    vendorIgniteP: Math.min(1, Math.max(0.02, r.vendor.raceP)),
    ownIgniteP: Math.min(1, Math.max(0.02, OWN_BASE_ATTACKER_WIN * r.own.raceP)),
    patchDays: c.patchDays,
    neverPatched: c.neverPatched,
    spreadP: HARDENING_SPREAD[c.hardening] ?? 0.38,
    crews: c.soc,
    maxFireSize: GOV_FIRE_CAP[c.governance] ?? 36,
    inHouseShare: c.inHouse,
  };
}

// Cell states
export const OK = 0;
export const VULN = 1;
export const BURNING = 2;
export const BURNED = 3;

export type Cell = {
  state: number;
  own: boolean; // in-house system
  patchAt: number; // sim-day when the patch lands (Infinity = never)
  igniteAt: number; // sim-day when the exploit lands (Infinity = none)
  burnUntil: number; // sim-day when the fire burns out
  fireId: number;
  struckAt: number; // for the lightning flash
};

export type Crew = { x: number; y: number; target: number }; // target = cell index or -1

export type Sim = {
  cols: number;
  rows: number;
  cells: Cell[];
  crews: Crew[];
  rng: Rng;
  day: number;
  strikeAcc: number;
  nextFireId: number;
  fireSizes: Map<number, number>;
  firesThisYear: number;
  burnedThisYear: number;
  year: number;
  params: SimParams;
};

export function createSim(cols: number, rows: number, seed: number, params: SimParams): Sim {
  const rng = mulberry32(seed);
  const cells: Cell[] = [];
  for (let i = 0; i < cols * rows; i += 1) {
    cells.push({
      state: OK,
      own: rng() < params.inHouseShare,
      patchAt: Infinity,
      igniteAt: Infinity,
      burnUntil: 0,
      fireId: 0,
      struckAt: -Infinity,
    });
  }
  return {
    cols,
    rows,
    cells,
    crews: [],
    rng,
    day: 0,
    strikeAcc: 0,
    nextFireId: 1,
    fireSizes: new Map(),
    firesThisYear: 0,
    burnedThisYear: 0,
    year: 1,
    params,
  };
}

// Live-update parameters without resetting the field (sliders move -> behavior changes).
export function applyParams(sim: Sim, params: SimParams) {
  sim.params = params;
  while (sim.crews.length < params.crews) {
    sim.crews.push({ x: sim.cols / 2, y: sim.rows / 2, target: -1 });
  }
  if (sim.crews.length > params.crews) sim.crews.length = params.crews;
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

function ignite(sim: Sim, i: number, fireId: number) {
  const cell = sim.cells[i];
  if (!cell || cell.state === BURNING) return;
  if (cell.state === BURNED && sim.day < cell.burnUntil) return; // still rebuilding
  cell.state = BURNING;
  cell.fireId = fireId;
  cell.burnUntil = sim.day + 3.5 + sim.rng() * 3;
  sim.fireSizes.set(fireId, (sim.fireSizes.get(fireId) ?? 0) + 1);
  sim.burnedThisYear += 1;
}

function strike(sim: Sim) {
  const { rng, params, cells } = sim;
  // pick a target cell of the right kind (vendor / own code)
  const wantOwn = rng() < params.ownStrikeShare;
  let idx = Math.floor(rng() * cells.length);
  for (let tries = 0; tries < 12; tries += 1) {
    const c = cells[idx];
    if (c && c.own === wantOwn && c.state !== BURNING) break;
    idx = Math.floor(rng() * cells.length);
  }
  const cell = cells[idx];
  if (!cell || cell.state === BURNING) return;
  cell.state = VULN;
  cell.struckAt = sim.day;
  const igniteP = cell.own ? params.ownIgniteP : params.vendorIgniteP;
  const patchIn = params.patchDays * (0.35 + 1.3 * rng());
  if (rng() < params.neverPatched) {
    cell.patchAt = Infinity;
    // unpatched systems stay exposed; the exploit arrives eventually
    cell.igniteAt = rng() < igniteP ? sim.day + patchIn * (0.5 + rng()) : Infinity;
  } else if (rng() < igniteP) {
    // exploit wins the race: lands before the patch
    cell.igniteAt = sim.day + patchIn * rng();
    cell.patchAt = sim.day + patchIn;
  } else {
    cell.igniteAt = Infinity;
    cell.patchAt = sim.day + patchIn;
  }
}

function stepCrews(sim: Sim, dtDays: number) {
  const { crews, cells, cols } = sim;
  for (const crew of crews) {
    let target = crew.target >= 0 ? cells[crew.target] : undefined;
    if (!target || target.state !== BURNING) {
      crew.target = -1;
      // find the oldest burning cell
      let best = -1;
      let bestAge = Infinity;
      for (let i = 0; i < cells.length; i += 1) {
        const c = cells[i];
        if (c && c.state === BURNING && c.burnUntil < bestAge) {
          bestAge = c.burnUntil;
          best = i;
        }
      }
      crew.target = best;
      target = best >= 0 ? cells[best] : undefined;
    }
    if (crew.target < 0 || !target) continue;
    const tx = crew.target % cols;
    const ty = Math.floor(crew.target / cols);
    const speed = 10 * dtDays; // cells per sim-day
    const dx = tx - crew.x;
    const dy = ty - crew.y;
    const dist = Math.hypot(dx, dy);
    if (dist < 0.6) {
      // extinguish
      target.state = BURNED;
      target.burnUntil = sim.day + 25; // rebuilding time
      crew.target = -1;
    } else {
      crew.x += (dx / dist) * Math.min(speed, dist);
      crew.y += (dy / dist) * Math.min(speed, dist);
    }
  }
}

export function stepSim(sim: Sim, dtDays: number) {
  const { params, rng, cells } = sim;
  sim.day += dtDays;
  if (sim.day >= sim.year * 365) {
    sim.year += 1;
    sim.firesThisYear = 0;
    sim.burnedThisYear = 0;
  }

  // lightning
  sim.strikeAcc += (params.strikesPerYear / 365) * dtDays;
  while (sim.strikeAcc >= 1) {
    sim.strikeAcc -= 1;
    strike(sim);
  }
  if (rng() < sim.strikeAcc) {
    sim.strikeAcc = 0;
    strike(sim);
  }

  for (let i = 0; i < cells.length; i += 1) {
    const cell = cells[i];
    if (!cell) continue;
    if (cell.state === VULN) {
      if (sim.day >= cell.igniteAt) {
        sim.firesThisYear += 1;
        ignite(sim, i, sim.nextFireId++);
      } else if (sim.day >= cell.patchAt) {
        cell.state = OK;
        cell.patchAt = Infinity;
      }
    } else if (cell.state === BURNING) {
      const size = sim.fireSizes.get(cell.fireId) ?? 0;
      if (size < params.maxFireSize) {
        for (const n of neighbors(sim, i)) {
          const nc = cells[n];
          if (nc && (nc.state === OK || nc.state === VULN) && rng() < params.spreadP * dtDays) {
            ignite(sim, n, cell.fireId);
          }
        }
      }
      if (sim.day >= cell.burnUntil) {
        cell.state = BURNED;
        cell.burnUntil = sim.day + 25;
      }
    } else if (cell.state === BURNED && sim.day >= cell.burnUntil) {
      cell.state = OK;
      cell.fireId = 0;
    }
  }

  stepCrews(sim, dtDays);
}
