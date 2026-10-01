// Deterministic forest model. Every cell is a system.
// Cells: 0 rebuilding after a breach, 1 unpatched (has an open vulnerability), 2 patched, 3 burning.
// The forest starts fully patched. Each day new vulnerabilities are published; each one affects a
// random share of systems (heavy-tailed: most software is niche, a few products are everywhere).
// Every affected system patches after its own random delay (mean = days to patch). A share of
// vulnerabilities is exploited (KEV share) after a random delay; the exploit attacks all affected
// systems in parallel and breaches those still unpatched.
export type FireSettings = {
  /** Vulnerabilities published, × the 2025 level. */
  lightning: number;
  /** Daily chance a breached system is rebuilt (clean, patched). */
  growth: number;
  /** 1 / mean days to patch; 0 = never. */
  rain: number;
  suppliers: number;
  lateral: number;
  /** Kept for compatibility; unused. */
  decay: number;
  /** Share of published vulnerabilities that get exploited (KEV share). */
  exploitShare: number;
  /** Mean days from publication until the exploit is used. */
  exploitDelay: number;
};

/** One lightning bolt stands for this many real published vulnerabilities. */
export const CVES_PER_BOLT = 40;
/** Bolts per day at the 2025 level: 47,948 CVEs / 365 / 40. */
export const BOLTS_PER_DAY_2025 = 47948 / 365 / CVES_PER_BOLT;
/** Chance an attacked, still-unpatched system is actually breached. */
const HIT_CHANCE = 0.5;

type Exploit = { cells: number[]; patchDay: number[]; published: number };

export type ForestState = {
  n: number;
  cells: Uint8Array;
  fireId: Int32Array;
  open: Int16Array;
  burnedAt: Int32Array;
  hubs: number[][];
  activeHubs: number[];
  nextId: number;
  sizes: Map<number, number>;
  live: Map<number, number>;
  hubFires: Set<number>;
  fires: number;
  strikes: number;
  largest: number;
  largestFromHub: boolean;
  finished: number[];
  tick: number;
  patches: Map<number, number[]>; // day -> [cell, published, cell, published, ...]
  pending: Map<number, Exploit[]>;
  exploits: number;
};

export function mulberry32(seed: number) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

export function createForest(n: number, seed: number, suppliers: number): ForestState {
  const cells = new Uint8Array(n * n).fill(2);
  const hubRng = mulberry32(910 + suppliers * 31 + seed);
  const hubs = Array.from({ length: suppliers }, () => Array.from({ length: 300 }, () => Math.floor(hubRng() * n * n)));
  return {
    n, cells, fireId: new Int32Array(n * n), open: new Int16Array(n * n), burnedAt: new Int32Array(n * n).fill(-1),
    hubs, activeHubs: [], nextId: 1, sizes: new Map(), live: new Map(), hubFires: new Set(),
    fires: 0, strikes: 0, largest: 0, largestFromHub: false, finished: [], tick: 0,
    patches: new Map(), pending: new Map(), exploits: 0,
  };
}

const expDays = (mean: number, rng: () => number) => Math.round(-Math.log(1 - rng()) * mean);
/** Share of all systems running the affected software: heavy-tailed, mean ≈ 0.2%. */
const reach = (rng: () => number) => Math.min(0.2, 0.00025 * Math.pow(1 - rng(), -0.85));

export function stepForest(s: ForestState, set: FireSettings, rng: () => number) {
  const { cells, n, fireId, open, burnedAt } = s;
  const N = cells.length;
  const today = s.tick;
  const next = cells.slice();
  const nextId = fireId.slice();
  const ignite = (i: number, id: number) => {
    if (next[i] === 3 || next[i] === 0) return;
    next[i] = 3;
    nextId[i] = id;
    burnedAt[i] = today;
    open[i] = 0;
    s.sizes.set(id, (s.sizes.get(id) ?? 0) + 1);
  };

  // 1. New vulnerabilities land on the systems that run the affected software.
  const rate = set.lightning * BOLTS_PER_DAY_2025;
  let bolts = Math.floor(rate);
  if (rng() < rate - bolts) bolts += 1;
  s.strikes += bolts;
  const exploitChance = Math.min(1, set.exploitShare * CVES_PER_BOLT);
  for (let b = 0; b < bolts; b += 1) {
    const count = Math.max(1, Math.round(reach(rng) * N));
    const exploited = rng() < exploitChance;
    const ex: Exploit | null = exploited ? { cells: [], patchDay: [], published: today } : null;
    for (let k = 0; k < count; k += 1) {
      const i = Math.floor(rng() * N);
      if (cells[i] === 0) continue; // being rebuilt
      const day = set.rain > 0 ? today + 1 + expDays(1 / set.rain, rng) : Infinity;
      open[i] = (open[i] ?? 0) + 1;
      if (Number.isFinite(day)) {
        const list = s.patches.get(day);
        if (list) list.push(i, today); else s.patches.set(day, [i, today]);
      }
      if (ex) { ex.cells.push(i); ex.patchDay.push(day); }
    }
    if (ex) {
      const at = today + Math.max(0, expDays(set.exploitDelay, rng));
      const list = s.pending.get(at);
      if (list) list.push(ex); else s.pending.set(at, [ex]);
    }
  }

  // 2. Patches land.
  const patched = s.patches.get(today);
  if (patched) {
    s.patches.delete(today);
    for (let k = 0; k < patched.length; k += 2) {
      const i = patched[k] ?? 0;
      if ((burnedAt[i] ?? -1) < (patched[k + 1] ?? 0) && (open[i] ?? 0) > 0) open[i] = (open[i] ?? 0) - 1;
    }
  }

  // 3. Exploits arrive and attack every affected system at once.
  const due = s.pending.get(today);
  if (due) {
    s.pending.delete(today);
    for (const ex of due) {
      s.exploits += 1;
      const id = s.nextId;
      let hit = false;
      ex.cells.forEach((i, k) => {
        const stillOpen = (ex.patchDay[k] ?? 0) > today && (burnedAt[i] ?? -1) < ex.published;
        if (stillOpen && cells[i] !== 3 && rng() < HIT_CHANCE) { ignite(i, id); hit = true; }
      });
      if (hit) { s.fires += 1; s.nextId += 1; }
    }
  }
  s.tick += 1;

  // 4. Spread and rebuild.
  for (let i = 0; i < N; i += 1) {
    const v = cells[i];
    if (v === 0) { if (rng() < set.growth) next[i] = 2; }
    else if (v === 3) {
      next[i] = 0;
      const id = fireId[i] ?? 0;
      const x = i % n;
      const nb = [i - n, i + n, x > 0 ? i - 1 : -1, x < n - 1 ? i + 1 : -1];
      for (const j of nb) {
        if (j < 0 || j >= N || cells[j] === 3 || cells[j] === 0) continue;
        if ((open[j] ?? 0) > 0) ignite(j, id);
        else if (rng() < set.lateral) ignite(j, id);
      }
    }
  }

  // 5. Shared suppliers: a breached linked system breaches every linked system, patched or not.
  s.activeHubs = [];
  s.hubs.forEach((links, h) => {
    const trigger = links.find((i) => next[i] === 3 && cells[i] !== 3);
    if (trigger === undefined) return;
    const id = nextId[trigger] ?? 0;
    if (s.hubFires.has(id)) return; // one supplier cascade per fire
    s.activeHubs.push(h);
    s.hubFires.add(id);
    for (const i of links) ignite(i, id);
  });

  // 6. Visible state: unpatched if any open vulnerability.
  for (let i = 0; i < N; i += 1) {
    const v = next[i];
    if (v === 1 || v === 2) next[i] = (open[i] ?? 0) > 0 ? 1 : 2;
  }

  // Track fires.
  const live = new Map<number, number>();
  for (let i = 0; i < N; i += 1) if (next[i] === 3) { const id = nextId[i] ?? 0; live.set(id, (live.get(id) ?? 0) + 1); }
  for (const id of s.live.keys()) {
    if (!live.has(id)) { s.finished.push(s.sizes.get(id) ?? 0); s.sizes.delete(id); s.hubFires.delete(id); }
  }
  for (const id of live.keys()) {
    const size = s.sizes.get(id) ?? 0;
    if (size > s.largest) { s.largest = size; s.largestFromHub = s.hubFires.has(id); }
  }
  if (s.finished.length > 500) s.finished = s.finished.slice(-500);
  s.live = live;
  s.cells = next;
  s.fireId = nextId;
}
