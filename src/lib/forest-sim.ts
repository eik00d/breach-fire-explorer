// Deterministic forest-fire model. Cells: 0 empty, 1 unpatched tree, 2 patched tree, 3 burning.
export type FireSettings = { lightning: number; growth: number; rain: number; suppliers: number; lateral: number };

export const PATCH_DECAY = 0.002;

export type ForestState = {
  n: number;
  cells: Uint8Array;
  fireId: Int32Array;
  hubs: number[][];
  activeHubs: number[];
  nextId: number;
  sizes: Map<number, number>; // fire id -> cells burned so far
  live: Map<number, number>; // fire id -> currently burning cells
  hubFires: Set<number>;
  fires: number;
  strikes: number;
  largest: number;
  largestFromHub: boolean;
  finished: number[];
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
  const rng = mulberry32(seed);
  const cells = new Uint8Array(n * n);
  for (let i = 0; i < cells.length; i += 1) cells[i] = rng() < 0.72 ? 1 : 0;
  const hubRng = mulberry32(910 + suppliers * 31 + seed);
  const hubs = Array.from({ length: suppliers }, () => Array.from({ length: 40 }, () => Math.floor(hubRng() * n * n)));
  return {
    n, cells, fireId: new Int32Array(n * n), hubs, activeHubs: [], nextId: 1,
    sizes: new Map(), live: new Map(), hubFires: new Set(),
    fires: 0, strikes: 0, largest: 0, largestFromHub: false, finished: [],
  };
}

export function stepForest(s: ForestState, set: FireSettings, rng: () => number) {
  const { cells, n, fireId } = s;
  const next = cells.slice();
  const nextId = fireId.slice();
  const ignite = (i: number, id: number) => {
    if (next[i] === 3) return;
    next[i] = 3;
    nextId[i] = id;
    s.sizes.set(id, (s.sizes.get(id) ?? 0) + 1);
  };

  // Lightning: only unpatched trees ignite.
  const rate = set.lightning / 12;
  let tries = Math.floor(rate);
  if (rng() < rate - tries) tries += 1;
  s.strikes += tries;
  for (let k = 0; k < tries; k += 1) {
    const hit = Math.floor(rng() * cells.length);
    if (cells[hit] === 1 && next[hit] !== 3) { s.fires += 1; ignite(hit, s.nextId++); }
  }

  // Spread, growth, rain, patch decay.
  for (let i = 0; i < cells.length; i += 1) {
    const v = cells[i];
    if (v === 0) { if (rng() < set.growth) next[i] = 1; }
    else if (v === 1) { if (next[i] !== 3 && rng() < set.rain) next[i] = 2; }
    else if (v === 2) { if (next[i] !== 3 && rng() < PATCH_DECAY) next[i] = 1; }
    else if (v === 3) {
      next[i] = 0;
      const id = fireId[i] ?? 0;
      const x = i % n;
      const nb = [i - n, i + n, x > 0 ? i - 1 : -1, x < n - 1 ? i + 1 : -1];
      for (const j of nb) {
        if (j < 0 || j >= cells.length) continue;
        if (cells[j] === 1) ignite(j, id);
        else if (cells[j] === 2 && rng() < set.lateral) ignite(j, id);
      }
    }
  }

  // Shared suppliers: a burning linked tree ignites every linked tree, patched or not.
  s.activeHubs = [];
  s.hubs.forEach((links, h) => {
    const trigger = links.find((i) => next[i] === 3 && cells[i] !== 3);
    if (trigger === undefined) return;
    const id = nextId[trigger] ?? 0;
    s.activeHubs.push(h);
    s.hubFires.add(id);
    for (const i of links) if (next[i] === 1 || next[i] === 2) ignite(i, id);
  });

  // Track live fires; record finished ones.
  const live = new Map<number, number>();
  for (let i = 0; i < next.length; i += 1) if (next[i] === 3) { const id = nextId[i] ?? 0; live.set(id, (live.get(id) ?? 0) + 1); }
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
