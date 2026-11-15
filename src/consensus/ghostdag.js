// GHOSTDAG (Sompolinsky, Wyborski, Zohar) — Kaspa's consensus protocol.
//
// In Bitcoin, two simultaneous blocks → one becomes an orphan (wasted work).
// In a BlockDAG, each block references ALL known tips, and nothing is discarded.
// GHOSTDAG colors the blocks:
//   BLUE  — the largest "well-connected" set (each one has ≤ k blue blocks in its
//           anticone): blocks from honest miners.
//   RED   — weakly connected blocks (late, or from an attacker).
// The selected chain (parent with the most blue work) + each block's "mergeset" define a
// TOTAL ORDER of all blocks — and therefore of the transactions.
// With k = 124 at 10 blocks/s, security matches Nakamoto's with a 5 s delay.
//
// Implementation based on rusty-kaspa's reference algorithm
// (consensus/src/processes/ghostdag/protocol.rs).

export function compareBlueWork(storeOrGet, a, b) {
  const wa = storeOrGet(a).blueWork, wb = storeOrGet(b).blueWork;
  if (wa !== wb) return wa < wb ? -1 : 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

/** Minimal DAG store: parents, children, height, GHOSTDAG data and work. */
export class DagStore {
  constructor() {
    this.parents = new Map();
    this.children = new Map();
    this.height = new Map();
    this.gd = new Map();
    this.work = new Map();
    this.ancCache = new Map();
  }
  has(h) { return this.gd.has(h); }
  add(h, parents, gd, work) {
    this.parents.set(h, parents);
    this.children.set(h, []);
    for (const p of parents) this.children.get(p).push(h);
    this.height.set(h, parents.length ? Math.max(...parents.map((p) => this.height.get(p))) + 1 : 0);
    this.gd.set(h, gd);
    this.work.set(h, work);
  }
  /** a ∈ past(b) ∪ {b}? Reverse search bounded by height (an ancestor has a lower height). */
  isAncestor(a, b) {
    if (a === b) return true;
    const ha = this.height.get(a), hb = this.height.get(b);
    if (ha >= hb) return false;
    const key = a + b;
    const c = this.ancCache.get(key);
    if (c !== undefined) return c;
    const seen = new Set([b]);
    const stack = [b];
    let found = false;
    outer: while (stack.length) {
      const x = stack.pop();
      for (const p of this.parents.get(x)) {
        if (p === a) { found = true; break outer; }
        if (!seen.has(p) && this.height.get(p) > ha) { seen.add(p); stack.push(p); }
      }
    }
    if (this.ancCache.size > 500_000) this.ancCache.clear();
    this.ancCache.set(key, found);
    return found;
  }
}

export function genesisGhostdag() {
  return { selectedParent: null, mergesetBlues: [], mergesetReds: [], bluesAnticoneSizes: new Map(),
    blueScore: 0, blueWork: 0n, daaScore: 0 };
}

export class Ghostdag {
  constructor(store, k) { this.store = store; this.k = k; }

  cmp(a, b) { return compareBlueWork((h) => this.store.gd.get(h), a, b); }

  selectedParent(parents) {
    let best = parents[0];
    for (const p of parents.slice(1)) if (this.cmp(p, best) > 0) best = p;
    return best;
  }

  /** Blocks in B's past but not in the selected parent's past, in increasing blue-work order. */
  orderedMergesetWithoutSP(sp, parents) {
    const queue = parents.filter((p) => p !== sp);
    const mergeset = new Set(queue);
    const spPast = new Set();
    while (queue.length) {
      const cur = queue.shift();
      for (const p of this.store.parents.get(cur)) {
        if (mergeset.has(p) || spPast.has(p)) continue;
        if (this.store.isAncestor(p, sp)) { spPast.add(p); continue; }
        mergeset.add(p);
        queue.push(p);
      }
    }
    return [...mergeset].sort((a, b) => this.cmp(a, b));
  }

  blueAnticoneSize(block, ctx) {
    let cur = ctx;
    for (;;) {
      const s = cur.bluesAnticoneSizes.get(block);
      if (s !== undefined) return s;
      if (!cur.selectedParent) throw new Error('block outside the context\'s blue set');
      cur = this.store.gd.get(cur.selectedParent);
    }
  }

  checkBlueCandidate(newData, candidate) {
    if (newData.mergesetBlues.length === this.k + 1) return null; // vermelho
    const sizes = new Map();
    let candAnticone = 0;
    let chainHash = null, chainData = newData;
    for (;;) {
      if (chainHash !== null && this.store.isAncestor(chainHash, candidate)) {
        return { anticone: candAnticone, sizes }; // azul
      }
      for (const b of chainData.mergesetBlues) {
        if (this.store.isAncestor(b, candidate)) continue;
        const s = this.blueAnticoneSize(b, newData);
        sizes.set(b, s);
        candAnticone++;
        if (candAnticone > this.k) return null;
        if (s === this.k) return null;
      }
      chainHash = chainData.selectedParent;
      if (chainHash === null) return { anticone: candAnticone, sizes };
      chainData = this.store.gd.get(chainHash);
    }
  }

  /** Computes the GHOSTDAG data of a new block with these parents. */
  run(parents) {
    const sp = this.selectedParent(parents);
    const spData = this.store.gd.get(sp);
    const data = {
      selectedParent: sp,
      mergesetBlues: [sp],
      mergesetReds: [],
      bluesAnticoneSizes: new Map([[sp, 0]]),
      blueScore: 0, blueWork: 0n, daaScore: 0,
    };
    const mergeset = this.orderedMergesetWithoutSP(sp, parents);
    for (const cand of mergeset) {
      const res = this.checkBlueCandidate(data, cand);
      if (res) {
        data.mergesetBlues.push(cand);
        data.bluesAnticoneSizes.set(cand, res.anticone);
        for (const [b, s] of res.sizes) data.bluesAnticoneSizes.set(b, s + 1);
      } else {
        data.mergesetReds.push(cand);
      }
    }
    data.blueScore = spData.blueScore + data.mergesetBlues.length;
    let added = 0n;
    for (const b of data.mergesetBlues) added += this.store.work.get(b);
    data.blueWork = spData.blueWork + added;
    data.daaScore = spData.daaScore + data.mergesetBlues.length + data.mergesetReds.length;
    data.mergesetAsc = mergeset; // mergeset without the selected parent, ascending order
    return data;
  }

  /** Consensus order of transactions: selected parent, then the mergeset in ascending order. */
  consensusOrder(gd) { return [gd.selectedParent, ...gd.mergesetAsc]; }
}
