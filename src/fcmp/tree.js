// Curve tree (Curve Trees, Campanelli–Hall-Andersen–Kamp 2023) with ALL the network's private
// outputs, in global order (the same numbering the wallets use).
//
//   leaf j (point of E2):  L_j = P.x·G0 + P.y·G1 + I.x·G2 + I.y·G3 + C.x·G4 + C.y·G5 (+ k·H)
//        P = one-time key, I = Hp(P) (key image base), C = amount commitment
//   level 1 (E1):  N = Σ x(L_j)·G_j  for up to `branch` leaves
//   level 2 (E2):  N = Σ x(child)·G_j  … and so on, alternating curves, up to the root.
//
// "Permissible": each node used as a child is shifted by k·H (minimal k) until y + 1 is a
// square and 1 − y is not — so the x coordinate identifies the point unambiguously
// (only one of ±P passes the test), and the circuit only needs to prove "y + 1 is a square".
//
// The tree is a VIEW over the UTXO state's list of private outputs: leaves and nodes are
// computed on demand and memoized (complete nodes never change; reorganizations truncate).

import { E1, E2 } from './curve.js';
import { bpGens } from './bp.js';
import { FixedBase } from './curve.js';
import { hashPointForKeyImage } from '../crypto/clsag.js';
import { Point } from '../crypto/secp256k1.js';

export const LEAF_WIDTH = 6;
export const LEAF_BLIND = 6; // position (in E2's G) of the leaf blinding

/** Curve, position of the children and of the node blinding at level l (1 = right above the leaves). */
export function segment(l, branch) {
  if (l % 2 === 1) { const o = ((l - 1) / 2) * (branch + 1); return { curve: E1, off: o, blind: o + branch }; }
  const o = LEAF_BLIND + 1 + ((l - 2) / 2) * (branch + 1);
  return { curve: E2, off: o, blind: o + branch };
}

export function depthFor(N, branch) {
  if (N < 1) throw new Error('empty tree');
  let d = 1, cap = branch;
  while (cap < N) { d++; cap *= branch; }
  return d;
}

export function isPermissible(curve, pt) {
  const a = pt.affine();
  if (!a) return false;
  const F = curve.F;
  return F.isSquare(F.add(a[1], 1n)) && !F.isSquare(F.sub(1n, a[1]));
}
/** Smallest k ≥ 0 with raw + k·H permissible. */
export function makePermissible(curve, raw, h) {
  let pt = raw;
  for (let k = 0; k < 4096; k++) {
    if (isPermissible(curve, pt)) return { k: BigInt(k), point: pt };
    pt = pt.add(h);
  }
  throw new Error('no permissible offset');
}

// ------------------------------------------------------------------ leaves
let leafTables = null;
function tables() {
  if (!leafTables) {
    const g = bpGens(E2, LEAF_BLIND + 1);
    leafTables = g.G.slice(0, LEAF_WIDTH).map((p) => new FixedBase(p));
  }
  return leafTables;
}

/** Leaf data of an output (P, C: secp256k1 points or 33 bytes). */
export function leafData(P, C) {
  if (!(P instanceof Point)) P = Point.fromBytes(P);
  if (!(C instanceof Point)) C = Point.fromBytes(C);
  const I = hashPointForKeyImage(P);
  const [px, py] = P.affine(), [ix, iy] = I.affine(), [cx, cy] = C.affine();
  const coords = [px, py, ix, iy, cx, cy];
  const t = tables();
  let raw = E2.INF;
  coords.forEach((v, i) => { raw = raw.add(t[i].mul(v)); });
  const { k, point } = makePermissible(E2, raw, bpGens(E2, 1).h);
  return { P, I, C, coords, raw, k, point, x: point.x };
}

const leafMemo = new Map(); // outpoint key → x(L') (immutable data: the txid commits to the output)
function leafX(key, P, C) {
  let x = leafMemo.get(key);
  if (x === undefined) {
    x = leafData(P, C).x;
    if (leafMemo.size > 2_000_000) leafMemo.clear();
    leafMemo.set(key, x);
  }
  return x;
}

// ------------------------------------------------------------------ tree
export class CurveTree {
  /** getLeaf(i) → { key, P, C } (bytes) of the i-th private output in global order. */
  constructor(branch, getLeaf) {
    this.branch = branch;
    this.getLeaf = getLeaf;
    this.cache = new Map();      // complete nodes: "level:index" → record
    this.maxIdx = new Map();     // level → highest memoized index (to truncate quickly)
    this.roots = new Map();      // N → root
  }

  leafX(i) { const l = this.getLeaf(i); return leafX(l.key, l.P, l.C); }

  /** Node (level, index) considering only the leaves < N. null if it does not exist. */
  nodeAt(level, idx, N) {
    const b = this.branch, span = b ** level, start = idx * span;
    if (start >= N) return null;
    const complete = start + span <= N, key = level + ':' + idx;
    if (complete) { const c = this.cache.get(key); if (c) return c; }
    const entries = [];
    for (let j = 0; j < b; j++) {
      if (level === 1) { if (start + j >= N) break; entries.push(this.leafX(start + j)); }
      else { const ch = this.nodeAt(level - 1, idx * b + j, N); if (!ch) break; entries.push(ch.x); }
    }
    const seg = segment(level, b), gens = bpGens(seg.curve, seg.blind + 1);
    const raw = seg.curve.msm(entries, gens.G.slice(seg.off, seg.off + entries.length));
    const { k, point } = makePermissible(seg.curve, raw, gens.h);
    const rec = { level, idx, entries, raw, k, point, x: point.x };
    if (complete) {
      this.cache.set(key, rec);
      if (!(this.maxIdx.get(level) >= idx)) this.maxIdx.set(level, idx);
    }
    return rec;
  }

  /** Root of the tree with the first N outputs: { depth, point (raw node), count (children) }. */
  root(N) {
    let r = this.roots.get(N);
    if (!r) {
      const depth = depthFor(N, this.branch), rec = this.nodeAt(depth, 0, N);
      r = { depth, point: rec.raw, count: rec.entries.length, entries: rec.entries };
      if (this.roots.size > 10_000) this.roots.clear();
      this.roots.set(N, r);
    }
    return r;
  }

  /**
   * Path of "chunk" (level-1 node) number `chunk`: the entries of each node on the path,
   * from level 1 up to the root. It is all the prover needs from the network.
   */
  pathForChunk(N, chunk) {
    const d = depthFor(N, this.branch), out = [];
    let idx = chunk;
    for (let l = 1; l <= d; l++) {
      const rec = this.nodeAt(l, idx, N);
      if (!rec) throw new Error('chunk outside the tree');
      out.push({ level: l, idx, entries: rec.entries });
      idx = Math.floor(idx / this.branch);
    }
    return out;
  }

  /** Reorganization: the outputs from n on changed — forget whatever depended on them. */
  truncate(n) {
    const b = this.branch;
    for (const [l, max] of this.maxIdx) {
      const span = b ** l;
      for (let idx = Math.floor(n / span); idx <= max; idx++) this.cache.delete(l + ':' + idx);
      this.maxIdx.set(l, Math.min(max, Math.floor(n / span) - 1));
    }
    for (const N of [...this.roots.keys()]) if (N > n) this.roots.delete(N);
  }
}
