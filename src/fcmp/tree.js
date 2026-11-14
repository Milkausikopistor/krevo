// Árvore de curvas (Curve Trees, Campanelli–Hall-Andersen–Kamp 2023) com TODAS as saídas
// privadas da rede, na ordem global (a mesma numeração usada pelas carteiras).
//
//   folha j (ponto de E2):  L_j = P.x·G0 + P.y·G1 + I.x·G2 + I.y·G3 + C.x·G4 + C.y·G5 (+ k·H)
//        P = chave de uso único, I = Hp(P) (base da imagem de chave), C = compromisso do valor
//   nível 1 (E1):  N = Σ x(L_j)·G_j  para até `branch` folhas
//   nível 2 (E2):  N = Σ x(filho)·G_j  … e assim por diante, alternando de curva, até a raiz.
//
// "Permissível": cada nó usado como filho é deslocado por k·H (k mínimo) até que y + 1 seja
// quadrado e 1 − y não seja — assim a coordenada x identifica o ponto sem ambiguidade
// (só um de ±P passa no teste), e o circuito só precisa provar "y + 1 é quadrado".
//
// A árvore é uma VISÃO sobre a lista de saídas privadas do estado UTXO: folhas e nós são
// calculados sob demanda e memorizados (nós completos nunca mudam; reorganizações truncam).

import { E1, E2 } from './curve.js';
import { bpGens } from './bp.js';
import { FixedBase } from './curve.js';
import { hashPointForKeyImage } from '../crypto/clsag.js';
import { Point } from '../crypto/secp256k1.js';

export const LEAF_WIDTH = 6;
export const LEAF_BLIND = 6; // posição (em G de E2) do cegamento da folha

/** Curva, posição dos filhos e do cegamento dos nós do nível l (1 = logo acima das folhas). */
export function segment(l, branch) {
  if (l % 2 === 1) { const o = ((l - 1) / 2) * (branch + 1); return { curve: E1, off: o, blind: o + branch }; }
  const o = LEAF_BLIND + 1 + ((l - 2) / 2) * (branch + 1);
  return { curve: E2, off: o, blind: o + branch };
}

export function depthFor(N, branch) {
  if (N < 1) throw new Error('árvore vazia');
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
/** Menor k ≥ 0 com raw + k·H permissível. */
export function makePermissible(curve, raw, h) {
  let pt = raw;
  for (let k = 0; k < 4096; k++) {
    if (isPermissible(curve, pt)) return { k: BigInt(k), point: pt };
    pt = pt.add(h);
  }
  throw new Error('nenhum deslocamento permissível');
}

// ------------------------------------------------------------------ folhas
let leafTables = null;
function tables() {
  if (!leafTables) {
    const g = bpGens(E2, LEAF_BLIND + 1);
    leafTables = g.G.slice(0, LEAF_WIDTH).map((p) => new FixedBase(p));
  }
  return leafTables;
}

/** Dados da folha de uma saída (P, C: pontos secp256k1 ou 33 bytes). */
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

const leafMemo = new Map(); // chave do outpoint → x(L') (dados imutáveis: o txid compromete a saída)
function leafX(key, P, C) {
  let x = leafMemo.get(key);
  if (x === undefined) {
    x = leafData(P, C).x;
    if (leafMemo.size > 2_000_000) leafMemo.clear();
    leafMemo.set(key, x);
  }
  return x;
}

// ------------------------------------------------------------------ árvore
export class CurveTree {
  /** getLeaf(i) → { key, P, C } (bytes) da i-ésima saída privada da ordem global. */
  constructor(branch, getLeaf) {
    this.branch = branch;
    this.getLeaf = getLeaf;
    this.cache = new Map();      // nós completos: "nível:índice" → registro
    this.maxIdx = new Map();     // nível → maior índice memorizado (para truncar rápido)
    this.roots = new Map();      // N → raiz
  }

  leafX(i) { const l = this.getLeaf(i); return leafX(l.key, l.P, l.C); }

  /** Nó (nível, índice) considerando só as folhas < N. null se não existir. */
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

  /** Raiz da árvore com as N primeiras saídas: { depth, point (nó cru), count (filhos) }. */
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
   * Caminho do "pedaço" (nó de nível 1) número `chunk`: as entradas de cada nó do caminho,
   * do nível 1 até a raiz. É tudo o que quem prova precisa da rede.
   */
  pathForChunk(N, chunk) {
    const d = depthFor(N, this.branch), out = [];
    let idx = chunk;
    for (let l = 1; l <= d; l++) {
      const rec = this.nodeAt(l, idx, N);
      if (!rec) throw new Error('pedaço fora da árvore');
      out.push({ level: l, idx, entries: rec.entries });
      idx = Math.floor(idx / this.branch);
    }
    return out;
  }

  /** Reorganização: as saídas a partir de n mudaram — esquece o que dependia delas. */
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
