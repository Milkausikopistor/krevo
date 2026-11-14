// Sistema de restrições (R1CS no formato dos Bulletproofs) e os "gadgets" da prova de
// pertencimento à árvore inteira.
//
// Variáveis:
//   portas de multiplicação  aL[i] · aR[i] = aO[i]
//   entradas de compromissos vetoriais  C_k = Σ c_k[j]·G_j + γ_k·H  (nós da árvore, cegados)
// Restrições lineares:  Σ coef·variável + constante = 0
//
// O MESMO código monta o circuito para quem prova (com valores) e para quem verifica
// (só a estrutura) — o verificador nunca vê valores secretos.

const BIG = 1 << 24;
export const wireL = (i) => 3 * i;
export const wireR = (i) => 3 * i + 1;
export const wireO = (i) => 3 * i + 2;
export const vcVar = (k, pos) => -1 - (k * BIG + pos);
export function decodeVar(v) {
  if (v >= 0) return { kind: v % 3, gate: Math.floor(v / 3) }; // 0 = L, 1 = R, 2 = O
  const u = -1 - v;
  return { kind: 3, k: Math.floor(u / BIG), pos: u % BIG };
}

/** Combinação linear: Σ coef·variável + c (coeficientes no campo do circuito). */
export class LC {
  constructor(m, terms = new Map(), c = 0n) { this.m = m; this.t = terms; this.c = c; }
  static v(m, v, coef = 1n) { return new LC(m, new Map([[v, ((coef % m) + m) % m]]), 0n); }
  static k(m, c) { return new LC(m, new Map(), ((c % m) + m) % m); }
  clone() { return new LC(this.m, new Map(this.t), this.c); }
  addScaled(o, s = 1n) {
    const m = this.m, r = this.clone();
    s = ((s % m) + m) % m;
    for (const [v, c] of o.t) {
      const nc = ((r.t.get(v) ?? 0n) + c * s) % m;
      if (nc === 0n) r.t.delete(v); else r.t.set(v, nc);
    }
    r.c = (r.c + o.c * s) % m;
    return r;
  }
  add(o) { return this.addScaled(o, 1n); }
  sub(o) { return this.addScaled(o, this.m - 1n); }
  scale(s) {
    const m = this.m; s = ((s % m) + m) % m;
    const r = new LC(m, new Map(), (this.c * s) % m);
    if (s !== 0n) for (const [v, c] of this.t) r.t.set(v, (c * s) % m);
    return r;
  }
  plus(k) { const r = this.clone(); r.c = (((r.c + k) % this.m) + this.m) % this.m; return r; }
}

export class ConstraintSystem {
  /** m = módulo do campo do circuito; prover = true para montar com valores. */
  constructor(m, prover) {
    this.m = m; this.prover = prover;
    this.nGates = 0; this.aL = []; this.aR = []; this.aO = [];
    this.cons = [];
    this.vcs = [];     // { point, entries (Map pos→valor), gamma } — valores só para quem prova
  }
  // ---- variáveis e avaliação
  value(v) {
    const d = decodeVar(v);
    if (d.kind === 0) return this.aL[d.gate];
    if (d.kind === 1) return this.aR[d.gate];
    if (d.kind === 2) return this.aO[d.gate];
    return this.vcs[d.k].entries.get(d.pos) ?? 0n;
  }
  eval(lc) {
    let s = lc.c;
    for (const [v, c] of lc.t) s += c * this.value(v);
    return s % this.m;
  }
  k(c) { return LC.k(this.m, c); }
  vc(k, pos) { return LC.v(this.m, vcVar(k, pos)); }
  /** Declara um compromisso vetorial; devolve seu índice. */
  addVC(point, entries = null, gamma = 0n) { this.vcs.push({ point, entries, gamma }); return this.vcs.length - 1; }

  // ---- portas
  _gate(va, vb) {
    const i = this.nGates++;
    if (this.prover) { this.aL[i] = va; this.aR[i] = vb; this.aO[i] = (va * vb) % this.m; }
    return { i, l: LC.v(this.m, wireL(i)), r: LC.v(this.m, wireR(i)), o: LC.v(this.m, wireO(i)) };
  }
  /** Porta com entradas livres (testemunhas novas). */
  mulFree(va, vb) { return this._gate(this.prover ? va : 0n, this.prover ? vb : 0n); }
  /** Porta cujas entradas são combinações lineares já existentes. */
  mul(a, b) {
    const g = this._gate(this.prover ? this.eval(a) : 0n, this.prover ? this.eval(b) : 0n);
    this.constrain(g.l.sub(a));
    this.constrain(g.r.sub(b));
    return g;
  }
  constrain(lc) { if (lc.t.size || lc.c) this.cons.push(lc); }

  /** Confere (só quem prova) que todas as restrições valem — pega erros antes de provar. */
  check() {
    for (let q = 0; q < this.cons.length; q++) {
      if (this.eval(this.cons[q]) !== 0n) throw new Error(`restrição ${q} não satisfeita`);
    }
  }

  /**
   * Pesos das restrições combinadas com potências de z (z^1 … z^Q):
   * wL, wR, wO (vetores densos de tamanho n), wC[k] (Map pos→peso), wc = Σ z^q·(−constante_q).
   */
  weights(z, n) {
    const m = this.m;
    const wL = new Array(n).fill(0n), wR = new Array(n).fill(0n), wO = new Array(n).fill(0n);
    const wC = this.vcs.map(() => new Map());
    let zq = 1n, wc = 0n;
    for (const lc of this.cons) {
      zq = (zq * z) % m;
      wc = (wc - zq * lc.c) % m;
      for (const [v, c] of lc.t) {
        const w = (zq * c) % m;
        if (v >= 0) {
          const kind = v % 3, i = (v - kind) / 3;
          const arr = kind === 0 ? wL : kind === 1 ? wR : wO;
          arr[i] = (arr[i] + w) % m;
        } else {
          const u = -1 - v, k = Math.floor(u / BIG), pos = u % BIG;
          wC[k].set(pos, ((wC[k].get(pos) ?? 0n) + w) % m);
        }
      }
    }
    return { wL, wR, wO, wC, wc: (wc + m) % m };
  }
}

// ======================================================================== gadgets

/** Bits de um escalar (testemunha): cada bit b com b·b = b. */
export function bitsGadget(cs, value, nbits) {
  const out = [];
  for (let i = 0; i < nbits; i++) {
    const b = cs.prover ? (value >> BigInt(i)) & 1n : 0n;
    const g = cs.mulFree(b, b);
    cs.constrain(g.r.sub(g.l));
    cs.constrain(g.o.sub(g.l));
    out.push(g.l);
  }
  return out;
}

/** Janelas de 3 bits com os produtos necessários para selecionar 1 de 8 valores. */
export function windowsGadget(cs, bits) {
  const W = bits.length / 3, wins = [];
  for (let j = 0; j < W; j++) {
    const [b0, b1, b2] = bits.slice(3 * j, 3 * j + 3);
    const p01 = cs.mul(b0, b1).o, p02 = cs.mul(b0, b2).o, p12 = cs.mul(b1, b2).o;
    const p012 = cs.mul(p01, b2).o;
    wins.push([b0, b1, b2, p01, p02, p12, p012]);
  }
  return wins;
}

/** Seleciona t[d] (d = b0 + 2b1 + 4b2) como combinação linear (coeficientes de Möbius). */
function select8(cs, win, t) {
  const m = cs.m, md = (v) => ((v % m) + m) % m;
  const [b0, b1, b2, p01, p02, p12, p012] = win;
  const c = [
    t[0], md(t[1] - t[0]), md(t[2] - t[0]), md(t[4] - t[0]),
    md(t[3] - t[2] - t[1] + t[0]), md(t[5] - t[4] - t[1] + t[0]), md(t[6] - t[4] - t[2] + t[0]),
    md(t[7] - t[6] - t[5] - t[3] + t[4] + t[2] + t[1] - t[0]),
  ];
  return cs.k(c[0]).addScaled(b0, c[1]).addScaled(b1, c[2]).addScaled(b2, c[3])
    .addScaled(p01, c[4]).addScaled(p02, c[5]).addScaled(p12, c[6]).addScaled(p012, c[7]);
}

/**
 * Soma incompleta A + S de pontos (x, y) dados por combinações lineares (3 portas).
 * Pré-condição: x_A ≠ x_S (garantida pela estrutura das tabelas, ou checada à parte).
 * As coordenadas devolvidas só referenciam as portas desta soma e as de S — as
 * combinações lineares não crescem ao encadear somas.
 */
function addGadget(cs, A, S, vals) {
  const m = cs.m;
  let lam = 0n;
  if (cs.prover) {
    const [xa, ya] = vals.A, [xs, ys] = vals.S;
    lam = ((ys - ya + m) % m) * inv(m, (xs - xa + m) % m) % m;
  }
  const g1 = cs.mulFree(lam, cs.prover ? (vals.S[0] - vals.A[0] + m) % m : 0n);
  cs.constrain(g1.r.sub(S.x.sub(A.x)));          // r1 = xs − xa
  cs.constrain(g1.o.sub(S.y.sub(A.y)));          // λ(xs − xa) = ys − ya
  const g2 = cs.mul(g1.l, g1.l);                  // λ²
  // x3 = λ² − xa − xs, com xa = xs − r1
  const x3 = g2.o.add(g1.r).sub(S.x.scale(2n));
  // λ·(xa − x3) = y3 + ya ;  xa − x3 = 3xs − 2r1 − λ²
  const g3 = cs.mul(g1.l, S.x.scale(3n).sub(g1.r.scale(2n)).sub(g2.o));
  const y3 = g3.o.sub(S.y).add(g1.o);           // y3 = o3 − ya,  ya = ys − o1
  let v3 = null;
  if (cs.prover) {
    const [xa, ya] = vals.A, [xs] = vals.S;
    const xr = (lam * lam - xa - xs) % m, x = (xr + 2n * m) % m;
    v3 = [x, ((lam * (xa - x) - ya) % m + 2n * m) % m];
  }
  return { P: { x: x3, y: y3 }, v: v3 };
}

function inv(m, a) {
  let r0 = ((a % m) + m) % m, r1 = m, s0 = 1n, s1 = 0n;
  if (r0 === 0n) throw new Error('circuito: inverso de zero (soma excepcional)');
  while (r1 !== 0n) { const q = r0 / r1; [r0, r1] = [r1, r0 - q * r1]; [s0, s1] = [s1, s0 - q * s1]; }
  return ((s0 % m) + m) % m;
}

/**
 * Tabela para multiplicação por base fixa em janelas de 3 bits:
 *   T_j[d] = d·8^j·B + 2^j·Ω    (j = 0..W−1, d = 0..7)
 * O deslocamento Ω (independente de B) garante que nenhuma soma do circuito caia num
 * caso excepcional (ponto no infinito, dobra): o coeficiente de Ω no acumulador é
 * 2^j − 1 e no ponto somado é 2^j — nunca iguais.
 * No fim, acumulador = r·B + (2^W − 1)·Ω.
 */
export function fixedBaseTable(curve, B, Omega, W) {
  const js = [];
  let Bj = B.j, Oj = Omega.j;
  for (let j = 0; j < W; j++) {
    let acc = Oj;
    js.push(acc);
    for (let d = 1; d < 8; d++) { acc = curve._add(acc, Bj); js.push(acc); }
    Bj = curve._dbl(curve._dbl(curve._dbl(Bj)));
    Oj = curve._dbl(Oj);
  }
  const aff = curve.batchAffine(js);
  if (aff.some((a) => !a)) throw new Error('tabela de base fixa degenerada');
  const tbl = [];
  for (let j = 0; j < W; j++) tbl.push(aff.slice(8 * j, 8 * j + 8));
  return { tbl, offset: Omega.mul((1n << BigInt(W)) - 1n), W }; // (2^W − 1)·Ω
}

/**
 * "Descegar" um ponto público Ĉ:  C = Ĉ − r·B, com os bits de r já no circuito.
 * Devolve as coordenadas de C como combinações lineares (e os valores, para quem prova).
 * Custo: (W−1)·3 portas das somas + 4 da soma final (com a checagem x ≠ x).
 */
export function unblindGadget(cs, wins, table, Chat, r) {
  const m = cs.m, { tbl, offset, W } = table;
  const dig = (j) => (cs.prover ? Number((r >> BigInt(3 * j)) & 7n) : 0);
  // acumulador A = Σ_j T_j[d_j]
  let A = { x: select8(cs, wins[0], tbl[0].map((p) => p[0])), y: select8(cs, wins[0], tbl[0].map((p) => p[1])) };
  let vA = cs.prover ? tbl[0][dig(0)] : null;
  for (let j = 1; j < W; j++) {
    const S = { x: select8(cs, wins[j], tbl[j].map((p) => p[0])), y: select8(cs, wins[j], tbl[j].map((p) => p[1])) };
    const vS = cs.prover ? tbl[j][dig(j)] : null;
    const res = addGadget(cs, A, S, { A: vA, S: vS });
    A = res.P; vA = res.v;
  }
  // K = Ĉ + (2^W − 1)·Ω (público);  C = K + (−A)
  const K = Chat.add(offset).affine();
  if (!K) throw new Error('ponto público degenerado');
  const Kl = { x: cs.k(K[0]), y: cs.k(K[1]) };
  const negA = { x: A.x, y: A.y.scale(m - 1n) };
  const vNegA = cs.prover ? [vA[0], (m - vA[1]) % m] : null;
  // x_{−A} ≠ x_K (senão a soma seria excepcional e λ ficaria livre)
  const gi = cs.mulFree(cs.prover ? inv(m, (vNegA[0] - K[0] + m) % m) : 0n, cs.prover ? (vNegA[0] - K[0] + m) % m : 0n);
  cs.constrain(gi.r.sub(negA.x.sub(Kl.x)));
  cs.constrain(gi.o.plus(-1n));
  const res = addGadget(cs, Kl, negA, { A: cs.prover ? K : null, S: vNegA });
  return res;
}

/** Ponto "permissível": y + 1 é quadrado (testemunha w com w² = y + 1). */
export function permissibleGadget(cs, y, yVal, sqrtFn) {
  const w = cs.prover ? sqrtFn(yVal + 1n) : 0n;
  if (cs.prover && w === null) throw new Error('ponto não permissível');
  const g = cs.mulFree(w, w);
  cs.constrain(g.r.sub(g.l));
  cs.constrain(g.o.sub(y.plus(1n)));
}

/** x ∈ {e_0, …, e_{k−1}}:  Π (e_j − x) = 0. */
export function selectGadget(cs, entries, x) {
  if (entries.length === 1) { cs.constrain(entries[0].sub(x)); return; }
  let acc = cs.mul(entries[0].sub(x), entries[1].sub(x)).o;
  for (let j = 2; j < entries.length; j++) acc = cs.mul(acc, entries[j].sub(x)).o;
  cs.constrain(acc);
}
