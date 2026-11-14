// Bulletproofs para circuitos aritméticos (Bünz et al., seção 5) com COMPROMISSOS
// VETORIAIS — a mesma ideia dos "Generalized Bulletproofs" usados nas árvores de curvas.
//
// Relação provada (sem configuração confiável):
//   aL ∘ aR = aO   e   W_L·aL + W_R·aR + W_O·aO + Σ_k W_Ck·c_k = c
// onde cada c_k é o vetor aberto por um compromisso público C_k = <c_k, G> + γ_k·H.
// Os nós (cegados) da árvore são exatamente esses compromissos: a prova "abre" o nó por
// dentro, sem revelar o conteúdo.
//
// Polinômios (potências de Laurent em X):
//   l(X) = (aL + y^-n∘wR)·X + aO·X² + sL·X³ + Σ_k c_k·X^(4+k)
//   r(X) = (wO − y^n) + (y^n∘aR + wL)·X + y^n∘sR·X³ + Σ_k wC_k·X^(−2−k)
// O coeficiente de X² de <l, r> é wc + δ(y, z) exatamente quando as restrições valem;
// cada c_k fica numa potência própria, então não se mistura com aL (nem entre si).
// O argumento de produto interno usa a dobra G' = G_lo + u·G_hi com desafios de 128 bits.

import { H, H64 } from '../crypto/hash.js';
import { randomBytes } from 'node:crypto';
import { bytesToBigBE, u32le } from '../util/bytes.js';

// ------------------------------------------------------------------ geradores
const genCache = new Map();
export function bpGens(curve, n) {
  let c = genCache.get(curve.name);
  if (!c) {
    c = { G: [], H: [], g: curve.gen('bp/g'), h: curve.gen('bp/h'), u: curve.gen('bp/u') };
    genCache.set(curve.name, c);
  }
  while (c.G.length < n) {
    const i = c.G.length;
    c.G.push(curve.hashToPoint('fcmp/bp/G', u32le(i)));
    c.H.push(curve.hashToPoint('fcmp/bp/H', u32le(i)));
  }
  return c;
}

/** Geradores já calculados (para entregar às threads de prova sem recalcular). */
export function exportGens(curve) {
  const c = genCache.get(curve.name);
  if (!c) return null;
  const xy = (p) => [p.x, p.y];
  return { G: c.G.map(xy), H: c.H.map(xy) };
}
export function installGens(curve, data) {
  if (!data) return;
  const c = bpGens(curve, 0);
  if (c.G.length >= data.G.length) return;
  c.G = data.G.map(([x, y]) => curve.point(x, y));
  c.H = data.H.map(([x, y]) => curve.point(x, y));
}

// ------------------------------------------------------------------ transcrição
export class Transcript {
  constructor(label) { this.st = H('fcmp/transcript', label); }
  add(label, ...xs) { this.st = H('fcmp/transcript', this.st, label, ...xs); return this; }
  ch(label, m) {
    for (let ctr = 0; ; ctr++) {
      const c = bytesToBigBE(H64('fcmp/challenge', this.st, label, ctr)) % m;
      if (c !== 0n) { this.add('ch', label, c); return c; }
    }
  }
  ch128(label) {
    for (let ctr = 0; ; ctr++) {
      const c = bytesToBigBE(H('fcmp/challenge128', this.st, label, ctr).subarray(0, 16));
      if (c !== 0n) { this.add('ch128', label, c); return c; }
    }
  }
}

// ------------------------------------------------------------------ utilidades
const powers = (x, n, m) => { const r = new Array(n); let a = 1n; for (let i = 0; i < n; i++) { r[i] = a; a = (a * x) % m; } return r; };
function inner(a, b, m) { let s = 0n; for (let i = 0; i < a.length; i++) if (a[i] && b[i]) s += a[i] * b[i]; return s % m; }
const log2 = (n) => 31 - Math.clz32(n);
export const nextPow2 = (x) => { let p = 1; while (p < x) p <<= 1; return p; };

/** Potências de X presentes em l, r e t (dependem só do número de compromissos K). */
export function tPowers(K) {
  const Lp = [1, 2, 3], Rp = [0, 1, 3];
  for (let k = 0; k < K; k++) { Lp.push(4 + k); Rp.push(-2 - k); }
  const s = new Set();
  for (const i of Lp) for (const j of Rp) if (i + j !== 2) s.add(i + j);
  return { Lp, Rp, T: [...s].sort((a, b) => a - b) };
}

function xpow(F, x, e) { return e >= 0 ? F.pow(x, BigInt(e)) : F.pow(F.inv(x), BigInt(-e)); }

// ======================================================================== provar
/**
 * cs: ConstraintSystem (modo prova) com cs.n (potência de 2) e os compromissos já declarados
 * (entries = Map posição → valor, gamma). tr: Transcript (já com o enunciado público).
 */
export function bpProve(curve, cs, tr, { unsafeSkipChecks = false } = {}) {
  const F = curve.S, m = F.m, n = cs.n, K = cs.vcs.length;
  if (cs.m !== m) throw new Error('bp: campo do circuito ≠ escalares da curva');
  if (cs.nGates > n) throw new Error('bp: portas demais para n');
  if (!unsafeSkipChecks) cs.check(); // (só testes desligam: simulam um provador desonesto)
  const gens = bpGens(curve, n);
  const G = gens.G.slice(0, n), Hs = gens.H.slice(0, n);
  const pad = (a) => { const r = new Array(n).fill(0n); for (let i = 0; i < a.length; i++) r[i] = a[i] ?? 0n; return r; };
  const aL = pad(cs.aL), aR = pad(cs.aR), aO = pad(cs.aO);
  // nonces "hedged": semente = H(testemunha ‖ acaso) — imprevisíveis mesmo com o gerador quebrado
  const seed = H('fcmp/bp/seed', ...aL, ...aR, ...(cs.vcs ?? []).map((v) => v.gamma ?? 0n), randomBytes(32));
  const nonce = (tag, i = 0) => bytesToBigBE(H64('fcmp/bp/nonce', seed, tag, i)) % m;
  const alpha = nonce('alpha'), beta = nonce('beta'), rho = nonce('rho');
  const sL = Array.from({ length: n }, (_, i) => nonce('sL', i)), sR = Array.from({ length: n }, (_, i) => nonce('sR', i));
  const AI = curve.msm([alpha, ...aL, ...aR], [gens.h, ...G, ...Hs]);
  const AO = curve.msm([beta, ...aO], [gens.h, ...G]);
  const S = curve.msm([rho, ...sL, ...sR], [gens.h, ...G, ...Hs]);
  tr.add('AI', AI).add('AO', AO).add('S', S);
  const y = tr.ch('y', m), z = tr.ch('z', m);
  const { wL, wR, wO, wC, wc } = cs.weights(z, n);
  const yp = powers(y, n, m), yi = powers(F.inv(y), n, m);

  const { Lp, Rp, T: Tpow } = tPowers(K);
  const lv = new Map(), rv = new Map();
  lv.set(1, aL.map((a, i) => (a + yi[i] * wR[i]) % m));
  lv.set(2, aO);
  lv.set(3, sL);
  rv.set(0, wO.map((w, i) => (w - yp[i] + m) % m));
  rv.set(1, aR.map((a, i) => (yp[i] * a + wL[i]) % m));
  rv.set(3, sR.map((s, i) => (yp[i] * s) % m));
  cs.vcs.forEach((vc, k) => {
    const c = new Array(n).fill(0n), w = new Array(n).fill(0n);
    for (const [pos, v] of vc.entries) { if (pos >= n) throw new Error('bp: compromisso fora do tamanho'); c[pos] = v % m; }
    for (const [pos, v] of wC[k]) { if (pos >= n) throw new Error('bp: restrição fora do tamanho'); w[pos] = v; }
    lv.set(4 + k, c); rv.set(-2 - k, w);
  });
  const t = new Map();
  for (const i of Lp) for (const j of Rp) t.set(i + j, ((t.get(i + j) ?? 0n) + inner(lv.get(i), rv.get(j), m)) % m);
  let delta = 0n;
  for (let i = 0; i < n; i++) if (wR[i] && wL[i]) delta += yi[i] * wR[i] % m * wL[i];
  if (!unsafeSkipChecks && t.get(2) !== (wc + delta) % m) throw new Error('bp: t2 não confere (circuito inconsistente)');

  const tau = new Map(), Ts = [];
  for (const e of Tpow) {
    const te = nonce('tau', e + 1000);
    tau.set(e, te);
    const Te = curve.msm([t.get(e) ?? 0n, te], [gens.g, gens.h]);
    Ts.push(Te); tr.add('T', String(e), Te);
  }
  const x = tr.ch('x', m);
  const l = new Array(n).fill(0n), r = new Array(n).fill(0n);
  for (const [e, v] of lv) { const xe = xpow(F, x, e); for (let i = 0; i < n; i++) if (v[i]) l[i] = (l[i] + v[i] * xe) % m; }
  for (const [e, v] of rv) { const xe = xpow(F, x, e); for (let i = 0; i < n; i++) if (v[i]) r[i] = (r[i] + v[i] * xe) % m; }
  const that = inner(l, r, m);
  let taux = 0n;
  for (const e of Tpow) taux = (taux + tau.get(e) * xpow(F, x, e)) % m;
  let mu = (alpha * x + beta * x % m * x + rho * F.pow(x, 3n)) % m;
  cs.vcs.forEach((vc, k) => { mu = (mu + (vc.gamma % m) * xpow(F, x, 4 + k)) % m; });
  tr.add('taux', taux).add('mu', mu).add('that', that);
  const w = tr.ch('w', m);
  const Q = gens.u.mul(w).j;

  // ---- argumento de produto interno; H'_i = y^-i·H_i guardado como peso cw_i
  let a = l, b = r, Gv = G.map((p) => p.j), Hv = Hs.map((p) => p.j), cw = yi;
  const Ls = [], Rs = [];
  while (a.length > 1) {
    const h = a.length / 2;
    const aLo = a.slice(0, h), aHi = a.slice(h), bLo = b.slice(0, h), bHi = b.slice(h);
    const cL = inner(aLo, bHi, m), cR = inner(aHi, bLo, m);
    const Lk = curve.msmJ([...aLo, ...bHi.map((v, i) => (v * cw[i]) % m), cL], [...Gv.slice(h), ...Hv.slice(0, h), Q]);
    const Rk = curve.msmJ([...aHi, ...bLo.map((v, i) => (v * cw[h + i]) % m), cR], [...Gv.slice(0, h), ...Hv.slice(h), Q]);
    const LP = new (curve.INF.constructor)(curve, Lk), RP = new (curve.INF.constructor)(curve, Rk);
    Ls.push(LP); Rs.push(RP);
    tr.add('L', LP).add('R', RP);
    const u = tr.ch128('u');
    a = aLo.map((v, i) => (v * u + aHi[i]) % m);
    b = bLo.map((v, i) => (v + bHi[i] * u) % m);
    // G' = G_lo + u·G_hi ;  H'' = u·H'_lo + H'_hi = cw_hi·((u·y^h)·H_lo + H_hi)
    const su = (u * F.pow(y, BigInt(h))) % m;
    const nG = new Array(h), nH = new Array(h);
    for (let i = 0; i < h; i++) {
      nG[i] = curve._add(Gv[i], curve._mulJ(Gv[h + i], u));
      nH[i] = curve._add(Hv[h + i], curve._mulJ(Hv[i], su));
    }
    const ag = curve.batchAffine(nG), ah = curve.batchAffine(nH);
    Gv = ag.map((p) => (p ? [p[0], p[1], 1n] : [0n, 1n, 0n]));
    Hv = ah.map((p) => (p ? [p[0], p[1], 1n] : [0n, 1n, 0n]));
    cw = cw.slice(h);
  }
  return { AI, AO, S, T: Ts, taux, mu, that, L: Ls, R: Rs, a: a[0], b: b[0] };
}

// ===================================================================== verificar
/** Acumulador para verificar várias provas (na mesma curva) com UMA multiexponenciação. */
export class BpBatch {
  constructor(curve) { this.curve = curve; this.n = 0; this.G = []; this.H = []; this.g = 0n; this.h = 0n; this.u = 0n; this.extra = []; }
  _grow(n) { while (this.G.length < n) { this.G.push(0n); this.H.push(0n); } this.n = Math.max(this.n, n); }
  check() {
    const c = this.curve, gens = bpGens(c, this.n);
    const ks = [...this.G, ...this.H, this.g, this.h, this.u, ...this.extra.map((e) => e[0])];
    const ps = [...gens.G.slice(0, this.n), ...gens.H.slice(0, this.n), gens.g, gens.h, gens.u, ...this.extra.map((e) => e[1])];
    return c.msm(ks, ps).isInf();
  }
}

/**
 * Acrescenta ao lote as equações de uma prova. cs: o MESMO circuito montado em modo
 * verificação (com cs.n e os compromissos públicos). Lança erro se a prova for malformada.
 */
export function bpVerifyInto(batch, cs, proof, tr) {
  const curve = batch.curve, F = curve.S, m = F.m, n = cs.n, K = cs.vcs.length;
  const rounds = log2(n);
  if (cs.m !== m || (1 << rounds) !== n) throw new Error('bp: parâmetros inválidos');
  const { T: Tpow } = tPowers(K);
  if (proof.T.length !== Tpow.length || proof.L.length !== rounds || proof.R.length !== rounds) throw new Error('bp: prova com tamanho errado');
  tr.add('AI', proof.AI).add('AO', proof.AO).add('S', proof.S);
  const y = tr.ch('y', m), z = tr.ch('z', m);
  Tpow.forEach((e, i) => tr.add('T', String(e), proof.T[i]));
  const x = tr.ch('x', m);
  tr.add('taux', proof.taux).add('mu', proof.mu).add('that', proof.that);
  const w = tr.ch('w', m);
  const us = [];
  for (let k = 0; k < rounds; k++) { tr.add('L', proof.L[k]).add('R', proof.R[k]); us.push(tr.ch128('u')); }

  const { wL, wR, wO, wC, wc } = cs.weights(z, n);
  const yp = powers(y, n, m), yi = powers(F.inv(y), n, m);
  let delta = 0n;
  for (let i = 0; i < n; i++) if (wR[i] && wL[i]) delta += yi[i] * wR[i] % m * wL[i];
  delta %= m;
  const c1 = F.random(), c2 = F.random();
  batch._grow(n);
  const X = (e) => xpow(F, x, e);
  // (1)  t̂·g + τx·h = x²(wc + δ)·g + Σ x^e·T_e
  batch.g = (batch.g + c1 * ((proof.that - X(2) * ((wc + delta) % m)) % m)) % m;
  batch.h = (batch.h + c1 * proof.taux) % m;
  Tpow.forEach((e, i) => batch.extra.push([(m - c1 * X(e) % m) % m, proof.T[i]]));
  // (2)  produto interno
  let Up = 1n;
  for (const u of us) Up = (Up * u) % m;
  const k2 = (c2 * Up) % m;
  const x1 = x, x2 = X(2), x3 = X(3);
  batch.extra.push([k2 * x1 % m, proof.AI], [k2 * x2 % m, proof.AO], [k2 * x3 % m, proof.S]);
  cs.vcs.forEach((vc, k) => batch.extra.push([k2 * X(4 + k) % m, vc.point]));
  batch.h = (batch.h - k2 * proof.mu) % m;
  batch.u = (batch.u + c2 * ((Up * proof.that - proof.a * proof.b) % m) % m * w) % m;
  let suffix = 1n;
  for (let k = rounds - 1; k >= 0; k--) {
    batch.extra.push([c2 * suffix % m * (us[k] * us[k] % m) % m, proof.L[k]], [c2 * suffix % m, proof.R[k]]);
    suffix = (suffix * us[k]) % m;
  }
  // s_i (G) e s'_i (H): rodada k ↔ bit (rounds−1−k) do índice
  let s = [1n], sp = [1n];
  for (let k = rounds - 1; k >= 0; k--) {
    s = [...s, ...s.map((v) => (v * us[k]) % m)];
    sp = [...sp.map((v) => (v * us[k]) % m), ...sp];
  }
  const xneg = cs.vcs.map((_, k) => X(-2 - k));
  for (let i = 0; i < n; i++) {
    const gi = (k2 * x1 % m * yi[i] % m * wR[i] - c2 * proof.a % m * s[i]) % m;
    let hr = (wO[i] - yp[i] + x1 * wL[i]) % m;
    for (let k = 0; k < cs.vcs.length; k++) { const wk = wC[k].get(i); if (wk) hr = (hr + xneg[k] * wk) % m; }
    const hi = (k2 * yi[i] % m * hr - c2 * proof.b % m * sp[i] % m * yi[i]) % m;
    batch.G[i] = (batch.G[i] + gi) % m;
    batch.H[i] = (batch.H[i] + hi) % m;
  }
  batch.g = ((batch.g % m) + m) % m; batch.h = ((batch.h % m) + m) % m; batch.u = ((batch.u % m) + m) % m;
}

// ================================================================ serialização
export function bpProofSize(n, K) { return (3 + tPowers(K).T.length + 2 * log2(n)) * 33 + 5 * 32; }

export function encodeBpProof(curve, p) {
  const sc = (v) => curve.S.toBytes(v);
  return Buffer.concat([
    p.AI.toBytes(), p.AO.toBytes(), p.S.toBytes(), ...p.T.map((t) => t.toBytes()),
    sc(p.taux), sc(p.mu), sc(p.that),
    ...p.L.flatMap((L, k) => [L.toBytes(), p.R[k].toBytes()]),
    sc(p.a), sc(p.b),
  ]);
}
export function decodeBpProof(curve, buf, n, K) {
  if (buf.length !== bpProofSize(n, K)) throw new Error('bp: tamanho de prova inválido');
  let o = 0;
  const pt = () => { const p = curve.fromBytes(buf.subarray(o, o + 33)); o += 33; return p; };
  const sc = () => { const v = curve.S.fromBytes(buf.subarray(o, o + 32)); o += 32; return v; };
  const AI = pt(), AO = pt(), S = pt();
  const T = tPowers(K).T.map(() => pt());
  const taux = sc(), mu = sc(), that = sc();
  const L = [], R = [];
  for (let k = 0; k < log2(n); k++) { L.push(pt()); R.push(pt()); }
  const a = sc(), b = sc();
  return { AI, AO, S, T, taux, mu, that, L, R, a, b };
}
