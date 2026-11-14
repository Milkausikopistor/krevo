// Bulletproofs — provas de intervalo agregadas (Bünz, Bootle, Boneh, Poelstra,
// Wuille, Maxwell, 2018). Provam que cada valor escondido em um compromisso
// C = x·G + v·H está em [0, 2^64), sem revelar v. Sem isso, alguém poderia
// criar uma saída "negativa" e inflar a oferta.
//
// Tamanho: 2·log2(64·m) + 9 elementos — ~690 bytes para 1 saída, ~755 para 2.
// Nenhuma configuração confiável (trusted setup): todos os geradores vêm de hash.
//
// Convenção: valor no gerador Hv, cegamento no gerador G (C = xG + vHv).

import { randomBytes } from 'node:crypto';
import { G, N, modN, invN, multiexp, hashToPoint, hashToScalar, randomScalar, hedgedScalar,
  scalarToBytes, scalarFromBytes, Point, mulG } from './secp256k1.js';
import { Hv, commit } from './pedersen.js';
import { H } from './hash.js';
import * as core from './wasm.js';
import { u32le, bytesToBigBE } from '../util/bytes.js';

export const BITS = 64;
export const MAX_AGGREGATION = 16;

const Gi = [], Hi = [];
function ensureGens(n) {
  while (Gi.length < n) {
    const i = Gi.length;
    Gi.push(hashToPoint('bp/G', u32le(i)));
    Hi.push(hashToPoint('bp/H', u32le(i)));
  }
}
const U = hashToPoint('bp/U', 'produto interno');

class Transcript {
  constructor(label) { this.st = H('bp/transcript', label); }
  add(label, x) { this.st = H('bp/transcript', this.st, label, x); }
  ch(label) {
    const c = hashToScalar('bp/challenge', this.st, label);
    if (c === 0n) throw new Error('desafio zero');
    this.add('ch', c);
    return c;
  }
}

function powers(x, n) {
  const r = new Array(n);
  let acc = 1n;
  for (let i = 0; i < n; i++) { r[i] = acc; acc = modN(acc * x); }
  return r;
}
const inner = (a, b) => { let s = 0n; for (let i = 0; i < a.length; i++) s += a[i] * b[i]; return modN(s); };
const log2 = (n) => 31 - Math.clz32(n);
const padM = (m) => { let p = 1; while (p < m) p <<= 1; return p; };

function startTranscript(V, m0) {
  const T = new Transcript('rangeproof');
  T.add('bits', BITS);
  T.add('m', m0);
  for (const v of V) T.add('V', v);
  return T;
}

/**
 * Cria prova agregada para values[j] com cegamentos gammas[j].
 * Retorna { V: Point[], proof: Buffer }.
 */
export function proveRange(values, gammas) {
  const m0 = values.length;
  if (m0 < 1 || m0 > MAX_AGGREGATION || gammas.length !== m0) throw new Error('bp: número de valores inválido');
  for (const v of values) if (v < 0n || v >= (1n << 64n)) throw new Error('bp: valor fora do intervalo');
  if (core.available()) {
    // núcleo em Rust: bits dos valores e máscaras em tempo constante; prova conferida antes de sair
    const r = core.proveRange(values, gammas.map(modN));
    return { V: r.V.map((b) => Point.fromBytes(b)), proof: r.proof };
  }
  const m = padM(m0), nn = BITS * m;
  ensureGens(nn);
  const v = [...values, ...new Array(m - m0).fill(0n)];
  const gamma = [...gammas, ...new Array(m - m0).fill(0n)];
  const V = values.map((vi, j) => commit(vi, gamma[j]));

  const aL = new Array(nn), aR = new Array(nn);
  for (let j = 0; j < m; j++) {
    for (let i = 0; i < BITS; i++) {
      const bit = (v[j] >> BigInt(i)) & 1n;
      aL[j * BITS + i] = bit;
      aR[j * BITS + i] = bit === 1n ? 0n : N - 1n;
    }
  }
  const GG = Gi.slice(0, nn), HH = Hi.slice(0, nn);
  // nonces de uma semente "hedged" (máscaras + valores + compromissos + acaso)
  const seed = scalarToBytes(hedgedScalar('bp/seed', ...gamma.map(scalarToBytes), ...v.map((x) => scalarToBytes(x)), ...V));
  const nonce = (tag, i = 0) => hashToScalar('bp/nonce', seed, tag, i);
  const alpha = nonce('alpha'), rho = nonce('rho');
  const sL = Array.from({ length: nn }, (_, i) => nonce('sL', i)), sR = Array.from({ length: nn }, (_, i) => nonce('sR', i));
  const A = multiexp([alpha, ...aL, ...aR], [G, ...GG, ...HH]);
  const S = multiexp([rho, ...sL, ...sR], [G, ...GG, ...HH]);

  const T = startTranscript(V, m0);
  T.add('A', A); T.add('S', S);
  const y = T.ch('y'), z = T.ch('z');
  const yp = powers(y, nn), zp = powers(z, m + 3), two = powers(2n, BITS);

  const l0 = new Array(nn), l1 = sL, r0 = new Array(nn), r1 = new Array(nn);
  for (let i = 0; i < nn; i++) {
    const j = Math.floor(i / BITS);
    l0[i] = modN(aL[i] - z);
    r0[i] = modN(yp[i] * (aR[i] + z) + zp[2 + j] * two[i % BITS]);
    r1[i] = modN(yp[i] * sR[i]);
  }
  const t1 = modN(inner(l0, r1) + inner(l1, r0));
  const t2 = inner(l1, r1);
  const tau1 = nonce('tau1'), tau2 = nonce('tau2');
  const T1 = commit(t1, tau1), T2 = commit(t2, tau2);
  T.add('T1', T1); T.add('T2', T2);
  const x = T.ch('x');

  let taux = modN(tau2 * x * x + tau1 * x);
  for (let j = 0; j < m; j++) taux = modN(taux + zp[2 + j] * gamma[j]);
  const mu = modN(alpha + rho * x);
  const l = l0.map((a, i) => modN(a + l1[i] * x));
  const r = r0.map((a, i) => modN(a + r1[i] * x));
  const that = inner(l, r);
  T.add('taux', taux); T.add('mu', mu); T.add('that', that);
  const w = T.ch('w');
  const Q = U.mul(w);

  // Argumento de produto interno (protocolo 2 do artigo, com Fiat–Shamir).
  const yinv = invN(y), ypinv = powers(yinv, nn);
  let gv = GG, hv = HH.map((h, i) => h.mul(ypinv[i]));
  let a = l, b = r;
  const Ls = [], Rs = [];
  while (a.length > 1) {
    const h2 = a.length / 2;
    const aLo = a.slice(0, h2), aHi = a.slice(h2), bLo = b.slice(0, h2), bHi = b.slice(h2);
    const gLo = gv.slice(0, h2), gHi = gv.slice(h2), hLo = hv.slice(0, h2), hHi = hv.slice(h2);
    const cL = inner(aLo, bHi), cR = inner(aHi, bLo);
    const L = multiexp([...aLo, ...bHi, cL], [...gHi, ...hLo, Q]);
    const R = multiexp([...aHi, ...bLo, cR], [...gLo, ...hHi, Q]);
    Ls.push(L); Rs.push(R);
    T.add('L', L); T.add('R', R);
    const u = T.ch('u'), ui = invN(u);
    gv = gLo.map((g, i) => multiexp([ui, u], [g, gHi[i]]));
    hv = hLo.map((h, i) => multiexp([u, ui], [h, hHi[i]]));
    a = aLo.map((x0, i) => modN(x0 * u + aHi[i] * ui));
    b = bLo.map((x0, i) => modN(x0 * ui + bHi[i] * u));
  }
  const proof = Buffer.concat([
    A.toBytes(), S.toBytes(), T1.toBytes(), T2.toBytes(),
    scalarToBytes(taux), scalarToBytes(mu), scalarToBytes(that),
    ...Ls.flatMap((L, k) => [L.toBytes(), Rs[k].toBytes()]),
    scalarToBytes(a[0]), scalarToBytes(b[0]),
  ]);
  return { V, proof };
}

export function rangeProofSize(m0) {
  const rounds = log2(BITS * padM(m0));
  return 4 * 33 + 3 * 32 + rounds * 66 + 64;
}

function parseProof(buf, m0) {
  if (buf.length !== rangeProofSize(m0)) throw new Error('bp: tamanho inválido');
  let o = 0;
  const pt = () => { const p = Point.fromBytes(buf.subarray(o, o + 33)); o += 33; return p; };
  const sc = () => { const s = scalarFromBytes(buf.subarray(o, o + 32)); o += 32; return s; };
  const A = pt(), S = pt(), T1 = pt(), T2 = pt();
  const taux = sc(), mu = sc(), that = sc();
  const rounds = log2(BITS * padM(m0));
  const L = [], R = [];
  for (let k = 0; k < rounds; k++) { L.push(pt()); R.push(pt()); }
  const a = sc(), b = sc();
  return { A, S, T1, T2, taux, mu, that, L, R, a, b };
}

/** Verifica a prova contra os compromissos V (Point[]). Uma única multiexponenciação. */
export function verifyRange(V, proofBuf) {
  try {
    const m0 = V.length;
    if (m0 < 1 || m0 > MAX_AGGREGATION) return false;
    const pf = parseProof(proofBuf, m0);
    const m = padM(m0), nn = BITS * m, rounds = log2(nn);
    ensureGens(nn);

    const T = startTranscript(V, m0);
    T.add('A', pf.A); T.add('S', pf.S);
    const y = T.ch('y'), z = T.ch('z');
    T.add('T1', pf.T1); T.add('T2', pf.T2);
    const x = T.ch('x');
    T.add('taux', pf.taux); T.add('mu', pf.mu); T.add('that', pf.that);
    const w = T.ch('w');
    const u = [];
    for (let k = 0; k < rounds; k++) { T.add('L', pf.L[k]); T.add('R', pf.R[k]); u.push(T.ch('u')); }

    const uinv = u.map(invN);
    const u2 = u.map((v) => modN(v * v)), uinv2 = uinv.map((v) => modN(v * v));
    // s_i = Π_k u_k^{±1}; bit (rounds−1−k) de i decide o sinal da rodada k.
    const s = new Array(nn);
    s[0] = uinv.reduce((acc, v) => modN(acc * v), 1n);
    for (let i = 1; i < nn; i++) {
      const j = 31 - Math.clz32(i);          // bit mais alto de i
      const k = rounds - 1 - j;              // rodada que divide por esse bit
      s[i] = modN(s[i - (1 << j)] * u2[k]);
    }
    const yinv = invN(y), ypinv = powers(yinv, nn), yp = powers(y, nn);
    const zp = powers(z, m + 3), two = powers(2n, BITS);
    const sumY = yp.reduce((acc, v) => acc + v, 0n);
    let delta = modN((z - z * z) * sumY);
    const ones64 = (1n << 64n) - 1n;
    for (let j = 0; j < m; j++) delta = modN(delta - zp[3 + j] * ones64);

    const c = bytesToBigBE(randomBytes(32)) % N; // peso aleatório do verificador
    const scalars = [], points = [];
    const push = (k, p) => { scalars.push(k); points.push(p); };
    push(1n, pf.A);
    push(x, pf.S);
    push(modN(-pf.mu + c * pf.taux), G);
    push(modN(w * (pf.that - pf.a * pf.b)), U);
    push(modN(c * (pf.that - delta)), Hv);
    for (let j = 0; j < m0; j++) push(modN(-c * zp[2 + j]), V[j]);
    push(modN(-c * x), pf.T1);
    push(modN(-c * x * x), pf.T2);
    for (let k = 0; k < rounds; k++) { push(u2[k], pf.L[k]); push(uinv2[k], pf.R[k]); }
    for (let i = 0; i < nn; i++) {
      const j = Math.floor(i / BITS);
      push(modN(-z - pf.a * s[i]), Gi[i]);
      const sinv = s[nn - 1 - i];
      push(modN(z + ypinv[i] * (zp[2 + j] * two[i % BITS] - pf.b * sinv)), Hi[i]);
    }
    return multiexp(scalars, points).isInf();
  } catch {
    return false;
  }
}
export { mulG };
