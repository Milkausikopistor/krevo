// Curva secp256k1 (y² = x³ + 7) — grupo de ordem prima, sem cofator.
// Implementação em JavaScript puro com BigInt e coordenadas Jacobianas.
//
// Multiplicações por escalar (k·P, k·G) vão para o núcleo em Rust/WebAssembly (./wasm.js), que
// é de TEMPO CONSTANTE: chaves, máscaras e nonces não vazam pelo tempo de execução nem pelo
// padrão de acesso à memória. A aritmética em BigInt abaixo continua servindo à verificação
// (multiexponenciação de dados públicos) e é o plano B se o WebAssembly não estiver
// disponível — correta, mas sem garantia de tempo constante.

import { randomBytes } from 'node:crypto';
import { H, H64 } from './hash.js';
import * as core from './wasm.js';
import { bigToBytesBE, bytesToBigBE, u32le } from '../util/bytes.js';

export const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
export const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

// ---------------------------------------------------------------- campo F_p
const MASK256 = (1n << 256n) - 1n;
const FOLD = 0x1000003d1n; // 2^256 mod p

function fr(x) { // reduz x >= 0 (até ~2^520) módulo p usando a forma especial de p
  let h = x >> 256n; x = (x & MASK256) + h * FOLD;
  h = x >> 256n; x = (x & MASK256) + h * FOLD;
  return x >= P ? x - P : x;
}
const fadd = (a, b) => { const s = a + b; return s >= P ? s - P : s; };
const fsub = (a, b) => { const s = a - b; return s < 0n ? s + P : s; };
const fmul = (a, b) => fr(a * b);
const fsqr = (a) => fr(a * a);

function invMod(a, m) {
  a %= m; if (a < 0n) a += m;
  if (a === 0n) throw new Error('inverso de zero');
  let r0 = a, r1 = m, s0 = 1n, s1 = 0n;
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error('não inversível');
  s0 %= m; return s0 < 0n ? s0 + m : s0;
}
const finv = (a) => invMod(a, P);

function fpow(b, e) {
  let r = 1n; b = fr(b);
  while (e > 0n) { if (e & 1n) r = fmul(r, b); b = fsqr(b); e >>= 1n; }
  return r;
}
const SQRT_EXP = (P + 1n) / 4n;
function fsqrt(a) { const y = fpow(a, SQRT_EXP); return fsqr(y) === a ? y : null; }

// ------------------------------------------------------------ escalares mod n
export const modN = (a) => { a %= N; return a < 0n ? a + N : a; };
export const invN = (a) => invMod(a, N);
export function randomScalar() {
  for (;;) {
    const s = bytesToBigBE(randomBytes(64)) % N;
    if (s !== 0n) return s;
  }
}
export const scalarToBytes = (s) => bigToBytesBE(modN(s), 32);
/**
 * Nonce "hedged": hash do domínio, dos segredos, da mensagem E de 32 bytes aleatórios.
 * Com gerador aleatório quebrado ou previsível vira determinístico (nunca repete para
 * mensagens diferentes — repetir um nonce entregaria a chave); com gerador bom, a parte
 * aleatória protege contra ataques de falha que exploram nonces determinísticos.
 */
export function hedgedScalar(domain, ...parts) {
  for (;;) {
    const k = hashToScalar(domain, ...parts, randomBytes(32));
    if (k !== 0n) return k;
  }
}
/** Lê escalar canônico (< n). Lança erro se não canônico. */
export function scalarFromBytes(b) {
  if (b.length !== 32) throw new Error('escalar deve ter 32 bytes');
  const s = bytesToBigBE(b);
  if (s >= N) throw new Error('escalar não canônico');
  return s;
}
/** Hash para escalar (64 bytes de hash → viés desprezível). */
export const hashToScalar = (domain, ...parts) => bytesToBigBE(H64(domain, ...parts)) % N;

// ---------------------------------------------------- aritmética Jacobiana
// Ponto = [X, Y, Z]; infinito tem Z = 0.
const JINF = [0n, 1n, 0n];

function jdbl(p) {
  const [X1, Y1, Z1] = p;
  if (Z1 === 0n || Y1 === 0n) return JINF;
  const A = fsqr(X1), B = fsqr(Y1), C = fsqr(B);
  let D = fsub(fsqr(fadd(X1, B)), fadd(A, C)); D = fadd(D, D);
  const E = fr(3n * A), F = fsqr(E);
  const X3 = fsub(F, fadd(D, D));
  const Y3 = fsub(fmul(E, fsub(D, X3)), fr(8n * C));
  const Z3 = fr(2n * fmul(Y1, Z1));
  return [X3, Y3, Z3];
}

function jadd(p, q) {
  if (p[2] === 0n) return q;
  if (q[2] === 0n) return p;
  if (q[2] === 1n) return jaddAff(p, q[0], q[1]);
  if (p[2] === 1n) return jaddAff(q, p[0], p[1]);
  const [X1, Y1, Z1] = p, [X2, Y2, Z2] = q;
  const Z1Z1 = fsqr(Z1), Z2Z2 = fsqr(Z2);
  const U1 = fmul(X1, Z2Z2), U2 = fmul(X2, Z1Z1);
  const S1 = fmul(fmul(Y1, Z2), Z2Z2), S2 = fmul(fmul(Y2, Z1), Z1Z1);
  const Hh = fsub(U2, U1), r = fsub(S2, S1);
  if (Hh === 0n) return r === 0n ? jdbl(p) : JINF;
  const H2 = fsqr(Hh), H3 = fmul(Hh, H2), U1H2 = fmul(U1, H2);
  const X3 = fsub(fsub(fsqr(r), H3), fadd(U1H2, U1H2));
  const Y3 = fsub(fmul(r, fsub(U1H2, X3)), fmul(S1, H3));
  const Z3 = fmul(fmul(Z1, Z2), Hh);
  return [X3, Y3, Z3];
}

function jaddAff(p, x2, y2) { // p Jacobiano + (x2, y2) afim
  const [X1, Y1, Z1] = p;
  if (Z1 === 0n) return [x2, y2, 1n];
  const Z1Z1 = fsqr(Z1);
  const U2 = fmul(x2, Z1Z1), S2 = fmul(fmul(y2, Z1), Z1Z1);
  const Hh = fsub(U2, X1), r = fsub(S2, Y1);
  if (Hh === 0n) return r === 0n ? jdbl(p) : JINF;
  const H2 = fsqr(Hh), H3 = fmul(Hh, H2), U1H2 = fmul(X1, H2);
  const X3 = fsub(fsub(fsqr(r), H3), fadd(U1H2, U1H2));
  const Y3 = fsub(fmul(r, fsub(U1H2, X3)), fmul(Y1, H3));
  const Z3 = fmul(Z1, Hh);
  return [X3, Y3, Z3];
}

const jneg = (p) => (p[2] === 0n ? p : [p[0], p[1] === 0n ? 0n : P - p[1], p[2]]);

function jtoAffine(p) {
  if (p[2] === 0n) return null;
  if (p[2] === 1n) return [p[0], p[1]];
  const zi = finv(p[2]), zi2 = fsqr(zi);
  return [fmul(p[0], zi2), fmul(p[1], fmul(zi2, zi))];
}

/** Normaliza vários pontos para coordenadas afins com uma única inversão. */
function batchAffine(points) {
  const n = points.length, acc = new Array(n);
  let run = 1n;
  for (let i = 0; i < n; i++) {
    acc[i] = run;
    if (points[i][2] !== 0n) run = fmul(run, points[i][2]);
  }
  let inv = finv(run);
  const out = new Array(n);
  for (let i = n - 1; i >= 0; i--) {
    const p = points[i];
    if (p[2] === 0n) { out[i] = null; continue; }
    const zi = fmul(inv, acc[i]);
    inv = fmul(inv, p[2]);
    const zi2 = fsqr(zi);
    out[i] = [fmul(p[0], zi2), fmul(p[1], fmul(zi2, zi))];
  }
  return out;
}

function nibbles(k) { // 64 dígitos hexadecimais, do mais significativo ao menos
  const s = k.toString(16).padStart(64, '0');
  const d = new Array(64);
  for (let i = 0; i < 64; i++) d[i] = parseInt(s[i], 16);
  return d;
}

function jmul(p, k) {
  k = modN(k);
  if (k === 0n || p[2] === 0n) return JINF;
  const tbl = [JINF, p];
  for (let i = 2; i < 16; i++) tbl[i] = jadd(tbl[i - 1], p);
  const d = nibbles(k);
  let acc = JINF;
  for (let i = 0; i < 64; i++) {
    if (acc[2] !== 0n) acc = jdbl(jdbl(jdbl(jdbl(acc))));
    if (d[i]) acc = jadd(acc, tbl[d[i]]);
  }
  return acc;
}

// ------------------------------------------------------------------ Point
export class Point {
  constructor(X, Y, Z) { this.j = [X, Y, Z]; this._aff = Z === 1n ? [X, Y] : undefined; }
  static _wrap(j) { return new Point(j[0], j[1], j[2]); }
  static fromAffine(x, y) { return new Point(x, y, 1n); }
  isInf() { return this.j[2] === 0n; }
  affine() {
    if (this._aff === undefined) {
      this._aff = jtoAffine(this.j);
      if (this._aff) this.j = [this._aff[0], this._aff[1], 1n];
    }
    return this._aff;
  }
  add(q) { return Point._wrap(jadd(this.j, q.j)); }
  sub(q) { return Point._wrap(jadd(this.j, jneg(q.j))); }
  neg() { return Point._wrap(jneg(this.j)); }
  dbl() { return Point._wrap(jdbl(this.j)); }
  mul(k) {
    if (this === G) return mulG(k);
    if (core.available()) {
      k = modN(k);
      const a = this.affine();
      if (k === 0n || !a) return INF;
      const r = core.mul(a[0], a[1], k);
      return r ? Point.fromAffine(r[0], r[1]) : INF;
    }
    return Point._wrap(jmul(this.j, k));
  }
  equals(q) {
    const [X1, Y1, Z1] = this.j, [X2, Y2, Z2] = q.j;
    if (Z1 === 0n || Z2 === 0n) return Z1 === 0n && Z2 === 0n;
    const Z1Z1 = fsqr(Z1), Z2Z2 = fsqr(Z2);
    return fmul(X1, Z2Z2) === fmul(X2, Z1Z1) &&
      fmul(fmul(Y1, Z2), Z2Z2) === fmul(fmul(Y2, Z1), Z1Z1);
  }
  /** Codificação comprimida de 33 bytes. O infinito é codificado como 33 zeros. */
  toBytes() {
    const a = this.affine();
    if (!a) return Buffer.alloc(33);
    const out = Buffer.alloc(33);
    out[0] = (a[1] & 1n) ? 3 : 2;
    bigToBytesBE(a[0], 32).copy(out, 1);
    return out;
  }
  hex() { return this.toBytes().toString('hex'); }
  /** Decodifica um ponto comprimido. Rejeita o infinito e pontos fora da curva. */
  static fromBytes(b) {
    b = Buffer.from(b);
    if (b.length !== 33 || (b[0] !== 2 && b[0] !== 3)) throw new Error('ponto inválido');
    const x = bytesToBigBE(b.subarray(1));
    if (x >= P) throw new Error('ponto inválido (x >= p)');
    let y = fsqrt(fadd(fmul(fsqr(x), x), 7n));
    if (y === null) throw new Error('ponto fora da curva');
    if ((y & 1n) !== BigInt(b[0] & 1)) y = P - y;
    return Point.fromAffine(x, y);
  }
}

export const INF = new Point(0n, 1n, 0n);
export const G = Point.fromAffine(GX, GY);

// ------------------------------------------------- base fixa (tabela pré-computada)
export class FixedBase {
  constructor(point) {
    this.point = point;
    this.table = null; // construída sob demanda
  }
  _build() {
    const rows = [];
    let base = this.point.j;
    const flat = [];
    for (let i = 0; i < 64; i++) {
      let acc = base;
      flat.push(acc);
      for (let d = 2; d < 16; d++) { acc = jadd(acc, base); flat.push(acc); }
      base = jdbl(jdbl(jdbl(jdbl(base))));
    }
    const aff = batchAffine(flat);
    for (let i = 0; i < 64; i++) rows.push([null, ...aff.slice(i * 15, i * 15 + 15)]);
    this.table = rows;
  }
  mulJ(k) {
    if (!this.table) this._build();
    k = modN(k);
    if (k === 0n) return JINF;
    const d = nibbles(k);
    let acc = JINF;
    for (let i = 0; i < 64; i++) {
      const di = d[63 - i];
      if (di) { const a = this.table[i][di]; acc = jaddAff(acc, a[0], a[1]); }
    }
    return acc;
  }
  mul(k) { return Point._wrap(this.mulJ(k)); }
}

const G_TABLE = new FixedBase(G);
export function mulG(k) {
  if (core.available()) {
    k = modN(k);
    if (k === 0n) return INF;
    const r = core.mulG(k);
    return Point.fromAffine(r[0], r[1]);
  }
  return G_TABLE.mul(k);
}

// ------------------------------------------------------- multiexponenciação
/**
 * Σ scalars[i] · points[i]. Usa Straus para poucos termos e Pippenger
 * (método de baldes) para muitos — essencial para verificar Bulletproofs.
 */
export function multiexp(scalars, points) {
  if (scalars.length !== points.length) throw new Error('multiexp: tamanhos diferentes');
  const ks = [], ps = [];
  for (let i = 0; i < scalars.length; i++) {
    const k = modN(scalars[i]);
    if (k === 0n || points[i].isInf()) continue;
    if (points[i] === G) { ks.push(k); ps.push(G); continue; }
    ks.push(k); ps.push(points[i]);
  }
  const n = ks.length;
  if (n === 0) return INF;
  // Separa o termo de G para usar a tabela fixa.
  let accG = JINF;
  const ks2 = [], js2 = [];
  for (let i = 0; i < n; i++) {
    if (ps[i] === G) accG = jadd(accG, G_TABLE.mulJ(ks[i]));
    else { ks2.push(ks[i]); js2.push(ps[i].j); }
  }
  let acc;
  if (ks2.length === 0) acc = JINF;
  else if (ks2.length < 24) acc = straus(ks2, js2);
  else acc = pippenger(ks2, js2);
  return Point._wrap(jadd(acc, accG));
}

function straus(ks, js) {
  const n = ks.length;
  const tbls = js.map((p) => {
    const t = [JINF, p];
    for (let i = 2; i < 16; i++) t[i] = jadd(t[i - 1], p);
    return t;
  });
  const digs = ks.map(nibbles);
  let acc = JINF;
  for (let w = 0; w < 64; w++) {
    if (acc[2] !== 0n) acc = jdbl(jdbl(jdbl(jdbl(acc))));
    for (let i = 0; i < n; i++) {
      const d = digs[i][w];
      if (d) acc = jadd(acc, tbls[i][d]);
    }
  }
  return acc;
}

function pippenger(ks, js) {
  const n = ks.length;
  const c = n < 64 ? 5 : n < 256 ? 6 : n < 1024 ? 7 : 8;
  const cb = BigInt(c), mask = (1n << cb) - 1n;
  const windows = Math.ceil(256 / c);
  // pontos em afim para somas mistas mais baratas
  const aff = batchAffine(js);
  let acc = JINF;
  for (let w = windows - 1; w >= 0; w--) {
    for (let i = 0; i < c && acc[2] !== 0n; i++) acc = jdbl(acc);
    const buckets = new Array(1 << c).fill(JINF);
    const shift = BigInt(w * c);
    for (let i = 0; i < n; i++) {
      const d = Number((ks[i] >> shift) & mask);
      if (d && aff[i]) buckets[d] = jaddAff(buckets[d], aff[i][0], aff[i][1]);
    }
    let run = JINF, sum = JINF;
    for (let d = buckets.length - 1; d >= 1; d--) {
      run = jadd(run, buckets[d]);
      sum = jadd(sum, run);
    }
    acc = jadd(acc, sum);
  }
  return acc;
}

// ------------------------------------------------------------ hash → ponto
/**
 * Mapeia dados para um ponto da curva cujo logaritmo discreto ninguém conhece
 * (try-and-increment). Usado para geradores "nada na manga" e imagens de chave.
 * Não é tempo constante, mas as entradas são sempre públicas.
 */
export function hashToPoint(domain, ...parts) {
  for (let ctr = 0; ctr < 256; ctr++) {
    const x = bytesToBigBE(H(domain, ...parts, u32le(ctr)));
    if (x >= P) continue;
    const y = fsqrt(fadd(fmul(fsqr(x), x), 7n));
    if (y === null) continue;
    return Point.fromAffine(x, (y & 1n) ? P - y : y);
  }
  throw new Error('hashToPoint falhou'); // probabilidade ~2^-256
}

/** Soma de vários pontos. */
export function sumPoints(points) {
  let acc = JINF;
  for (const p of points) acc = jadd(acc, p.j);
  return Point._wrap(acc);
}
