// The secp256k1 / secq256k1 curve cycle — the foundation of the curve tree (Curve Trees).
//
//   E1 = secp256k1:  y² = x³ + 7 over F_p, order n   (Krevo's usual curve)
//   E2 = secq256k1:  y² = x³ + 7 over F_n, order p   (the "twin": field and order swapped)
//
// Since one curve's field is the other's order, the x coordinate of a point of E1 is a scalar
// of E2 and vice versa. This allows proving, INSIDE a proof over E2, operations with
// points of E1 (and vice versa) — each tree level alternates curves.
//
// Generic pure-JavaScript implementation (BigInt, Jacobian coordinates). Not
// constant-time: secrets only pass through here when proving, on the owner's machine.

import { randomBytes } from 'node:crypto';
import { H, H64 } from '../crypto/hash.js';
import { bigToBytesBE, bytesToBigBE, u32le } from '../util/bytes.js';

export const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
export const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;

// --------------------------------------------------------------------- fields
export class Field {
  constructor(m) {
    this.m = m;
    const MASK = (1n << 256n) - 1n, FOLD = (1n << 256n) % m;
    // fast reduction for moduli 2^256 − c with small c (secp256k1's p); generic (%) for the others
    this.red = FOLD < (1n << 40n)
      ? (x) => { let h = x >> 256n; x = (x & MASK) + h * FOLD; h = x >> 256n; x = (x & MASK) + h * FOLD; return x >= m ? x - m : x; }
      : (x) => x % m;
    // square root: m ≡ 3 (mod 4) → direct exponent; otherwise Tonelli–Shanks
    if (m % 4n === 3n) this.sqrtExp = (m + 1n) / 4n;
    else {
      let q = m - 1n, s = 0n;
      while (!(q & 1n)) { q >>= 1n; s++; }
      let z = 2n;
      while (this.pow(z, (m - 1n) / 2n) !== m - 1n) z++;
      this.ts = { q, s, c: this.pow(z, q) };
    }
  }
  norm(a) { a %= this.m; return a < 0n ? a + this.m : a; }
  add(a, b) { const s = a + b; return s >= this.m ? s - this.m : s; }
  sub(a, b) { const s = a - b; return s < 0n ? s + this.m : s; }
  neg(a) { return a === 0n ? 0n : this.m - a; }
  mul(a, b) { return this.red(a * b); }
  sqr(a) { return this.red(a * a); }
  pow(b, e) {
    let r = 1n; b = this.norm(b);
    while (e > 0n) { if (e & 1n) r = this.red(r * b); b = this.red(b * b); e >>= 1n; }
    return r;
  }
  inv(a) {
    const m = this.m;
    a = this.norm(a);
    if (a === 0n) throw new Error('inverse of zero');
    let r0 = a, r1 = m, s0 = 1n, s1 = 0n;
    while (r1 !== 0n) {
      const q = r0 / r1;
      [r0, r1] = [r1, r0 - q * r1];
      [s0, s1] = [s1, s0 - q * s1];
    }
    s0 %= m; return s0 < 0n ? s0 + m : s0;
  }
  /** Squareness test via the Jacobi symbol (much faster than exponentiation). */
  isSquare(a) {
    a = this.norm(a);
    if (a === 0n) return true;
    let n = this.m, t = 1;
    while (a !== 0n) {
      while ((a & 1n) === 0n) { a >>= 1n; const r = n & 7n; if (r === 3n || r === 5n) t = -t; }
      [a, n] = [n, a];
      if ((a & 3n) === 3n && (n & 3n) === 3n) t = -t;
      a %= n;
    }
    return n === 1n && t === 1;
  }
  /** Square root (which of the two is not guaranteed) or null if none exists. */
  sqrt(a) {
    a = this.norm(a);
    if (a === 0n) return 0n;
    if (this.sqrtExp) { const y = this.pow(a, this.sqrtExp); return this.sqr(y) === a ? y : null; }
    if (!this.isSquare(a)) return null;
    let { q, s: M, c } = this.ts;
    let t = this.pow(a, q), R = this.pow(a, (q + 1n) / 2n);
    while (t !== 1n) {
      let i = 0n, t2 = t;
      while (t2 !== 1n) { t2 = this.sqr(t2); i++; }
      let b = c;
      for (let j = 0n; j < M - i - 1n; j++) b = this.sqr(b);
      M = i; c = this.sqr(b); t = this.mul(t, c); R = this.mul(R, b);
    }
    return R;
  }
  random() {
    for (;;) { const s = bytesToBigBE(randomBytes(64)) % this.m; if (s !== 0n) return s; }
  }
  /** Hash → element (64 bytes of hash: negligible bias). */
  hash(domain, ...parts) { return bytesToBigBE(H64(domain, ...parts)) % this.m; }
  toBytes(a) { return bigToBytesBE(this.norm(a), 32); }
  fromBytes(b) {
    if (b.length !== 32) throw new Error('an element must have 32 bytes');
    const a = bytesToBigBE(b);
    if (a >= this.m) throw new Error('non-canonical element');
    return a;
  }
}

export const Fp = new Field(P);
export const Fn = new Field(N);

// --------------------------------------------------------------------- curves
const JINF = Object.freeze([0n, 1n, 0n]);

export class Curve {
  /** y² = x³ + 7 over `field`, with `order` points (no cofactor). */
  constructor(name, field, scalar) {
    this.name = name; this.F = field; this.S = scalar; this.order = scalar.m;
    const F = field, m = F.m, red = F.red;
    const add = (a, b) => { const s = a + b; return s >= m ? s - m : s; };
    const sub = (a, b) => { const s = a - b; return s < 0n ? s + m : s; };
    this._dbl = (p) => {
      const X1 = p[0], Y1 = p[1], Z1 = p[2];
      if (Z1 === 0n || Y1 === 0n) return JINF;
      const A = red(X1 * X1), B = red(Y1 * Y1), C = red(B * B);
      let D = sub(red(add(X1, B) ** 2n), add(A, C)); D = add(D, D);
      const E = red(3n * A), Fv = red(E * E);
      const X3 = sub(Fv, add(D, D));
      const Y3 = sub(red(E * sub(D, X3)), red(8n * C));
      const Z3 = red(2n * red(Y1 * Z1));
      return [X3, Y3, Z3];
    };
    this._addAff = (p, x2, y2) => {
      const X1 = p[0], Y1 = p[1], Z1 = p[2];
      if (Z1 === 0n) return [x2, y2, 1n];
      const Z1Z1 = red(Z1 * Z1);
      const U2 = red(x2 * Z1Z1), S2 = red(red(y2 * Z1) * Z1Z1);
      const Hh = sub(U2, X1), r = sub(S2, Y1);
      if (Hh === 0n) return r === 0n ? this._dbl(p) : JINF;
      const H2 = red(Hh * Hh), H3 = red(Hh * H2), U1H2 = red(X1 * H2);
      const X3 = sub(sub(red(r * r), H3), add(U1H2, U1H2));
      const Y3 = sub(red(r * sub(U1H2, X3)), red(Y1 * H3));
      return [X3, Y3, red(Z1 * Hh)];
    };
    this._add = (p, q) => {
      if (p[2] === 0n) return q;
      if (q[2] === 0n) return p;
      if (q[2] === 1n) return this._addAff(p, q[0], q[1]);
      if (p[2] === 1n) return this._addAff(q, p[0], p[1]);
      const X1 = p[0], Y1 = p[1], Z1 = p[2], X2 = q[0], Y2 = q[1], Z2 = q[2];
      const Z1Z1 = red(Z1 * Z1), Z2Z2 = red(Z2 * Z2);
      const U1 = red(X1 * Z2Z2), U2 = red(X2 * Z1Z1);
      const S1 = red(red(Y1 * Z2) * Z2Z2), S2 = red(red(Y2 * Z1) * Z1Z1);
      const Hh = sub(U2, U1), r = sub(S2, S1);
      if (Hh === 0n) return r === 0n ? this._dbl(p) : JINF;
      const H2 = red(Hh * Hh), H3 = red(Hh * H2), U1H2 = red(U1 * H2);
      const X3 = sub(sub(red(r * r), H3), add(U1H2, U1H2));
      const Y3 = sub(red(r * sub(U1H2, X3)), red(S1 * H3));
      return [X3, Y3, red(red(Z1 * Z2) * Hh)];
    };
    this._neg = (p) => (p[2] === 0n ? p : [p[0], p[1] === 0n ? 0n : m - p[1], p[2]]);
    this.INF = new CPoint(this, JINF);
    this._gens = new Map();
  }

  onCurve(x, y) { const F = this.F; return F.sqr(y) === F.add(F.mul(F.sqr(x), x), 7n); }
  point(x, y) {
    if (!this.onCurve(x, y)) throw new Error(`${this.name}: point not on the curve`);
    return new CPoint(this, [x, y, 1n]);
  }
  /** Point with this x coordinate and "even" y (or null if x is not on the curve). */
  liftX(x, odd = false) {
    const F = this.F;
    if (x >= F.m) return null;
    const rhs = F.add(F.mul(F.sqr(x), x), 7n);
    if (!F.isSquare(rhs)) return null; // Jacobi: much cheaper than trying the root
    let y = F.sqrt(rhs);
    if (y === null) return null;
    if ((y & 1n) !== (odd ? 1n : 0n)) y = F.neg(y);
    return new CPoint(this, [x, y, 1n]);
  }
  fromBytes(b) {
    b = Buffer.from(b);
    if (b.length !== 33 || (b[0] !== 2 && b[0] !== 3)) throw new Error(`${this.name}: invalid point`);
    const p = this.liftX(bytesToBigBE(b.subarray(1)), b[0] === 3);
    if (!p) throw new Error(`${this.name}: point not on the curve`);
    return p;
  }
  /** "Nothing up my sleeve" point: nobody knows its discrete logarithm. */
  hashToPoint(domain, ...parts) {
    for (let ctr = 0; ctr < 1000; ctr++) {
      const x = bytesToBigBE(H(domain, this.name, ...parts, u32le(ctr)));
      const p = this.liftX(x);
      if (p) return p;
    }
    throw new Error('hashToPoint failed');
  }
  /** Named generator (memoized). */
  gen(label) {
    let g = this._gens.get(label);
    if (!g) { g = this.hashToPoint('fcmp/gen', label); g.affine(); this._gens.set(label, g); }
    return g;
  }

  batchAffine(js) {
    const F = this.F, n = js.length, acc = new Array(n);
    let run = 1n;
    for (let i = 0; i < n; i++) { acc[i] = run; if (js[i][2] !== 0n) run = F.mul(run, js[i][2]); }
    let inv = F.inv(run === 0n ? 1n : run);
    const out = new Array(n);
    for (let i = n - 1; i >= 0; i--) {
      const p = js[i];
      if (p[2] === 0n) { out[i] = null; continue; }
      const zi = F.mul(inv, acc[i]);
      inv = F.mul(inv, p[2]);
      const zi2 = F.sqr(zi);
      out[i] = [F.mul(p[0], zi2), F.mul(p[1], F.mul(zi2, zi))];
    }
    return out;
  }

  _mulJ(p, k) {
    k %= this.order; if (k < 0n) k += this.order;
    if (k === 0n || p[2] === 0n) return JINF;
    const tbl = [JINF, p];
    for (let i = 2; i < 16; i++) tbl[i] = this._add(tbl[i - 1], p);
    const s = k.toString(16);
    let acc = JINF;
    for (let i = 0; i < s.length; i++) {
      if (acc[2] !== 0n) acc = this._dbl(this._dbl(this._dbl(this._dbl(acc))));
      const d = parseInt(s[i], 16);
      if (d) acc = this._add(acc, tbl[d]);
    }
    return acc;
  }

  /** Σ ks[i]·ps[i] (CPoint[]). Straus for few terms, Pippenger for many. */
  msm(ks, ps) { return new CPoint(this, this.msmJ(ks, ps.map((p) => p.j))); }
  /** Same as msm, with points in raw Jacobian coordinates ([X, Y, Z]). */
  msmJ(ks, js) {
    if (ks.length !== js.length) throw new Error('msm: tamanhos diferentes');
    const r = this.order, k2 = [], j2 = [];
    for (let i = 0; i < ks.length; i++) {
      let k = ks[i] % r; if (k < 0n) k += r;
      if (k === 0n || js[i][2] === 0n) continue;
      k2.push(k); j2.push(js[i]);
    }
    if (!k2.length) return JINF;
    return k2.length < 16 ? this._straus(k2, j2) : this._pippenger(k2, j2);
  }

  _straus(ks, js) {
    const tbls = js.map((p) => {
      const t = [JINF, p];
      for (let i = 2; i < 16; i++) t[i] = this._add(t[i - 1], p);
      return t;
    });
    const digs = ks.map((k) => k.toString(16).padStart(64, '0'));
    let acc = JINF;
    for (let w = 0; w < 64; w++) {
      if (acc[2] !== 0n) acc = this._dbl(this._dbl(this._dbl(this._dbl(acc))));
      for (let i = 0; i < ks.length; i++) {
        const d = parseInt(digs[i][w], 16);
        if (d) acc = this._add(acc, tbls[i][d]);
      }
    }
    return acc;
  }

  _pippenger(ks, js) {
    const n = ks.length;
    const c = n < 64 ? 4 : n < 256 ? 6 : n < 1024 ? 7 : n < 8192 ? 8 : 10;
    const windows = Math.ceil(256 / c);
    const aff = this.batchAffine(js);
    // c-bit digits of each scalar (from least to most significant)
    const digits = new Array(n);
    const mask = (1 << c) - 1;
    for (let i = 0; i < n; i++) {
      const d = new Int32Array(windows);
      // 64 bits at a time (BigInt → Number in 32-bit blocks)
      let k = ks[i], bitPos = 0, buf = 0, bufBits = 0, w = 0;
      while (w < windows) {
        if (bufBits < c) {
          const chunk = Number(k & 0xffffffffn); k >>= 32n;
          buf += chunk * 2 ** bufBits; bufBits += 32; // buf < 2^(32+c) — fits in a double
        }
        d[w++] = buf % (mask + 1); buf = Math.floor(buf / (mask + 1)); bufBits -= c; bitPos += c;
      }
      digits[i] = d;
    }
    let acc = JINF;
    for (let w = windows - 1; w >= 0; w--) {
      if (acc[2] !== 0n) for (let i = 0; i < c; i++) acc = this._dbl(acc);
      const buckets = new Array(1 << c).fill(JINF);
      for (let i = 0; i < n; i++) {
        const d = digits[i][w];
        if (d && aff[i]) buckets[d] = this._addAff(buckets[d], aff[i][0], aff[i][1]);
      }
      let run = JINF, sum = JINF;
      for (let d = buckets.length - 1; d >= 1; d--) {
        if (buckets[d][2] !== 0n) run = this._add(run, buckets[d]);
        if (run[2] !== 0n) sum = this._add(sum, run);
      }
      acc = this._add(acc, sum);
    }
    return acc;
  }

  sum(points) { let a = JINF; for (const p of points) a = this._add(a, p.j); return new CPoint(this, a); }
}

export class CPoint {
  constructor(curve, j) { this.c = curve; this.j = j; this._aff = j[2] === 1n ? [j[0], j[1]] : undefined; }
  isInf() { return this.j[2] === 0n; }
  affine() {
    if (this._aff === undefined) {
      const p = this.j;
      if (p[2] === 0n) this._aff = null;
      else {
        const F = this.c.F, zi = F.inv(p[2]), zi2 = F.sqr(zi);
        this._aff = [F.mul(p[0], zi2), F.mul(p[1], F.mul(zi2, zi))];
        this.j = [this._aff[0], this._aff[1], 1n];
      }
    }
    return this._aff;
  }
  get x() { return this.affine()[0]; }
  get y() { return this.affine()[1]; }
  add(q) { return new CPoint(this.c, this.c._add(this.j, q.j)); }
  sub(q) { return new CPoint(this.c, this.c._add(this.j, this.c._neg(q.j))); }
  neg() { return new CPoint(this.c, this.c._neg(this.j)); }
  dbl() { return new CPoint(this.c, this.c._dbl(this.j)); }
  mul(k) { return new CPoint(this.c, this.c._mulJ(this.j, k)); }
  equals(q) {
    const F = this.c.F, [X1, Y1, Z1] = this.j, [X2, Y2, Z2] = q.j;
    if (Z1 === 0n || Z2 === 0n) return Z1 === 0n && Z2 === 0n;
    const Z1Z1 = F.sqr(Z1), Z2Z2 = F.sqr(Z2);
    return F.mul(X1, Z2Z2) === F.mul(X2, Z1Z1) && F.mul(F.mul(Y1, Z2), Z2Z2) === F.mul(F.mul(Y2, Z1), Z1Z1);
  }
  toBytes() {
    const a = this.affine();
    if (!a) return Buffer.alloc(33);
    const out = Buffer.alloc(33);
    out[0] = (a[1] & 1n) ? 3 : 2;
    bigToBytesBE(a[0], 32).copy(out, 1);
    return out;
  }
  hex() { return this.toBytes().toString('hex'); }
}

/** Fixed-base table (4-bit windows, 64 rows × 15 affine points). */
export class FixedBase {
  constructor(point) { this.point = point; this.c = point.c; this.table = null; }
  _build() {
    const c = this.c, flat = [];
    let base = this.point.j;
    for (let i = 0; i < 64; i++) {
      let acc = base;
      flat.push(acc);
      for (let d = 2; d < 16; d++) { acc = c._add(acc, base); flat.push(acc); }
      base = c._dbl(c._dbl(c._dbl(c._dbl(base))));
    }
    const aff = c.batchAffine(flat);
    this.table = [];
    for (let i = 0; i < 64; i++) this.table.push([null, ...aff.slice(i * 15, i * 15 + 15)]);
  }
  mul(k) {
    if (!this.table) this._build();
    const c = this.c;
    k %= c.order; if (k < 0n) k += c.order;
    const s = k.toString(16).padStart(64, '0');
    let acc = JINF;
    for (let i = 0; i < 64; i++) {
      const d = parseInt(s[63 - i], 16);
      if (d) { const a = this.table[i][d]; acc = c._addAff(acc, a[0], a[1]); }
    }
    return new CPoint(c, acc);
  }
}

export const E1 = new Curve('secp256k1', Fp, Fn);
export const E2 = new Curve('secq256k1', Fn, Fp);
