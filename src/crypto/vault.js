// Wallet secret vault (see rust/krevod/src/vault.rs).
//
// The seed enters here once; the spend key, the view key and every derived key stay INSIDE the
// vault. Whoever uses the wallet gets objects that know how to SIGN, compute key images and
// prove ownership — but that do not contain the key. With the Rust/WebAssembly core, the secrets
// live in the core's memory: no BigInt (whose arithmetic has variable timing and which cannot be
// wiped), no key in JavaScript objects that could end up in a file, a log or a JSON by mistake,
// and everything is zeroed when the wallet is closed.
//
// Honest limit: WebAssembly memory is readable by any JavaScript in the same page or process.
// The vault does not isolate against malicious code already running; it prevents leaks through
// timing, carelessness and persistence.
//
// Without WebAssembly, JsVault does the same computations in JavaScript (same interface and results).

import * as core from './wasm.js';
import { Point, mulG, modN, hashToScalar } from './secp256k1.js';
import { H } from './hash.js';
import { subaddressScalar, subaddressKeys, sharedSecret } from './stealth.js';
import { schnorrSign } from './schnorr.js';
import { clsagSign, keyImage } from './clsag.js';
import { mldsaKeyFromSeed, mldsaSign } from './pq.js';
import { dleqProve } from './dleq.js';
import { ecdsaSign } from '../btc/ecdsa.js';
import { gspProveWit } from '../fcmp/fcmp.js';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

// ---------------------------------------------------------------- key descriptors
// { t: i } transparent · { q: i } quantum-safe · { ms: 1 } multisig · { swapKrv: i } / { swapBtc: i }
// Bitcoin swap · { spend: 1 } spend key (public part only) · { out: k, sub } private output
const u32 = (n) => { const b = Buffer.alloc(4); b.writeUInt32LE(n >>> 0); return b; };
const be32 = (n) => Buffer.from(modN(n).toString(16).padStart(64, '0'), 'hex');
function encodeDesc(d) {
  if (d.out !== undefined) return Buffer.concat([Buffer.from([6]), u32(d.sub ?? 0), be32(d.out)]);
  const [kind, i] = d.t !== undefined ? [1, d.t] : d.q !== undefined ? [2, d.q] : d.ms ? [3, 0]
    : d.swapKrv !== undefined ? [4, d.swapKrv] : d.swapBtc !== undefined ? [5, d.swapBtc] : d.spend ? [7, 0] : [0, 0];
  if (!kind) throw new Error('invalid key descriptor');
  return Buffer.concat([Buffer.from([kind]), u32(i)]);
}
const big = (b) => BigInt('0x' + Buffer.from(b).toString('hex'));

/** Opens a vault with the seed (32 bytes). The caller must wipe its own copy (seed.fill(0)). */
export function openVault(seed) {
  if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error('the seed must have 32 bytes');
  return core.available() ? new WasmVault(seed) : new JsVault(seed);
}

class VaultBase {
  /** Object that signs with the descriptor's key (the key never leaves the vault). */
  signer(desc) {
    const v = this;
    let P;
    return {
      desc,
      get P() { return (P ??= v.pub(desc)); },
      sign: (msg, domain = 'sig') => v.sign(desc, msg, domain),
      ecdsa: (hash) => v.ecdsa(desc, hash),
    };
  }
  /** Object that spends the private output with scalar k (from scanning) received on subaddress sub. */
  spender(k, sub = 0) {
    const desc = { out: k, sub };
    return {
      desc,
      keyImage: (P) => this.keyImage(desc, P),
      clsag: (msg, ring, pseudo, pi, z) => this.clsag(desc, msg, ring, pseudo, pi, z),
      gsp: (ctx, Phat, Ihat, D, P, r1, aw) => this.gsp(desc, ctx, Phat, Ihat, D, P, r1, aw),
      dleq: (P, I, ctx) => this.dleq(desc, P, I, ctx),
    };
  }
  shared(R) { return this.sharedMany([R])[0]; }
}

// ---------------------------------------------------------------- WebAssembly core
const closer = typeof FinalizationRegistry !== 'undefined' ? new FinalizationRegistry((h) => { try { core.rawCall(21, h); } catch { /* already closed */ } }) : null;

class WasmVault extends VaultBase {
  constructor(seed) {
    super();
    this.h = Buffer.from(core.rawCall(20, seed));
    closer?.register(this, this.h, this);
  }
  _c(op, ...parts) { if (!this.h) throw new Error('vault closed'); return Buffer.from(core.rawCall(op, Buffer.concat([this.h, ...parts]))); }
  close() { if (this.h) { core.rawCall(21, this.h); closer?.unregister(this); this.h = null; } }
  spendPub() { return Point.fromBytes(this._c(22, encodeDesc({ spend: 1 }))); }
  pub(desc) { return Point.fromBytes(this._c(22, encodeDesc(desc))); }
  subaddress(i) { const r = this._c(23, u32(i)); return { D: Point.fromBytes(r.subarray(0, 33)), C: Point.fromBytes(r.subarray(33)) }; }
  exportViewKey() { const r = this._c(24); return { a: big(r.subarray(0, 32)), B: Point.fromBytes(r.subarray(32)) }; }
  sharedMany(Rs) {
    if (!Rs.length) return [];
    const r = this._c(25, ...Rs.map((R) => (R instanceof Point ? R.toBytes() : Buffer.from(R))));
    return Rs.map((_, i) => r.subarray(33 * i, 33 * i + 33));
  }
  sign(desc, msg, domain = 'sig') {
    const d = Buffer.from(domain, 'utf8');
    return this._c(26, encodeDesc(desc), Buffer.from([d.length]), d, Buffer.from(msg));
  }
  mldsaPub(i) { return this._c(27, u32(i)); }
  mldsaSign(i, msg) { return this._c(28, u32(i), Buffer.from(msg)); }
  keyImage(desc, P) { return Point.fromBytes(this._c(29, encodeDesc(desc), P.toBytes())); }
  clsag(desc, msg, ring, pseudo, pi, z) {
    const n = ring.length;
    const r = this._c(30, encodeDesc(desc), u32(pi), be32(z), pseudo.toBytes(), u32(n), ...ring.flatMap((m) => [m.P.toBytes(), m.C.toBytes()]), Buffer.from(msg));
    const s = [];
    for (let i = 0; i < n; i++) s.push(big(r.subarray(32 + 32 * i, 64 + 32 * i)));
    const o = 32 + 32 * n;
    return { c0: big(r.subarray(0, 32)), s, I: Point.fromBytes(r.subarray(o, o + 33)), D: Point.fromBytes(r.subarray(o + 33, o + 66)) };
  }
  gsp(desc, ctx, Phat, Ihat, D, P, r1, aw) {
    return this._c(31, encodeDesc(desc), Buffer.from(ctx), Phat.toBytes(), Ihat.toBytes(), D.toBytes(), P.toBytes(), be32(r1), be32(aw));
  }
  dleq(desc, P, I, ctx) { const r = this._c(32, encodeDesc(desc), P.toBytes(), I.toBytes(), Buffer.from(ctx)); return { c: big(r.subarray(0, 32)), s: big(r.subarray(32)) }; }
  ecdsa(desc, hash) { const r = this._c(33, encodeDesc(desc), Buffer.from(hash)); return { r: big(r.subarray(0, 32)), s: big(r.subarray(32)) }; }
  nameSalt(name, n) { const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(n)); return this._c(34, Buffer.from([1]), b, Buffer.from(name, 'utf8')); }
  swapSecret(i) { return this._c(34, Buffer.from([2]), u32(i)); }
  seal(data) { return this._c(35, Buffer.from(data)); }
  unseal(blob) { return this._c(36, Buffer.from(blob)); }
}

// ---------------------------------------------------------------- JavaScript fallback
class JsVault extends VaultBase {
  constructor(seed) {
    super();
    this.seed = Buffer.from(seed);
    this.b = hashToScalar('wallet/spend', this.seed);
    this.a = hashToScalar('wallet/view', this.seed);
    this.B = mulG(this.b);
  }
  close() { this.seed?.fill(0); this.seed = null; this.a = this.b = null; }
  _seed() { if (!this.seed) throw new Error('vault closed'); return this.seed; }
  _secret(d) {
    const s = this._seed();
    const x = d.out !== undefined ? modN(d.out + this.b + subaddressScalar(this.a, d.sub ?? 0))
      : d.t !== undefined ? hashToScalar('wallet/t', s, d.t) : d.q !== undefined ? hashToScalar('wallet/q', s, d.q)
        : d.ms ? hashToScalar('wallet/multisig', s) : d.swapKrv !== undefined ? hashToScalar('wallet/swap/krv', s, d.swapKrv)
          : d.swapBtc !== undefined ? hashToScalar('wallet/swap/btc', s, d.swapBtc) : d.spend ? this.b : null;
    if (x === null) throw new Error('invalid key descriptor');
    return x;
  }
  _outKey(d, P) {
    if (d.out === undefined) throw new Error('operation only for private output keys');
    const p = this._secret(d);
    if (!mulG(p).equals(P)) throw new Error('the key does not match the output');
    return p;
  }
  spendPub() { this._seed(); return this.B; }
  pub(desc) { return mulG(this._secret(desc)); }
  subaddress(i) { this._seed(); const s = subaddressKeys(this.a, this.B, i); return { D: s.D, C: s.C }; }
  exportViewKey() { this._seed(); return { a: this.a, B: this.B }; }
  sharedMany(Rs) { this._seed(); return Rs.map((R) => sharedSecret(this.a, R instanceof Point ? R : Point.fromBytes(R))); }
  sign(desc, msg, domain = 'sig') {
    if (desc.out !== undefined || desc.spend || desc.swapBtc !== undefined) throw new Error('this key does not sign Schnorr');
    return schnorrSign(this._secret(desc), msg, domain);
  }
  _mldsa(i) { return mldsaKeyFromSeed(H('wallet/mldsa', this._seed(), i)); }
  mldsaPub(i) { return this._mldsa(i).pub; }
  mldsaSign(i, msg) { return mldsaSign(this._mldsa(i).priv, msg); }
  keyImage(desc, P) { return keyImage(this._outKey(desc, P), P); }
  clsag(desc, msg, ring, pseudo, pi, z) { return clsagSign(msg, ring, pseudo, pi, this._outKey(desc, ring[pi].P), z); }
  gsp(desc, ctx, Phat, Ihat, D, P, r1, aw) {
    const p = this._outKey(desc, P);
    return gspProveWit(ctx, { Phat, Ihat, D, KI: keyImage(p, P) }, { p, t: r1, q: modN(p * p), y: modN(p * r1), a: aw, b: r1 });
  }
  dleq(desc, P, I, ctx) { return dleqProve(this._outKey(desc, P), P, I, ctx); }
  ecdsa(desc, hash) {
    if (desc.swapBtc === undefined) throw new Error('this key does not sign ECDSA');
    return ecdsaSign(this._secret(desc), hash);
  }
  nameSalt(name, n) { return H('wallet/name/salt', this._seed(), name, n); }
  swapSecret(i) { return H('wallet/swap/secret', this._seed(), i); }
  _key() { return H('wallet/store', this._seed()); }
  seal(data) {
    const iv = randomBytes(12), c = createCipheriv('aes-256-gcm', this._key(), iv);
    const ct = Buffer.concat([c.update(Buffer.from(data)), c.final()]);
    return Buffer.concat([iv, ct, c.getAuthTag()]);
  }
  unseal(blob) {
    blob = Buffer.from(blob);
    if (blob.length < 28) throw new Error('encrypted data too short');
    const d = createDecipheriv('aes-256-gcm', this._key(), blob.subarray(0, 12));
    d.setAuthTag(blob.subarray(blob.length - 16));
    try { return Buffer.concat([d.update(blob.subarray(12, blob.length - 16)), d.final()]); } catch { throw new Error('wallet data corrupted or from another seed'); }
  }
}

