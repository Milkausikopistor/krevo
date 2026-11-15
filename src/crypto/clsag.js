// CLSAG — Concise Linkable Spontaneous Anonymous Group signature
// (Goodell, Noether, RandomRun, 2019), adapted to secp256k1 (no cofactor).
//
// Proves, without revealing WHICH ring member is spent, that the signer:
//   1) knows p such that P_π = p·G   (owns the real output)
//   2) knows z such that C_π − C' = z·G  (the pseudo-commitment C' has the same amount)
// and publishes the key image I = p·Hp(P_π), which is unique per output: spending the same
// output twice produces the same I, and the network rejects repeated images.

import { G, N, mulG, modN, multiexp, hashToPoint, hashToScalar, randomScalar, hedgedScalar,
  scalarToBytes, scalarFromBytes, Point } from './secp256k1.js';
import { H } from './hash.js';

const hpCache = new Map();
/** Hp(P): hash point used in the key image. */
export function hashPointForKeyImage(P) {
  const k = P.hex();
  let r = hpCache.get(k);
  if (!r) {
    r = hashToPoint('clsag/keyimage', P);
    if (hpCache.size > 50_000) hpCache.clear();
    hpCache.set(k, r);
  }
  return r;
}
export const keyImage = (p, P) => hashPointForKeyImage(P).mul(p);

function aggCoefs(ring, pseudo, I, D) {
  const ringP = Buffer.concat(ring.map((m) => m.P.toBytes()));
  const ringC = Buffer.concat(ring.map((m) => m.C.toBytes()));
  const muP = hashToScalar('clsag/agg0', ringP, ringC, I, D, pseudo);
  const muC = hashToScalar('clsag/agg1', ringP, ringC, I, D, pseudo);
  const prefix = H('clsag/prefix', ringP, ringC, pseudo);
  return { muP, muC, prefix };
}
const roundHash = (prefix, msg, L, R) => hashToScalar('clsag/round', prefix, msg, L, R);

/**
 * ring: [{P: Point, C: Point}], pseudo: Point, pi: real index,
 * p: one-time private key, z: x_real − x_pseudo.
 */
export function clsagSign(msg, ring, pseudo, pi, p, z) {
  const n = ring.length;
  const HpPi = hashPointForKeyImage(ring[pi].P);
  if (!mulG(p).equals(ring[pi].P)) throw new Error('clsag: key does not match the real member');
  if (!mulG(z).equals(ring[pi].C.sub(pseudo))) throw new Error('clsag: commitment does not match');
  const I = HpPi.mul(p), D = HpPi.mul(z);
  const { muP, muC, prefix } = aggCoefs(ring, pseudo, I, D);
  const Wtilde = multiexp([muP, muC], [I, D]);
  const w = modN(muP * p + muC * z);
  const s = new Array(n), c = new Array(n);
  const alpha = hedgedScalar('clsag/alpha', scalarToBytes(p), scalarToBytes(z), msg, I, pseudo);
  c[(pi + 1) % n] = roundHash(prefix, msg, mulG(alpha), HpPi.mul(alpha));
  for (let k = 1; k < n; k++) {
    const i = (pi + k) % n;
    s[i] = randomScalar();
    const ci = c[i];
    const L = multiexp([s[i], modN(ci * muP), modN(ci * muC)], [G, ring[i].P, ring[i].C.sub(pseudo)]);
    const R = multiexp([s[i], ci], [hashPointForKeyImage(ring[i].P), Wtilde]);
    c[(i + 1) % n] = roundHash(prefix, msg, L, R);
  }
  s[pi] = modN(alpha - c[pi] * w);
  const sig = { c0: c[0], s, I, D };
  // check before returning: a fault halfway through cannot become a signature that leaks p
  if (!clsagVerify(msg, ring, pseudo, sig)) throw new Error('clsag: signing failed (self-verification)');
  return sig;
}

export function clsagVerify(msg, ring, pseudo, sig) {
  const { c0, s, I, D } = sig;
  const n = ring.length;
  if (n < 1 || s.length !== n || I.isInf() || D.isInf()) return false;
  const { muP, muC, prefix } = aggCoefs(ring, pseudo, I, D);
  const Wtilde = multiexp([muP, muC], [I, D]);
  let c = c0;
  for (let i = 0; i < n; i++) {
    const L = multiexp([s[i], modN(c * muP), modN(c * muC)], [G, ring[i].P, ring[i].C.sub(pseudo)]);
    const R = multiexp([s[i], c], [hashPointForKeyImage(ring[i].P), Wtilde]);
    c = roundHash(prefix, msg, L, R);
  }
  return c === c0;
}

/** Serialization of the "witness" part (the key image I goes in the tx body). */
export function encodeClsag(sig) {
  return Buffer.concat([scalarToBytes(sig.c0), ...sig.s.map(scalarToBytes), sig.D.toBytes()]);
}
export function decodeClsag(buf, n, I) {
  if (buf.length !== 32 + 32 * n + 33) throw new Error('clsag: invalid size');
  const c0 = scalarFromBytes(buf.subarray(0, 32));
  const s = [];
  for (let i = 0; i < n; i++) s.push(scalarFromBytes(buf.subarray(32 + 32 * i, 64 + 32 * i)));
  const D = Point.fromBytes(buf.subarray(32 + 32 * n));
  return { c0, s, I, D };
}
export const clsagSize = (n) => 32 + 32 * n + 33;
export { N };
