// ECDSA over secp256k1, as Bitcoin uses it in segwit v0 addresses (P2WPKH/P2WSH).
//   • deterministic RFC 6979 nonce (HMAC-SHA256): the same message and key always give the
//     same signature — without depending on a random generator;
//   • low S (BIP-62/146): required by Bitcoin's relay policy;
//   • strict DER encoding (BIP-66).
// Uses the project's own curve arithmetic (src/crypto/secp256k1.js).

import { createHmac } from 'node:crypto';
import { N, mulG, Point, invN, modN } from '../crypto/secp256k1.js';
import { bigToBytesBE, bytesToBigBE } from '../util/bytes.js';

const HALF_N = N >> 1n;
const hmac = (key, ...parts) => { const h = createHmac('sha256', key); for (const p of parts) h.update(p); return h.digest(); };

/** Deterministic k (RFC 6979, section 3.2) for key x and a 32-byte hash. */
export function rfc6979Nonce(x, hash) {
  const xb = bigToBytesBE(x, 32);
  const hb = bigToBytesBE(bytesToBigBE(hash) % N, 32);
  let V = Buffer.alloc(32, 1), K = Buffer.alloc(32, 0);
  K = hmac(K, V, Buffer.from([0]), xb, hb); V = hmac(K, V);
  K = hmac(K, V, Buffer.from([1]), xb, hb); V = hmac(K, V);
  for (;;) {
    V = hmac(K, V);
    const k = bytesToBigBE(V);
    if (k >= 1n && k < N) return k;
    K = hmac(K, V, Buffer.from([0])); V = hmac(K, V);
  }
}

export function ecdsaSign(x, hash) {
  if (x <= 0n || x >= N) throw new Error('invalid private key');
  const z = bytesToBigBE(hash);
  const k = rfc6979Nonce(x, hash);
  const r = mulG(k).affine()[0] % N;
  let s = modN(invN(k) * (z + r * x));
  if (r === 0n || s === 0n) throw new Error('degenerate signature (negligible probability)');
  if (s > HALF_N) s = N - s;
  return { r, s };
}

export function ecdsaVerify(pub33, hash, { r, s }) {
  if (r < 1n || r >= N || s < 1n || s >= N) return false;
  let Q;
  try { Q = Point.fromBytes(pub33); } catch { return false; }
  const z = bytesToBigBE(hash);
  const w = invN(s);
  const X = mulG(modN(z * w)).add(Q.mul(modN(r * w))).affine();
  return !!X && X[0] % N === r;
}

export const isLowS = ({ s }) => s >= 1n && s <= HALF_N;

function derInt(v) {
  let b = bigToBytesBE(v, 32);
  let i = 0;
  while (i < 31 && b[i] === 0) i++;
  b = b.subarray(i);
  if (b[0] & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return Buffer.concat([Buffer.from([0x02, b.length]), b]);
}

export function derEncode({ r, s }) {
  const body = Buffer.concat([derInt(r), derInt(s)]);
  return Buffer.concat([Buffer.from([0x30, body.length]), body]);
}

/** Strict DER (BIP-66). Throws if malformed. */
export function derDecode(sig) {
  const b = Buffer.from(sig);
  if (b.length < 8 || b.length > 72 || b[0] !== 0x30 || b[1] !== b.length - 2) throw new Error('invalid DER signature');
  const readInt = (o) => {
    if (b[o] !== 0x02) throw new Error('invalid DER signature');
    const len = b[o + 1];
    if (!len || o + 2 + len > b.length) throw new Error('invalid DER signature');
    const v = b.subarray(o + 2, o + 2 + len);
    if (v[0] & 0x80) throw new Error('DER signature: negative number');
    if (len > 1 && v[0] === 0 && !(v[1] & 0x80)) throw new Error('DER signature: leading zero');
    return { v: bytesToBigBE(v), next: o + 2 + len };
  };
  const r = readInt(2), s = readInt(r.next);
  if (s.next !== b.length) throw new Error('DER signature with leftover bytes');
  return { r: r.v, s: s.v };
}

export const pubFromPriv = (x) => mulG(x).toBytes();
