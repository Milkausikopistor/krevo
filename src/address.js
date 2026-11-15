// Addresses (Bech32m).
//   transparent:  krv1...  data = [0x00] + public key (33)                 — public amounts
//   private:      krs1...  data = [0x01] + A (33) + B (33)                  — amounts and recipient hidden
//   view key:     krw1...  data = [0x02] + a (32) + B (33)                  — read-only, for audits
//   multisig:     krv1…    data = [0x03] + hash of the M-of-N policy (32)   — transparent, requires M signatures
//   quantum-safe: krq1...  data = [0x04] + hash(Schnorr key ‖ ML-DSA key) (32) — transparent, quantum-resistant
// The prefix changes per network (krvdev/krsdev on devnet), preventing payments to the wrong network.

import { encode, decode } from './util/bech32m.js';
import { Point, scalarFromBytes, scalarToBytes } from './crypto/secp256k1.js';
import { LOCK_NAME, LOCK_NAME_COMMIT, parseNameRecord } from './consensus/names.js';

export const ADDR_TRANSPARENT = 0x00;
export const ADDR_SHIELDED = 0x01;
export const ADDR_VIEWKEY = 0x02;
export const ADDR_MULTISIG = 0x03;
export const ADDR_PQ = 0x04;

/** Transparent address data = lock of a transparent output. */
export const transparentData = (pubkey) => Buffer.concat([Buffer.from([ADDR_TRANSPARENT]), pubkey.toBytes()]);
export const shieldedData = (A, B) => Buffer.concat([Buffer.from([ADDR_SHIELDED]), A.toBytes(), B.toBytes()]);

/** Parses address data (also used in the coinbase payload). Throws if invalid. */
export function parseAddressData(data) {
  data = Buffer.from(data);
  if (data[0] === ADDR_TRANSPARENT && data.length === 34) {
    return { type: 't', data, pubkey: Point.fromBytes(data.subarray(1)) };
  }
  if (data[0] === ADDR_SHIELDED && data.length === 67) {
    return { type: 's', data, A: Point.fromBytes(data.subarray(1, 34)), B: Point.fromBytes(data.subarray(34)) };
  }
  if (data[0] === ADDR_MULTISIG && data.length === 33) {
    return { type: 'm', data, hash: data.subarray(1) };
  }
  if (data[0] === ADDR_PQ && data.length === 33) {
    return { type: 'q', data, hash: data.subarray(1) };
  }
  // locks that are not addresses: name record (@name) and name commitment
  if (data[0] === LOCK_NAME) return { type: 'n', data, record: parseNameRecord(data) };
  if (data[0] === LOCK_NAME_COMMIT && data.length === 33) return { type: 'c', data, hash: data.subarray(1) };
  throw new Error('invalid address data');
}

/** Text to display any lock: the address, or what it is (name record/commitment). */
export function describeLock(params, lock) {
  if (lock[0] === LOCK_NAME) {
    try { return `@${parseNameRecord(lock).name} (name record)`; } catch { return 'invalid name record'; }
  }
  if (lock[0] === LOCK_NAME_COMMIT) return 'name commitment (hidden until the reveal)';
  return encodeAddress(params, lock);
}

const HRP_OF = { t: 't', m: 't', s: 's', q: 'q' };

export function encodeAddress(params, data) {
  const t = data[0];
  if (t === LOCK_NAME || t === LOCK_NAME_COMMIT) throw new Error('this lock is not an address (it is a name record)');
  const hrp = t === ADDR_TRANSPARENT || t === ADDR_MULTISIG ? params.hrp.t : t === ADDR_SHIELDED ? params.hrp.s : t === ADDR_PQ ? params.hrp.q : params.hrp.v;
  return encode(hrp, data);
}

export function decodeAddress(params, str) {
  const { hrp, bytes } = decode(str.trim());
  const info = parseAddressData(bytes);
  const expected = params.hrp[HRP_OF[info.type]];
  if (hrp !== expected) throw new Error(`address of another network or type (prefix ${hrp}, expected ${expected})`);
  return info;
}

export function encodeViewKey(params, a, B) {
  return encode(params.hrp.v, Buffer.concat([Buffer.from([ADDR_VIEWKEY]), scalarToBytes(a), B.toBytes()]));
}
export function decodeViewKey(params, str) {
  const { hrp, bytes } = decode(str.trim());
  if (hrp !== params.hrp.v || bytes[0] !== ADDR_VIEWKEY || bytes.length !== 66) throw new Error('invalid view key');
  return { a: scalarFromBytes(bytes.subarray(1, 33)), B: Point.fromBytes(bytes.subarray(33)) };
}
