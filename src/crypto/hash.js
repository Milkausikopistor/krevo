// Domain-separated hashing. Every hash function of the protocol goes through here.
// H(domain, parts...) = BLAKE2b-512("KRV" || len(domain) || domain || Σ len(part) || part)
// Each part is prefixed with its length, so there is no concatenation ambiguity.

import { createHash } from 'node:crypto';
import { bigToBytesBE, u32le } from '../util/bytes.js';

function encodePart(p) {
  if (Buffer.isBuffer(p)) return p;
  if (p instanceof Uint8Array) return Buffer.from(p);
  if (typeof p === 'string') return Buffer.from(p, 'utf8');
  if (typeof p === 'bigint') return bigToBytesBE(p, 32);
  if (typeof p === 'number') {
    const b = Buffer.alloc(8); b.writeBigUInt64LE(BigInt(p)); return b;
  }
  if (p && typeof p.toBytes === 'function') return p.toBytes();
  throw new Error('unsupported hash part: ' + typeof p);
}

const PREFIX = Buffer.from('KRV');

export function H64(domain, ...parts) {
  const h = createHash('blake2b512');
  const d = Buffer.from(domain, 'utf8');
  h.update(PREFIX);
  h.update(Buffer.from([d.length]));
  h.update(d);
  for (const p of parts) {
    const b = encodePart(p);
    h.update(u32le(b.length));
    h.update(b);
  }
  return h.digest();
}

/** 32-byte domain-separated hash. */
export const H = (domain, ...parts) => H64(domain, ...parts).subarray(0, 32);

/** SHAKE256 with arbitrary output length (used by MuHash). */
export function shake256(data, outLen) {
  return createHash('shake256', { outputLength: outLen }).update(data).digest();
}
