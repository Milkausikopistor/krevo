// Stealth addresses with subaddresses.
//
// Wallet: view key a, spend key b, B = b·G.
// Subaddress i (the main address is subaddress 0):
//   m_i = 0 if i = 0, otherwise Hs("subaddr", a, i)
//   D_i = B + m_i·G          C_i = a·D_i          address_i = (C_i, D_i)
// Every address has the SAME form: nobody can tell the main address from a subaddress, nor
// find out that two subaddresses belong to the same wallet.
//
// Sender, for the output of index j paid to the address (C, D):
//   r_j random PER OUTPUT,  R_j = r_j·D   (published in the output itself)
//   ss = r_j·C               (the recipient computes a·R_j = a·r_j·D = r_j·C)
//   k  = Hs(ss, j)
//   P  = k·G + D             (one-time key)
//   x  = Hs'(ss, j)          (commitment blinding)
//   C  = x·G + v·H, encrypted amount = v XOR H''(ss, j), tag = H'''(ss, j)[0]
//
// Recipient: ss = a·R_j, D' = P − k·G, and looks D' up in a table of subaddresses
// (ONE multiplication per output, no matter how many subaddresses exist).
// One-time private key p = k + b + m_i; key image I = p·Hp(P).
// Whoever has only (a, B) — the "view key" — sees incoming payments to every subaddress,
// but cannot spend.

import { createCipheriv, createDecipheriv } from 'node:crypto';
import { H } from './hash.js';
import { mulG, hashToScalar, modN } from './secp256k1.js';

/** Scalar of subaddress i (0 for the main address). */
export const subaddressScalar = (a, i) => (i === 0 ? 0n : hashToScalar('stealth/subaddr', a, i));

/** Points (C, D) of subaddress i. */
export function subaddressKeys(a, B, i) {
  const m = subaddressScalar(a, i);
  const D = m === 0n ? B : B.add(mulG(m));
  return { index: i, m, D, C: D.mul(a) };
}
import { commit, mulH } from './pedersen.js';
import { u64le } from '../util/bytes.js';

export const sharedSecret = (scalar, point) => point.mul(scalar).toBytes();
export const outputScalar = (ss, i) => hashToScalar('stealth/key', ss, i);
export const viewTag = (ss, i) => H('stealth/tag', ss, i)[0];
export const blindingFactor = (ss, i) => hashToScalar('stealth/blind', ss, i);
const amountMask = (ss, i) => H('stealth/amount', ss, i).subarray(0, 8);

export function encryptAmount(v, ss, i) {
  const b = u64le(v), m = amountMask(ss, i);
  for (let j = 0; j < 8; j++) b[j] ^= m[j];
  return b;
}
export function decryptAmount(enc, ss, i) {
  const b = Buffer.from(enc), m = amountMask(ss, i);
  for (let j = 0; j < 8; j++) b[j] ^= m[j];
  return b.readBigUInt64LE(0);
}

/**
 * Creates the private output of index i for the address (A, B) = (C, D) with this output's
 * secret r. coinbase=true uses zero blinding (the reward amount is already public).
 */
export function makeShieldedOutput({ A, B }, r, i, v, coinbase = false) {
  const R = B.mul(r);
  const ss = sharedSecret(r, A);
  const k = outputScalar(ss, i);
  const P = mulG(k).add(B);
  const x = coinbase ? 0n : blindingFactor(ss, i);
  const C = coinbase ? mulH(v) : commit(v, x);
  return { R, P, C, encAmount: encryptAmount(v, ss, i), viewTag: viewTag(ss, i), x, ss };
}

/**
 * Tries to recognize a private output.
 * keys = { a, B, b?, table?, sub? } (raw keys: light server, view key, tests)
 *     or { vault, B, table } — the wallet: a·R is computed INSIDE the vault (src/crypto/vault.js).
 * table: Map(D.hex → subaddress index); without it, only the main address is recognized.
 * ss: shared secret already computed (batch scanning), optional.
 * Returns null if it is not ours; otherwise { v, x, k, ss, index, p? } (index = the subaddress
 * that received; p only with raw keys that include b — the wallet spends with keys.spender(k, index)).
 */
export function scanShieldedOutput(keys, R, i, out, ss = null) {
  ss ??= keys.vault ? keys.vault.shared(R) : sharedSecret(keys.a, R);
  if (viewTag(ss, i) !== out.viewTag) return null;
  const k = outputScalar(ss, i);
  const D = out.P.sub(mulG(k));
  let index = 0;
  if (keys.table) {
    index = keys.table.get(D.hex());
    if (index === undefined) return null;
  } else if (!D.equals(keys.B)) return null;
  const v = decryptAmount(out.encAmount, ss, i);
  let x = blindingFactor(ss, i);
  if (!commit(v, x).equals(out.C)) {
    if (mulH(v).equals(out.C)) x = 0n; // coinbase output
    else return null; // commitment does not match: corrupted amount
  }
  const res = { v, x, k, ss, index };
  if (keys.b !== undefined) res.p = modN(k + keys.b + (keys.sub ? keys.sub(index) : subaddressScalar(keys.a, index)));
  return res;
}

// ------------------------------------------------------------------ memos
// Memo encrypted in the transaction's `payload` field: AES-256-GCM with a key derived from the
// shared secret of the recipient's output. Only someone with the recipient's view key (or the
// sender) can read it.
//
// FIXED size (1 + 128 + 16 bytes): every transaction with a private output carries a memo block
// — empty when the user writes nothing —, so whoever watches the network learns neither
// WHETHER there is a message nor its length.

export const MEMO_VERSION = 0x01;
export const MEMO_MAX_BYTES = 127;
const MEMO_PLAIN = 128;
export const MEMO_BLOCK_SIZE = 1 + MEMO_PLAIN + 16;
const memoKey = (ss, j) => H('memo/key', ss, j);
const ZERO_IV = Buffer.alloc(12); // the key is unique per (R, recipient, j): there is never nonce reuse

export function encryptMemo(text, ss, j) {
  const msg = Buffer.from(text ?? '', 'utf8');
  if (msg.length > MEMO_MAX_BYTES) throw new Error(`memo too long (${msg.length} bytes; maximum ${MEMO_MAX_BYTES})`);
  const plain = Buffer.alloc(MEMO_PLAIN);
  plain[0] = msg.length;
  msg.copy(plain, 1);
  const c = createCipheriv('aes-256-gcm', memoKey(ss, j), ZERO_IV);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([Buffer.from([MEMO_VERSION]), ct, c.getAuthTag()]);
}

/** Returns the text (possibly empty) or null if the block is not for this output. */
export function decryptMemo(payload, ss, j) {
  if (!payload || payload.length !== MEMO_BLOCK_SIZE || payload[0] !== MEMO_VERSION) return null;
  try {
    const d = createDecipheriv('aes-256-gcm', memoKey(ss, j), ZERO_IV);
    d.setAuthTag(payload.subarray(1 + MEMO_PLAIN));
    const plain = Buffer.concat([d.update(payload.subarray(1, 1 + MEMO_PLAIN)), d.final()]);
    if (plain[0] > MEMO_MAX_BYTES) return null;
    return plain.subarray(1, 1 + plain[0]).toString('utf8');
  } catch {
    return null;
  }
}
