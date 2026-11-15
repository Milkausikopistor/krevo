// Proof of payment: "output j of transaction T paid V KRV to the private address (C, D)".
//
// The payer knows the output's secret r (R = r·D is published in the output itself).
// The proof reveals only S = r·C — the shared secret of THAT output with THAT recipient —
// and a proof of equality of discrete logarithms (Chaum–Pedersen / DLEQ) that
// log_D(R) = log_C(S). Thus:
//   • r stays secret and no other output of the transaction (such as the change) is exposed;
//   • no key of the payer's or the recipient's wallet is revealed;
//   • with S, anyone recomputes the recipient's output, the amount and the memo;
//   • the proof is bound to the txid, the output and an optional message (e.g. "order 123"),
//     and cannot be reused for another address or message without knowing r.

import { modN, randomScalar, hedgedScalar, hashToScalar, scalarToBytes, scalarFromBytes, Point, multiexp, mulG } from '../crypto/secp256k1.js';
import { encode, decode } from '../util/bech32m.js';
import { outputScalar, decryptAmount, blindingFactor, decryptMemo, viewTag } from '../crypto/stealth.js';
import { commit } from '../crypto/pedersen.js';
import { decodeAddress } from '../address.js';

const VERSION = 0x02;

const challenge = (txid, j, R, D, C, S, T1, T2, message) =>
  hashToScalar('proof/payment', txid, j, R, D, C, S, T1, T2, Buffer.from(message ?? '', 'utf8'));

/** Creates the proof. txid: Buffer(32); r: secret of output j; address: the recipient's private address. */
export function createPaymentProof(params, { txid, r, j = 0, address, message = '' }) {
  const addr = decodeAddress(params, address);
  if (addr.type !== 's') throw new Error('payment proofs are for private addresses (transparent payments are already public)');
  const D = addr.B, C = addr.A;
  const R = D.mul(r), S = C.mul(r);
  for (;;) {
    const k = hedgedScalar('proof/nonce', scalarToBytes(r), txid, j, D, C, Buffer.from(message ?? '', 'utf8'));
    const c = challenge(txid, j, R, D, C, S, D.mul(k), C.mul(k), message);
    if (c === 0n) continue;
    const s = modN(k - c * r);
    // check before returning (D·s + R·c = D·k and C·s + S·c = C·k)
    if (challenge(txid, j, R, D, C, S, D.mul(s).add(R.mul(c)), C.mul(s).add(S.mul(c)), message) !== c) throw new Error('failed to create the proof (verification)');
    return encode(params.hrp.p, Buffer.concat([Buffer.from([VERSION]), txid, Buffer.from([j]), S.toBytes(), scalarToBytes(c), scalarToBytes(s)]));
  }
}

export function decodePaymentProof(params, str) {
  const { hrp, bytes } = decode(str.trim());
  if (hrp !== params.hrp.p) throw new Error(`proof from another network or format (prefix ${hrp}, expected ${params.hrp.p})`);
  if (bytes.length !== 1 + 32 + 1 + 33 + 64 || bytes[0] !== VERSION) throw new Error('malformed proof');
  return {
    txid: bytes.subarray(1, 33),
    j: bytes[33],
    S: Point.fromBytes(bytes.subarray(34, 67)),
    c: scalarFromBytes(bytes.subarray(67, 99)),
    s: scalarFromBytes(bytes.subarray(99, 131)),
  };
}

/**
 * Verifies against the transaction (obtained from a node). Returns
 * { valid, reason?, outputs:[{j, amount}], total, memo }.
 */
export function verifyPaymentProof(params, { proof, address, tx, message = '' }) {
  const no = (reason) => ({ valid: false, reason, outputs: [], total: 0n, memo: null });
  let p, addr;
  try { p = decodePaymentProof(params, proof); } catch (e) { return no(e.message); }
  try { addr = decodeAddress(params, address); } catch (e) { return no(e.message); }
  if (addr.type !== 's') return no('the address must be private (krs1…)');
  if (!p.txid.equals(tx.id)) return no('the proof is for another transaction');
  const o = tx.sOut[p.j];
  if (!o) return no('the transaction does not have that private output');
  const D = addr.B, C = addr.A, R = Point.fromBytes(o.R);
  const T1 = multiexp([p.s, p.c], [D, R]);
  const T2 = multiexp([p.s, p.c], [C, p.S]);
  if (challenge(tx.id, p.j, R, D, C, p.S, T1, T2, message) !== p.c) {
    return no('the proof\'s signature does not check out (tampered proof, wrong address or different message)');
  }
  const ss = p.S.toBytes(), j = p.j;
  if (viewTag(ss, j) !== o.viewTag || !mulG(outputScalar(ss, j)).add(D).equals(Point.fromBytes(o.P))) {
    return no('the output was not paid to this address');
  }
  const amount = decryptAmount(o.encAmount, ss, j);
  if (!commit(amount, blindingFactor(ss, j)).equals(Point.fromBytes(o.C))) return no('the amount does not match the commitment');
  const memo = j === 0 ? decryptMemo(tx.payload, ss, 0) : null;
  return { valid: true, outputs: [{ j, amount }], total: amount, memo: memo || null };
}
