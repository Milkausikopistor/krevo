// Transparent address resistant to quantum computers (consensus rule).
//
// Hybrid Schnorr (secp256k1) + ML-DSA-44 (FIPS 204): spending requires BOTH signatures.
//   • If a quantum computer breaks secp256k1, ML-DSA still protects.
//   • If a flaw appears in lattice cryptography (newer), Schnorr still protects.
// The address stores only the HASH of both public keys, so nothing useful is exposed
// while the money sits still:
//
//   lock:     [0x04][H("lock/pq", Schnorr key (33) ‖ ML-DSA key (1,312))]   — 33 bytes
//   witness:  [0xF1] ‖ Schnorr key ‖ ML-DSA key ‖ Schnorr signature (64) ‖ ML-DSA signature (2,420)

import { H } from '../crypto/hash.js';
import { Point } from '../crypto/secp256k1.js';
import { schnorrVerify } from '../crypto/schnorr.js';
import { mldsaVerify, MLDSA_PUB_SIZE, MLDSA_SIG_SIZE } from '../crypto/pq.js';

export const LOCK_PQ = 0x04;
export const PQ_WITNESS_VERSION = 0xf1;
export const PQ_WITNESS_SIZE = 1 + 33 + MLDSA_PUB_SIZE + 64 + MLDSA_SIG_SIZE; // 3.830 bytes

export const pqLockHash = (schnorrPub, mldsaPub) => H('lock/pq', schnorrPub, mldsaPub);
export const pqLock = (schnorrPub, mldsaPub) => Buffer.concat([Buffer.from([LOCK_PQ]), pqLockHash(schnorrPub, mldsaPub)]);
export const isPqWitness = (w) => w.length === PQ_WITNESS_SIZE && w[0] === PQ_WITNESS_VERSION;

export function encodePqWitness(schnorrPub, mldsaPub, schnorrSig, mldsaSig) {
  const w = Buffer.concat([Buffer.from([PQ_WITNESS_VERSION]), schnorrPub, mldsaPub, schnorrSig, mldsaSig]);
  if (w.length !== PQ_WITNESS_SIZE) throw new Error('quantum-safe witness with invalid size');
  return w;
}

/** Consensus rule: both keys match the address and BOTH signatures are valid. */
export function verifyPqWitness(lock, witness, msg) {
  if (lock.length !== 33 || lock[0] !== LOCK_PQ || !isPqWitness(witness)) return false;
  let o = 1;
  const sPub = witness.subarray(o, (o += 33));
  const qPub = witness.subarray(o, (o += MLDSA_PUB_SIZE));
  const sSig = witness.subarray(o, (o += 64));
  const qSig = witness.subarray(o, (o += MLDSA_SIG_SIZE));
  if (!pqLockHash(sPub, qPub).equals(lock.subarray(1))) return false;
  let P;
  try { P = Point.fromBytes(sPub); } catch { return false; }
  return schnorrVerify(P, msg, Buffer.from(sSig)) && mldsaVerify(Buffer.from(qPub), msg, Buffer.from(qSig));
}
