// Endereço transparente resistente a computadores quânticos (regra de consenso).
//
// Híbrido Schnorr (secp256k1) + ML-DSA-44 (FIPS 204): gastar exige AS DUAS assinaturas.
//   • Se um computador quântico quebrar secp256k1, o ML-DSA continua protegendo.
//   • Se surgir uma falha na criptografia de reticulados (mais nova), o Schnorr continua.
// O endereço guarda só o HASH das duas chaves públicas, então nada útil fica exposto
// enquanto o dinheiro está parado:
//
//   trava:       [0x04][H("lock/pq", chave Schnorr (33) ‖ chave ML-DSA (1.312))]   — 33 bytes
//   testemunha:  [0xF1] ‖ chave Schnorr ‖ chave ML-DSA ‖ assinatura Schnorr (64) ‖ assinatura ML-DSA (2.420)

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
  if (w.length !== PQ_WITNESS_SIZE) throw new Error('testemunha quântica com tamanho inválido');
  return w;
}

/** Regra de consenso: as duas chaves batem com o endereço e as DUAS assinaturas são válidas. */
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
