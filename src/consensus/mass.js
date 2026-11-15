// "Mass" = resource cost of a transaction. Fee = mass × fee per gram.
//
// compute mass: bytes + cost of verifying signatures/proofs.
// storage mass (Kaspa's KIP-9): C · (Σ 1/output − |E|²/Σ input).
//   Creating many tiny outputs ("dust") becomes expensive; consolidating becomes cheap.
//   That is what keeps the UTXO set small — and node hardware affordable — even with
//   near-zero fees.
// final mass = max(compute, storage) and is declared in the transaction itself.

import { isPqWitness } from './pqlock.js';
import { parseWitnessPath } from './policy.js';
import { COMMIT_WITNESS, parseCommitWitness } from './names.js';

/** How many signature verifications a transparent witness requires (for the mass). */
function sigCount(w) {
  if (w.length === 64) return 1;                  // Schnorr simples
  if (isPqWitness(w)) return 2;                   // Schnorr + ML-DSA (verifying ML-DSA costs about the same)
  if (w[0] === COMMIT_WITNESS) {                  // name reveal: count the owner's witness
    const c = parseCommitWitness(w);
    if (c) return sigCount(c.inner);
  }
  const p = parseWitnessPath(w);                  // multiassinatura: M assinaturas
  return p ? p.p.m : Math.max(1, Math.floor(w.length / 65));
}

export function computeMass(tx, params) {
  let m = tx.size * params.massPerByte;
  // multisig: each witness carries M signatures (conservative count by size)
  for (const i of tx.tIn) m += sigCount(i.sig) * params.massPerSig;
  for (const si of tx.sIn) m += si.ring.length ? si.ring.length * params.massPerRingMember : params.massPerFcmpInput;
  m += tx.sOut.length * params.massPerShieldedOutput;
  return m;
}

/**
 * inputAmounts: amounts of the transparent inputs (private ones are hidden and count
 * as zero — conservative).
 */
export function storageMass(tx, inputAmounts, params) {
  const C = params.storageMassC;
  let harmonic = 0n;
  for (const o of tx.tOut) {
    if (o.amount <= 0n) return Number.MAX_SAFE_INTEGER;
    harmonic += C / o.amount;
  }
  let arith = 0n;
  const sumIn = inputAmounts.reduce((a, b) => a + b, 0n);
  if (sumIn > 0n) {
    const n = BigInt(inputAmounts.length);
    arith = (C * n * n) / sumIn;
  }
  let m = harmonic > arith ? harmonic - arith : 0n;
  m += BigInt(tx.sOut.length * params.shieldedStorageMass);
  return m > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(m);
}
