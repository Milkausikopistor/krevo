// Proof-of-reserves DLEQ: proves that log_G(P) = log_Hp(P)(I) — the key image I belongs to the
// output P — without revealing the key. Used by src/wallet/reserves.js and by the vault (src/crypto/vault.js).
import { mulG, modN, hashToScalar, hedgedScalar, scalarToBytes } from './secp256k1.js';
import { hashPointForKeyImage } from './clsag.js';

export function dleqProve(p, P, I, ctx) {
  const Hp = hashPointForKeyImage(P);
  const k = hedgedScalar('reserves/nonce', scalarToBytes(p), ctx, P, I);
  const c = hashToScalar('reserves/dleq', ctx, P, I, mulG(k), Hp.mul(k));
  const proof = { c, s: modN(k - c * p) };
  if (!dleqVerify(P, I, ctx, proof)) throw new Error('failed to create the proof of reserves (verification)');
  return proof;
}

export function dleqVerify(P, I, ctx, { c, s }) {
  const Hp = hashPointForKeyImage(P);
  const A = mulG(s).add(P.mul(c)), B = Hp.mul(s).add(I.mul(c));
  return hashToScalar('reserves/dleq', ctx, P, I, A, B) === c;
}
