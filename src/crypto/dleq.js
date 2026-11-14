// DLEQ da prova de reservas: prova que log_G(P) = log_Hp(P)(I) — a imagem de chave I é a da
// saída P — sem revelar a chave. Usada por src/wallet/reserves.js e pelo cofre (src/crypto/vault.js).
import { mulG, modN, hashToScalar, hedgedScalar, scalarToBytes } from './secp256k1.js';
import { hashPointForKeyImage } from './clsag.js';

export function dleqProve(p, P, I, ctx) {
  const Hp = hashPointForKeyImage(P);
  const k = hedgedScalar('reserves/nonce', scalarToBytes(p), ctx, P, I);
  const c = hashToScalar('reserves/dleq', ctx, P, I, mulG(k), Hp.mul(k));
  const proof = { c, s: modN(k - c * p) };
  if (!dleqVerify(P, I, ctx, proof)) throw new Error('falha ao criar a prova de reservas (verificação)');
  return proof;
}

export function dleqVerify(P, I, ctx, { c, s }) {
  const Hp = hashPointForKeyImage(P);
  const A = mulG(s).add(P.mul(c)), B = Hp.mul(s).add(I.mul(c));
  return hashToScalar('reserves/dleq', ctx, P, I, A, B) === c;
}
