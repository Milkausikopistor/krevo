// Schnorr signatures ((e, s) form, 64 bytes) over secp256k1.
//   sign:    k = H(x, P, m, random) ("hedged"); R = kG; e = H(R, P, m); s = k + e·x
//            — in the Rust core (constant time) when available; the signature is always
//            checked before it leaves (a hardware fault halfway through could leak x)
//   verify:  R' = sG − eP; accept if H(R', P, m) == e
// Used for transparent inputs and for the "balance signature" (binding signature).

import { randomBytes } from 'node:crypto';
import { G, N, mulG, modN, multiexp, hashToScalar, scalarToBytes, scalarFromBytes } from './secp256k1.js';
import * as core from './wasm.js';

export function schnorrSign(x, msg, domain = 'sig') {
  x = modN(x);
  if (x === 0n) throw new Error('zero secret key');
  if (core.available()) return core.schnorrSign(x, msg, domain);
  const P = mulG(x);
  for (;;) {
    const k = hashToScalar('schnorr/nonce', scalarToBytes(x), P, msg, randomBytes(32));
    if (k === 0n) continue;
    const R = mulG(k);
    const e = hashToScalar('schnorr/' + domain, R, P, msg);
    if (e === 0n) continue;
    const s = modN(k + e * x);
    const sig = Buffer.concat([scalarToBytes(e), scalarToBytes(s)]);
    if (!schnorrVerify(P, msg, sig, domain)) throw new Error('signing failed (self-verification)');
    return sig;
  }
}

export function schnorrVerify(P, msg, sig, domain = 'sig') {
  if (!Buffer.isBuffer(sig) || sig.length !== 64 || P.isInf()) return false;
  let e, s;
  try { e = scalarFromBytes(sig.subarray(0, 32)); s = scalarFromBytes(sig.subarray(32)); } catch { return false; }
  if (e === 0n) return false;
  const R = multiexp([s, N - e], [G, P]);
  if (R.isInf()) return false;
  return hashToScalar('schnorr/' + domain, R, P, msg) === e;
}
