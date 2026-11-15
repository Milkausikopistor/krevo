// Post-quantum ML-DSA-44 signatures (NIST FIPS 204, "Dilithium"), security level 2.
//
// In Node.js we use the built-in OpenSSL 3.5+ implementation; where it does not exist (browser,
// older Node), the Rust/WebAssembly core's (ml-dsa crate, src/crypto/wasm.js) — both derive the
// SAME key from the seed and accept each other's signatures (tested). The key is derived
// deterministically from a 32-byte seed (the "seed-only" PKCS#8 format of draft-ietf-lamps-dilithium-
// certificates), so it can also be recovered from the 24-word phrase.
//
//   public key: 1,312 bytes · signature: 2,420 bytes · verification: ~0.1 ms
//
// Security: lattice-based (Module-LWE/SIS), resistant to Shor's algorithm.

import crypto from 'node:crypto';
import * as core from './wasm.js';

export const MLDSA_ALG = 'ml-dsa-44';
export const MLDSA_PUB_SIZE = 1312;
export const MLDSA_SIG_SIZE = 2420;
// Fixed DER of the ML-DSA-44 algorithm (OID 2.16.840.1.101.3.4.3.17)
const SPKI_PREFIX = Buffer.from('30820532300b06096086480165030403110382052100', 'hex');
const PKCS8_SEED_PREFIX = Buffer.from('3034020100300b060960864801650304031104228020', 'hex');

let openssl = null;
function opensslPq() {
  if (openssl === null) {
    try { crypto.generateKeyPairSync(MLDSA_ALG); openssl = true; } catch { openssl = false; }
  }
  return openssl;
}
export function pqAvailable() { return opensslPq() || core.available(); }
function requirePq() {
  if (!pqAvailable()) throw new Error('ML-DSA unavailable (requires Node 24.7+ with OpenSSL 3.5+, or the WebAssembly core): cannot validate quantum-safe addresses');
}

/** Deterministic key pair from a 32-byte seed. */
export function mldsaKeyFromSeed(seed) {
  requirePq();
  if (!Buffer.isBuffer(seed) || seed.length !== 32) throw new Error('the ML-DSA seed must have 32 bytes');
  if (!opensslPq()) return { priv: { seed: Buffer.from(seed) }, pub: core.mldsaPub(seed) };
  const priv = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_SEED_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  const spki = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' });
  if (!spki.subarray(0, SPKI_PREFIX.length).equals(SPKI_PREFIX) || spki.length !== SPKI_PREFIX.length + MLDSA_PUB_SIZE) {
    throw new Error('unexpected ML-DSA key format');
  }
  return { priv, pub: Buffer.from(spki.subarray(SPKI_PREFIX.length)) };
}

export function mldsaSign(priv, msg) {
  if (priv?.seed) return core.mldsaSign(priv.seed, msg);
  return crypto.sign(null, msg, priv);
}

const pubCache = new Map();
export function mldsaVerify(pub, msg, sig) {
  requirePq();
  if (!Buffer.isBuffer(pub) || pub.length !== MLDSA_PUB_SIZE || !Buffer.isBuffer(sig) || sig.length !== MLDSA_SIG_SIZE) return false;
  if (!opensslPq()) { try { return core.mldsaVerify(pub, msg, sig); } catch { return false; } }
  const k = pub.toString('hex');
  let key = pubCache.get(k);
  try {
    if (!key) {
      key = crypto.createPublicKey({ key: Buffer.concat([SPKI_PREFIX, pub]), format: 'der', type: 'spki' });
      if (pubCache.size > 10_000) pubCache.clear();
      pubCache.set(k, key);
    }
    return crypto.verify(null, msg, key, sig);
  } catch {
    return false;
  }
}
