// Assinatura pós-quântica ML-DSA-44 (NIST FIPS 204, "Dilithium"), nível de segurança 2.
//
// No Node.js usamos a implementação do OpenSSL 3.5+ embutida; onde ela não existe (navegador,
// Node antigo), a do núcleo em Rust/WebAssembly (crate ml-dsa, src/crypto/wasm.js) — as duas
// geram a MESMA chave a partir da semente e aceitam as assinaturas uma da outra (testado). A chave é derivada de forma determinística de uma
// semente de 32 bytes (formato PKCS#8 "só semente" do draft-ietf-lamps-dilithium-
// certificates), então ela também é recuperável pela frase de 24 palavras.
//
//   chave pública: 1.312 bytes · assinatura: 2.420 bytes · verificação: ~0,1 ms
//
// Segurança: baseada em reticulados (Module-LWE/SIS), resistente ao algoritmo de Shor.

import crypto from 'node:crypto';
import * as core from './wasm.js';

export const MLDSA_ALG = 'ml-dsa-44';
export const MLDSA_PUB_SIZE = 1312;
export const MLDSA_SIG_SIZE = 2420;
// DER fixo do algoritmo ML-DSA-44 (OID 2.16.840.1.101.3.4.3.17)
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
  if (!pqAvailable()) throw new Error('ML-DSA indisponível (requer Node 24.7+ com OpenSSL 3.5+, ou o núcleo WebAssembly): impossível validar endereços quânticos');
}

/** Par de chaves determinístico a partir de uma semente de 32 bytes. */
export function mldsaKeyFromSeed(seed) {
  requirePq();
  if (!Buffer.isBuffer(seed) || seed.length !== 32) throw new Error('semente ML-DSA precisa de 32 bytes');
  if (!opensslPq()) return { priv: { seed: Buffer.from(seed) }, pub: core.mldsaPub(seed) };
  const priv = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_SEED_PREFIX, seed]), format: 'der', type: 'pkcs8' });
  const spki = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' });
  if (!spki.subarray(0, SPKI_PREFIX.length).equals(SPKI_PREFIX) || spki.length !== SPKI_PREFIX.length + MLDSA_PUB_SIZE) {
    throw new Error('formato inesperado da chave ML-DSA');
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
