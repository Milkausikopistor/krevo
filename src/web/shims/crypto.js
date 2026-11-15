// "node:crypto" for the browser (mapped by the import map in src/web/index.html).
// Only what the wallet uses; everything else says clearly that it does not exist in the browser.
import { Buffer } from './buffer.js';
import { blake2b, sha256, sha512, pbkdf2, hmac, aesGcmEncrypt as aesEncJs, aesGcmDecrypt as aesDecJs, randomFill } from '../../util/purecrypto.js';
import * as core from '../../crypto/wasm.js';

// AES-GCM in the Rust/WebAssembly core (bitsliced, constant-time AES); the JavaScript AES uses
// lookup tables (it leaks through the cache) and is only the fallback.
const aesGcmEncrypt = (k, iv, d) => (core.available() ? core.aesGcmEncrypt(k, iv, d) : aesEncJs(k, iv, d));
const aesGcmDecrypt = (k, iv, d, t) => (core.available() ? core.aesGcmDecrypt(k, iv, d, t) : aesDecJs(k, iv, d, t));

const HASHES = { blake2b512: (d) => blake2b(d, 64), sha256, sha512 };
const toBytes = (d, encoding) => (typeof d === 'string' ? Buffer.from(d, encoding ?? 'utf8') : d);

class Hash {
  constructor(alg) {
    if (!HASHES[alg]) throw new Error(`hash "${alg}" is not available in the browser`);
    this.fn = HASHES[alg];
    this.parts = [];
  }
  update(d, encoding) { this.parts.push(toBytes(d, encoding)); return this; }
  digest(encoding) {
    const out = Buffer.from(this.fn(Buffer.concat(this.parts)));
    return encoding ? out.toString(encoding) : out;
  }
}
export const createHash = (alg) => new Hash(alg);

class Hmac {
  constructor(alg, key) { this.alg = alg; this.key = toBytes(key); this.parts = []; }
  update(d, encoding) { this.parts.push(toBytes(d, encoding)); return this; }
  digest(encoding) { const out = Buffer.from(hmac(this.alg, this.key, Buffer.concat(this.parts))); return encoding ? out.toString(encoding) : out; }
}
export const createHmac = (alg, key) => new Hmac(alg, key);

export function pbkdf2Sync(password, salt, iterations, keyLen, digest) {
  return Buffer.from(pbkdf2(digest, toBytes(password), toBytes(salt), iterations, keyLen));
}

export function randomBytes(n) { return Buffer.from(randomFill(n)); }
export function randomInt(min, max) {
  if (max === undefined) { max = min; min = 0; }
  const range = max - min;
  if (!(range > 0) || range > 2 ** 48) throw new RangeError('randomInt: invalid range');
  const limit = Math.floor(2 ** 48 / range) * range;
  for (;;) {
    const b = randomFill(6);
    const v = b[0] * 2 ** 40 + b[1] * 2 ** 32 + b[2] * 2 ** 24 + b[3] * 2 ** 16 + b[4] * 2 ** 8 + b[5];
    if (v < limit) return min + (v % range);
  }
}

// AES-256-GCM in Node's style: everything is processed in final()
class Gcm {
  constructor(mode, alg, key, iv) {
    if (alg !== 'aes-256-gcm') throw new Error(`cipher "${alg}" is not available in the browser`);
    this.mode = mode; this.key = key; this.iv = iv; this.parts = []; this.tag = null;
  }
  update(d) { this.parts.push(toBytes(d)); return Buffer.alloc(0); }
  setAuthTag(t) { this.tag = t; return this; }
  setAAD() { throw new Error('AAD is not supported'); }
  final() {
    const data = Buffer.concat(this.parts);
    if (this.mode === 'enc') {
      const { ct, tag } = aesGcmEncrypt(this.key, this.iv, data);
      this.tag = Buffer.from(tag);
      return Buffer.from(ct);
    }
    return Buffer.from(aesGcmDecrypt(this.key, this.iv, data, this.tag ?? new Uint8Array(0)));
  }
  getAuthTag() { return this.tag; }
}
export const createCipheriv = (alg, key, iv) => new Gcm('enc', alg, key, iv);
export const createDecipheriv = (alg, key, iv) => new Gcm('dec', alg, key, iv);

const unavailable = (what) => () => { throw new Error(`${what} is not available in the browser`); };
export const scryptSync = unavailable('scrypt (wallet file encryption)');
export const generateKeyPairSync = unavailable('ML-DSA (quantum-safe addresses)');
export const createPrivateKey = unavailable('ML-DSA (quantum-safe addresses)');
export const createPublicKey = unavailable('ML-DSA (quantum-safe addresses)');
export const sign = unavailable('ML-DSA (quantum-safe addresses)');
export const verify = unavailable('ML-DSA (quantum-safe addresses)');

export default {
  createHash, createHmac, pbkdf2Sync, randomBytes, randomInt, createCipheriv, createDecipheriv,
  scryptSync, generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify,
};
