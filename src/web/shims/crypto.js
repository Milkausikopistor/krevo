// "node:crypto" para o navegador (mapeado pelo import map de src/web/index.html).
// Só o que a carteira usa; o resto avisa claramente que não existe no navegador.
import { Buffer } from './buffer.js';
import { blake2b, sha256, sha512, pbkdf2, hmac, aesGcmEncrypt as aesEncJs, aesGcmDecrypt as aesDecJs, randomFill } from '../../util/purecrypto.js';
import * as core from '../../crypto/wasm.js';

// AES-GCM no núcleo em Rust/WebAssembly (AES "bitsliced", de tempo constante); o AES em JavaScript
// usa tabelas (vaza pelo cache) e fica só como plano B.
const aesGcmEncrypt = (k, iv, d) => (core.available() ? core.aesGcmEncrypt(k, iv, d) : aesEncJs(k, iv, d));
const aesGcmDecrypt = (k, iv, d, t) => (core.available() ? core.aesGcmDecrypt(k, iv, d, t) : aesDecJs(k, iv, d, t));

const HASHES = { blake2b512: (d) => blake2b(d, 64), sha256, sha512 };
const toBytes = (d, encoding) => (typeof d === 'string' ? Buffer.from(d, encoding ?? 'utf8') : d);

class Hash {
  constructor(alg) {
    if (!HASHES[alg]) throw new Error(`hash "${alg}" indisponível no navegador`);
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
  if (!(range > 0) || range > 2 ** 48) throw new RangeError('randomInt: intervalo inválido');
  const limit = Math.floor(2 ** 48 / range) * range;
  for (;;) {
    const b = randomFill(6);
    const v = b[0] * 2 ** 40 + b[1] * 2 ** 32 + b[2] * 2 ** 24 + b[3] * 2 ** 16 + b[4] * 2 ** 8 + b[5];
    if (v < limit) return min + (v % range);
  }
}

// AES-256-GCM no estilo do Node: tudo é processado em final()
class Gcm {
  constructor(mode, alg, key, iv) {
    if (alg !== 'aes-256-gcm') throw new Error(`cifra "${alg}" indisponível no navegador`);
    this.mode = mode; this.key = key; this.iv = iv; this.parts = []; this.tag = null;
  }
  update(d) { this.parts.push(toBytes(d)); return Buffer.alloc(0); }
  setAuthTag(t) { this.tag = t; return this; }
  setAAD() { throw new Error('AAD não suportado'); }
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

const unavailable = (what) => () => { throw new Error(`${what} não está disponível no navegador`); };
export const scryptSync = unavailable('scrypt (cifra do arquivo da carteira)');
export const generateKeyPairSync = unavailable('ML-DSA (endereços quânticos)');
export const createPrivateKey = unavailable('ML-DSA (endereços quânticos)');
export const createPublicKey = unavailable('ML-DSA (endereços quânticos)');
export const sign = unavailable('ML-DSA (endereços quânticos)');
export const verify = unavailable('ML-DSA (endereços quânticos)');

export default {
  createHash, createHmac, pbkdf2Sync, randomBytes, randomInt, createCipheriv, createDecipheriv,
  scryptSync, generateKeyPairSync, createPrivateKey, createPublicKey, sign, verify,
};
