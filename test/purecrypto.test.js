// A criptografia em JS puro (para o navegador) conferida contra o OpenSSL do Node.js:
// milhares de entradas aleatórias, incluindo os tamanhos que cruzam fronteiras de bloco.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import nodeCrypto from 'node:crypto';
import { blake2b, sha256, sha512, hmac, pbkdf2, aesGcmEncrypt, aesGcmDecrypt } from '../src/util/purecrypto.js';
import { Buffer as WebBuffer } from '../src/web/shims/buffer.js';
import * as shim from '../src/web/shims/crypto.js';

const rnd = (n) => nodeCrypto.randomBytes(n);
const lengths = [0, 1, 2, 3, 31, 32, 33, 55, 56, 57, 63, 64, 65, 111, 112, 113, 127, 128, 129, 200, 255, 256, 257, 1000, 4097];
const hex = (b) => Buffer.from(b).toString('hex');

test('BLAKE2b-512, SHA-256 e SHA-512: idênticos ao OpenSSL', () => {
  for (const n of [...lengths, ...Array.from({ length: 300 }, () => Math.floor(Math.random() * 600))]) {
    const d = rnd(n);
    assert.equal(hex(blake2b(d)), nodeCrypto.createHash('blake2b512').update(d).digest('hex'), `blake2b ${n}`);
    assert.equal(hex(sha256(d)), nodeCrypto.createHash('sha256').update(d).digest('hex'), `sha256 ${n}`);
    assert.equal(hex(sha512(d)), nodeCrypto.createHash('sha512').update(d).digest('hex'), `sha512 ${n}`);
  }
  // vetores clássicos
  assert.equal(hex(sha256(Buffer.from('abc'))), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.equal(hex(blake2b(Buffer.from('abc'))).slice(0, 32), 'ba80a53f981c4d0d6a2797b69f12f6e9');
});

test('HMAC e PBKDF2 (o da frase BIP-39): idênticos ao OpenSSL', () => {
  for (const alg of ['sha256', 'sha512']) {
    for (const kl of [0, 1, 32, 64, 127, 128, 129, 300]) {
      const key = rnd(kl), data = rnd(Math.floor(Math.random() * 300));
      assert.equal(hex(hmac(alg, key, data)), nodeCrypto.createHmac(alg, key).update(data).digest('hex'), `hmac ${alg} ${kl}`);
    }
  }
  for (const [it, len] of [[1, 64], [2, 64], [2048, 64], [5, 100], [3, 20]]) {
    const pw = rnd(20), salt = rnd(16);
    assert.equal(hex(pbkdf2('sha512', pw, salt, it, len)), hex(nodeCrypto.pbkdf2Sync(pw, salt, it, len, 'sha512')), `pbkdf2 ${it}/${len}`);
  }
});

test('AES-256-GCM (memos): idêntico ao OpenSSL; etiqueta adulterada é recusada', () => {
  for (const n of [0, 1, 15, 16, 17, 31, 32, 33, 128, 129, 145, 200]) {
    const key = rnd(32), iv = rnd(12), plain = rnd(n);
    const c = nodeCrypto.createCipheriv('aes-256-gcm', key, iv);
    const ct = Buffer.concat([c.update(plain), c.final()]), tag = c.getAuthTag();
    const mine = aesGcmEncrypt(key, iv, plain);
    assert.equal(hex(mine.ct), hex(ct), `ct ${n}`);
    assert.equal(hex(mine.tag), hex(tag), `tag ${n}`);
    assert.equal(hex(aesGcmDecrypt(key, iv, ct, tag)), hex(plain));
    const bad = Buffer.from(tag); bad[0] ^= 1;
    assert.throws(() => aesGcmDecrypt(key, iv, ct, bad), /authenticate/);
  }
  // pela interface no estilo do Node (como src/crypto/stealth.js usa)
  const key = rnd(32), iv = Buffer.alloc(12), plain = rnd(128);
  const e = shim.createCipheriv('aes-256-gcm', key, iv);
  const ct = WebBuffer.concat([e.update(plain), e.final()]);
  const d = nodeCrypto.createDecipheriv('aes-256-gcm', key, iv);
  d.setAuthTag(e.getAuthTag());
  assert.equal(hex(Buffer.concat([d.update(ct), d.final()])), hex(plain), 'o Node decifra o que o navegador cifrou');
});

test('Buffer do navegador: mesmos resultados que o Buffer do Node', () => {
  const samples = ['', 'abc', 'pão de queijo ☕', 'Krevo\u0000ÿ', '0123456789abcdef'];
  for (const s of samples) {
    for (const enc of ['utf8', 'ascii', 'latin1', 'hex', 'base64']) {
      const input = enc === 'hex' ? Buffer.from(s).toString('hex') : enc === 'base64' ? Buffer.from(s).toString('base64') : s;
      assert.equal(hex(WebBuffer.from(input, enc)), hex(Buffer.from(input, enc)), `from ${enc} ${JSON.stringify(s)}`);
      const b = Buffer.from(s);
      assert.equal(WebBuffer.from(b).toString(enc), b.toString(enc), `toString ${enc}`);
    }
  }
  assert.equal(hex(WebBuffer.from('abzz', 'hex')), hex(Buffer.from('abzz', 'hex')), 'hex inválido para no mesmo ponto');
  const a = rnd(40), b = rnd(40);
  assert.equal(hex(WebBuffer.concat([WebBuffer.from(a), WebBuffer.from(b)], 50)), hex(Buffer.concat([a, b], 50)));
  assert.equal(WebBuffer.compare(WebBuffer.from(a), WebBuffer.from(b)), Buffer.compare(a, b));
  const w = WebBuffer.alloc(16, 7), n = Buffer.alloc(16, 7);
  w.writeUInt32LE(0xdeadbeef, 0); n.writeUInt32LE(0xdeadbeef, 0);
  w.writeBigUInt64LE(123456789012345678n, 4); n.writeBigUInt64LE(123456789012345678n, 4);
  w.writeUInt16LE(513, 12); n.writeUInt16LE(513, 12);
  assert.equal(hex(w), hex(n));
  assert.equal(w.readBigUInt64LE(4), n.readBigUInt64LE(4));
  assert.equal(w.readUInt32LE(0), n.readUInt32LE(0));
  assert.equal(w.readUInt16LE(12), n.readUInt16LE(12));
  const view = w.subarray(2, 6); view[0] = 99;
  assert.equal(w[2], 99, 'subarray é uma visão');
  assert.ok(view instanceof WebBuffer && WebBuffer.isBuffer(view));
  const tgt = WebBuffer.alloc(8); WebBuffer.from(a).copy(tgt, 2, 0, 4);
  const tgtN = Buffer.alloc(8); a.copy(tgtN, 2, 0, 4);
  assert.equal(hex(tgt), hex(tgtN));
  assert.ok(WebBuffer.from(a).equals(WebBuffer.from(a)) && !WebBuffer.from(a).equals(WebBuffer.from(b)));
  assert.equal(hex(WebBuffer.from(a).reverse()), hex(Buffer.from(a).reverse()));
  assert.equal(WebBuffer.byteLength('pão'), Buffer.byteLength('pão'));
  // a interface de hash do "node:crypto" do navegador
  assert.equal(shim.createHash('blake2b512').update('KRV').update(a).digest('hex'), nodeCrypto.createHash('blake2b512').update('KRV').update(a).digest('hex'));
  assert.ok(shim.randomInt(10) >= 0 && shim.randomInt(10) < 10);
  assert.equal(shim.randomBytes(33).length, 33);
});
