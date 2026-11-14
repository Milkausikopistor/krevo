// MuHash3072 — hash de multiconjunto incremental (Bellare–Micciancio).
// Compromisso do estado UTXO completo em cada cabeçalho de bloco: adicionar ou
// remover um elemento custa uma multiplicação modular, e a ordem não importa.
// Permite sincronizar um nó novo a partir de um "instantâneo" do estado,
// verificando-o contra o cabeçalho — sem baixar todo o histórico.

import { shake256, H } from './hash.js';
import { bytesToBigLE, bigToBytesLE } from '../util/bytes.js';

const MP = (1n << 3072n) - 1103717n;

function invMod(a, m) {
  let r0 = a % m, r1 = m, s0 = 1n, s1 = 0n;
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  s0 %= m; return s0 < 0n ? s0 + m : s0;
}

function elementNum(data) {
  const v = bytesToBigLE(shake256(Buffer.concat([Buffer.from('KRV/muhash'), data]), 384)) % MP;
  return v === 0n ? 1n : v;
}

export class MuHash {
  constructor(num = 1n, den = 1n) { this.num = num; this.den = den; }
  clone() { return new MuHash(this.num, this.den); }
  add(data) { this.num = (this.num * elementNum(data)) % MP; return this; }
  remove(data) { this.den = (this.den * elementNum(data)) % MP; return this; }
  normalize() {
    if (this.den !== 1n) { this.num = (this.num * invMod(this.den, MP)) % MP; this.den = 1n; }
    return this;
  }
  digest() {
    this.normalize();
    return H('muhash/final', bigToBytesLE(this.num, 384));
  }
}
