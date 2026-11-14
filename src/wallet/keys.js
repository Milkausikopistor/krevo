// Chaves da carteira — todas guardadas no COFRE (src/crypto/vault.js), derivadas da semente:
//   transparente i:  x_i = Hs("wallet/t", semente, i)
//   privada:         b = Hs("wallet/spend", semente), a = Hs("wallet/view", semente)
//   subendereço i:   D_i = B + Hs("subaddr", a, i)·G,  C_i = a·D_i   (i = 0 → endereço principal)
//   quântico i:      x_i = Hs("wallet/q", semente, i) (Schnorr) + semente ML-DSA = H("wallet/mldsa", semente, i)
//                    — as duas chaves vêm da mesma frase de 24 palavras
// Este objeto só guarda dados PÚBLICOS e "assinadores": quem precisa assinar recebe um objeto que
// assina, nunca a chave.
import { randomBytes } from 'node:crypto';
import { openVault } from '../crypto/vault.js';
import { pqLock } from '../consensus/pqlock.js';
import { transparentData, shieldedData, encodeAddress, encodeViewKey } from '../address.js';

export class Keys {
  /** seed: 32 bytes. A carteira apaga a sua cópia depois (o cofre guarda a dele). */
  constructor(seed) {
    if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error('semente deve ter 32 bytes');
    this.vault = openVault(seed);
    this._t = new Map();
    this._sub = new Map();
    this._q = new Map();
    this.B = this.vault.spendPub();
    const main = this.subaddress(0);
    this.A = main.C;                  // endereço principal = (a·B, B)
    this.shieldedData = main.data;
  }
  static random() { const s = randomBytes(32); try { return new Keys(s); } finally { s.fill(0); } }
  /** Apaga as chaves do cofre (a carteira deixa de poder assinar). */
  close() { this.vault.close(); }

  /** Chave transparente i: { index, P, lock, signer }. */
  tKey(i) {
    let k = this._t.get(i);
    if (!k) {
      const signer = this.vault.signer({ t: i });
      const P = signer.P;
      k = { index: i, P, lock: transparentData(P), signer };
      this._t.set(i, k);
    }
    return k;
  }

  /**
   * Chave quântica i (endereço krq1…): par Schnorr + par ML-DSA-44, ambos no cofre.
   * { index, P, sPub (33), mldsa: { pub (1.312), sign(msg) }, lock, signer }
   */
  qKey(i) {
    let k = this._q.get(i);
    if (!k) {
      const signer = this.vault.signer({ q: i });
      const P = signer.P;
      const mldsa = { pub: this.vault.mldsaPub(i), sign: (msg) => this.vault.mldsaSign(i, msg) };
      k = { index: i, P, sPub: P.toBytes(), mldsa, lock: pqLock(P.toBytes(), mldsa.pub), signer };
      this._q.set(i, k);
    }
    return k;
  }

  /** Subendereço i: { index, C, D, data }. */
  subaddress(i) {
    let s = this._sub.get(i);
    if (!s) {
      const { C, D } = this.vault.subaddress(i);
      s = { index: i, C, D, data: shieldedData(C, D) };
      this._sub.set(i, s);
    }
    return s;
  }

  /** Quem gasta a saída privada de escalar k (da varredura) recebida no subendereço sub. */
  spender(k, sub = 0) { return this.vault.spender(k, sub); }
  /** Assinador da chave de multiassinatura (recuperável pela frase). */
  multisigSigner() { return this.vault.signer({ ms: 1 }); }

  tAddress(params, i = 0) { return encodeAddress(params, this.tKey(i).lock); }
  qAddress(params, i = 0) { return encodeAddress(params, this.qKey(i).lock); }
  sAddress(params, i = 0) { return encodeAddress(params, this.subaddress(i).data); }
  /** Exporta a chave de visualização (pedido explícito: quem a tem vê as entradas, mas não gasta). */
  viewKey(params) { const { a, B } = this.vault.exportViewKey(); return encodeViewKey(params, a, B); }

  /** Chaves de varredura cobrindo os subendereços 0..count-1 (o segredo a·R é calculado no cofre). */
  scanKeysFor(count) {
    const table = new Map();
    for (let i = 0; i < count; i++) table.set(this.subaddress(i).D.hex(), i);
    return { vault: this.vault, B: this.B, table };
  }
  get scanKeys() { return this.scanKeysFor(1); }
}
