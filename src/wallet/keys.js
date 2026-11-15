// Wallet keys — all kept in the VAULT (src/crypto/vault.js), derived from the seed:
//   transparent i:  x_i = Hs("wallet/t", seed, i)
//   private:        b = Hs("wallet/spend", seed), a = Hs("wallet/view", seed)
//   subaddress i:   D_i = B + Hs("subaddr", a, i)·G,  C_i = a·D_i   (i = 0 → main address)
//   quantum-safe i: x_i = Hs("wallet/q", seed, i) (Schnorr) + ML-DSA seed = H("wallet/mldsa", seed, i)
//                   — both keys come from the same 24-word phrase
// This object only keeps PUBLIC data and "signers": whoever needs to sign gets an object that
// signs, never the key.
import { randomBytes } from 'node:crypto';
import { openVault } from '../crypto/vault.js';
import { pqLock } from '../consensus/pqlock.js';
import { transparentData, shieldedData, encodeAddress, encodeViewKey } from '../address.js';

export class Keys {
  /** seed: 32 bytes. The wallet wipes its own copy afterwards (the vault keeps its own). */
  constructor(seed) {
    if (!(seed instanceof Uint8Array) || seed.length !== 32) throw new Error('the seed must have 32 bytes');
    this.vault = openVault(seed);
    this._t = new Map();
    this._sub = new Map();
    this._q = new Map();
    this.B = this.vault.spendPub();
    const main = this.subaddress(0);
    this.A = main.C;                  // main address = (a·B, B)
    this.shieldedData = main.data;
  }
  static random() { const s = randomBytes(32); try { return new Keys(s); } finally { s.fill(0); } }
  /** Wipes the keys from the vault (the wallet can no longer sign). */
  close() { this.vault.close(); }

  /** Transparent key i: { index, P, lock, signer }. */
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
   * Quantum-safe key i (krq1… address): Schnorr pair + ML-DSA-44 pair, both in the vault.
   * { index, P, sPub (33), mldsa: { pub (1,312), sign(msg) }, lock, signer }
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

  /** Subaddress i: { index, C, D, data }. */
  subaddress(i) {
    let s = this._sub.get(i);
    if (!s) {
      const { C, D } = this.vault.subaddress(i);
      s = { index: i, C, D, data: shieldedData(C, D) };
      this._sub.set(i, s);
    }
    return s;
  }

  /** Who spends the private output with scalar k (from scanning) received on subaddress sub. */
  spender(k, sub = 0) { return this.vault.spender(k, sub); }
  /** Signer of the multisig key (recoverable from the phrase). */
  multisigSigner() { return this.vault.signer({ ms: 1 }); }

  tAddress(params, i = 0) { return encodeAddress(params, this.tKey(i).lock); }
  qAddress(params, i = 0) { return encodeAddress(params, this.qKey(i).lock); }
  sAddress(params, i = 0) { return encodeAddress(params, this.subaddress(i).data); }
  /** Exports the view key (explicit request: whoever has it sees incoming funds, but cannot spend). */
  viewKey(params) { const { a, B } = this.vault.exportViewKey(); return encodeViewKey(params, a, B); }

  /** Scan keys covering subaddresses 0..count-1 (the secret a·R is computed in the vault). */
  scanKeysFor(count) {
    const table = new Map();
    for (let i = 0; i < count; i++) table.set(this.subaddress(i).D.hex(), i);
    return { vault: this.vault, B: this.B, table };
  }
  get scanKeys() { return this.scanKeysFor(1); }
}
