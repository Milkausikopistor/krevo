// Transações Bitcoin: serialização (com testemunha segwit, BIP-144), txid, peso/vbytes e o
// hash de assinatura segwit v0 (BIP-143).
//
// txid é exibido invertido (como em exploradores e no Bitcoin Core); na serialização o
// ponto de saída usa a ordem interna.

import { Writer, Reader } from '../util/bytes.js';
import { hash256 } from './address.js';

export const SIGHASH_ALL = 1;
const EMPTY = Buffer.alloc(0);

export class BtcTx {
  /**
   * inputs:  [{ txid (hex de exibição), vout, sequence, scriptSig?, witness?: Buffer[] }]
   * outputs: [{ value (BigInt, satoshis), script (scriptPubKey) }]
   */
  constructor({ version = 2, inputs = [], outputs = [], locktime = 0 } = {}) {
    this.version = version;
    this.inputs = inputs.map((i) => ({ sequence: 0xffffffff, scriptSig: EMPTY, witness: [], ...i }));
    this.outputs = outputs.map((o) => ({ ...o, value: BigInt(o.value) }));
    this.locktime = locktime;
  }

  hasWitness() { return this.inputs.some((i) => i.witness && i.witness.length); }

  serialize(withWitness = true) {
    const w = new Writer();
    w.u32(this.version);
    const seg = withWitness && this.hasWitness();
    if (seg) { w.u8(0); w.u8(1); }
    w.varint(this.inputs.length);
    for (const i of this.inputs) {
      w.bytes(Buffer.from(i.txid, 'hex').reverse(), 32);
      w.u32(i.vout);
      w.varbytes(i.scriptSig ?? EMPTY);
      w.u32(i.sequence);
    }
    w.varint(this.outputs.length);
    for (const o of this.outputs) { w.u64(o.value); w.varbytes(o.script); }
    if (seg) {
      for (const i of this.inputs) {
        w.varint(i.witness.length);
        for (const item of i.witness) w.varbytes(item);
      }
    }
    w.u32(this.locktime);
    return w.done();
  }

  toHex() { return this.serialize().toString('hex'); }
  get txid() { return Buffer.from(hash256(this.serialize(false))).reverse().toString('hex'); }
  get weight() { return this.serialize(false).length * 3 + this.serialize(true).length; }
  get vsize() { return Math.ceil(this.weight / 4); }

  static parse(hexOrBuf) {
    const r = new Reader(typeof hexOrBuf === 'string' ? Buffer.from(hexOrBuf, 'hex') : hexOrBuf);
    const version = r.u32();
    let seg = false;
    if (r.buf[r.pos] === 0 && r.buf[r.pos + 1] === 1) { r.pos += 2; seg = true; }
    const nIn = r.varint(100_000);
    const inputs = [];
    for (let k = 0; k < nIn; k++) {
      const txid = Buffer.from(r.bytes(32)).reverse().toString('hex');
      inputs.push({ txid, vout: r.u32(), scriptSig: r.varbytes(10_000), sequence: r.u32(), witness: [] });
    }
    const nOut = r.varint(100_000);
    const outputs = [];
    for (let k = 0; k < nOut; k++) outputs.push({ value: r.u64(), script: r.varbytes(10_000) });
    if (seg) {
      for (const i of inputs) {
        const n = r.varint(1_000);
        for (let k = 0; k < n; k++) i.witness.push(r.varbytes(4_000_000));
      }
    }
    const locktime = r.u32();
    r.end();
    return new BtcTx({ version, inputs, outputs, locktime });
  }

  /**
   * Hash de assinatura segwit v0 (BIP-143), só SIGHASH_ALL (o único que a troca usa).
   * scriptCode: o witnessScript (P2WSH) ou 76a914{hash160}88ac (P2WPKH), sem o prefixo de tamanho.
   */
  sighashV0(index, scriptCode, amount, hashType = SIGHASH_ALL) {
    if (hashType !== SIGHASH_ALL) throw new Error('só SIGHASH_ALL é suportado');
    const prevouts = new Writer(), seqs = new Writer(), outs = new Writer();
    for (const i of this.inputs) { prevouts.bytes(Buffer.from(i.txid, 'hex').reverse(), 32); prevouts.u32(i.vout); seqs.u32(i.sequence); }
    for (const o of this.outputs) { outs.u64(o.value); outs.varbytes(o.script); }
    const inp = this.inputs[index];
    const w = new Writer();
    w.u32(this.version);
    w.bytes(hash256(prevouts.done()), 32);
    w.bytes(hash256(seqs.done()), 32);
    w.bytes(Buffer.from(inp.txid, 'hex').reverse(), 32);
    w.u32(inp.vout);
    w.varbytes(scriptCode);
    w.u64(BigInt(amount));
    w.u32(inp.sequence);
    w.bytes(hash256(outs.done()), 32);
    w.u32(this.locktime);
    w.u32(hashType);
    return hash256(w.done());
  }
}
