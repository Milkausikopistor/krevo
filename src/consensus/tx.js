// Estrutura de transação do Krevo: UM formato para os dois mundos.
//
//  tIn  — entradas transparentes: (txid, índice) + assinatura Schnorr (ou M assinaturas, se multiassinatura)
//  sIn  — entradas privadas: âncora N (a árvore com as N primeiras saídas privadas) + pseudo-compromisso
//         + imagem de chave + prova de pertencimento à cadeia inteira (FCMP)
//         [legado, só na simnet: anel de saídas + CLSAG — codificado com tamanho de anel > 0]
//  tOut — saídas transparentes: valor público + trava (chave pública)
//  sOut — saídas privadas: chave efêmera R, chave de uso único P, compromisso C, valor cifrado, etiqueta
//
// Qualquer combinação é válida: transparente→transparente, transparente→privada
// ("blindar"), privada→privada, privada→transparente ("desblindar").
// O balanço é provado por uma única regra homomórfica + "assinatura de balanço".
//
// txid = hash do CORPO (sem assinaturas/provas) → assinaturas não alteram o id.

import { H } from '../crypto/hash.js';
import { Writer, Reader, toHex } from '../util/bytes.js';

export const TX_VERSION = 1;

export class Transaction {
  constructor({ version = TX_VERSION, tIn = [], sIn = [], tOut = [], sOut = [],
    fee = 0n, mass = 0, payload = Buffer.alloc(0), rangeProof = Buffer.alloc(0), bindingSig = null } = {}) {
    Object.assign(this, { version, tIn, sIn, tOut, sOut, fee, mass, payload, rangeProof, bindingSig });
    this._id = null; this._hash = null; this._size = null;
  }

  isCoinbase() { return this.tIn.length === 0 && this.sIn.length === 0; }

  serializeBody() {
    const w = new Writer();
    w.u16(this.version);
    w.varint(this.tIn.length);
    for (const i of this.tIn) { w.bytes(i.outpoint.txid, 32); w.u32(i.outpoint.index); }
    w.varint(this.sIn.length);
    for (const i of this.sIn) {
      w.varint(i.ring.length);
      if (!i.ring.length) w.varint(i.anchor); // FCMP: âncora (nº de saídas da árvore)
      for (const m of i.ring) { w.bytes(m.txid, 32); w.u32(m.index); }
      w.bytes(i.pseudo, 33); w.bytes(i.keyImage, 33);
    }
    w.varint(this.tOut.length);
    for (const o of this.tOut) { w.u64(o.amount); w.varbytes(o.lock); }
    w.varint(this.sOut.length);
    for (const o of this.sOut) { w.bytes(o.R, 33); w.bytes(o.P, 33); w.bytes(o.C, 33); w.bytes(o.encAmount, 8); w.u8(o.viewTag); }
    w.u64(this.fee);
    w.u64(this.mass);
    w.varbytes(this.payload);
    return w.done();
  }

  serializeWitness() {
    const w = new Writer();
    for (const i of this.tIn) w.varbytes(i.sig); // 64 bytes (chave única) ou política + M assinaturas
    for (const i of this.sIn) w.varbytes(i.ring.length ? i.clsag : i.fcmp);
    w.varbytes(this.rangeProof);
    if (this.bindingSig) { w.u8(1); w.bytes(this.bindingSig, 64); } else w.u8(0);
    return w.done();
  }

  serialize() { return Buffer.concat([this.serializeBody(), this.serializeWitness()]); }

  static read(r) {
    const tx = new Transaction();
    tx.version = r.u16();
    const nT = r.varint(10_000);
    for (let k = 0; k < nT; k++) tx.tIn.push({ outpoint: { txid: r.bytes(32), index: r.u32() } });
    const nS = r.varint(1_000);
    for (let k = 0; k < nS; k++) {
      const n = r.varint(128);
      const anchor = n ? undefined : r.varint(2 ** 40);
      const ring = [];
      for (let j = 0; j < n; j++) ring.push({ txid: r.bytes(32), index: r.u32() });
      tx.sIn.push(n ? { ring, pseudo: r.bytes(33), keyImage: r.bytes(33) } : { ring, anchor, pseudo: r.bytes(33), keyImage: r.bytes(33) });
    }
    const nTo = r.varint(10_000);
    for (let k = 0; k < nTo; k++) tx.tOut.push({ amount: r.u64(), lock: r.varbytes(255) });
    const nSo = r.varint(1_000);
    for (let k = 0; k < nSo; k++) tx.sOut.push({ R: r.bytes(33), P: r.bytes(33), C: r.bytes(33), encAmount: r.bytes(8), viewTag: r.u8() });
    tx.fee = r.u64();
    const mass = r.u64();
    if (mass > 0xffffffffn) throw new Error('massa inválida');
    tx.mass = Number(mass);
    tx.payload = r.varbytes(10_000);
    // testemunha
    for (const i of tx.tIn) i.sig = r.varbytes(8192); // Schnorr (64), multiassinatura ou híbrida quântica (3.830)
    for (const i of tx.sIn) { if (i.ring.length) i.clsag = r.varbytes(32 + 32 * 128 + 33); else i.fcmp = r.varbytes(16_384); }
    tx.rangeProof = r.varbytes(4_000);
    const hasB = r.u8();
    if (hasB > 1) throw new Error('flag inválida');
    tx.bindingSig = hasB ? r.bytes(64) : null;
    return tx;
  }

  static deserialize(buf) {
    const r = new Reader(buf);
    const tx = Transaction.read(r);
    r.end();
    return tx;
  }

  get id() { return (this._id ??= H('tx/id', this.serializeBody())); }
  get idHex() { return toHex(this.id); }
  get hash() { return (this._hash ??= H('tx/hash', this.id, H('tx/witness', this.serializeWitness()))); }
  get hashHex() { return toHex(this.hash); }
  get size() { return (this._size ??= this.serialize().length); }
  /** Mensagem assinada por todas as assinaturas da transação. */
  sighash() { return H('tx/sighash', this.id); }
  invalidate() { this._id = this._hash = this._size = null; }
}

export const outpointKey = (txid, index) => `${toHex(txid)}:${index}`;
export function parseOutpointKey(k) {
  const [h, i] = k.split(':');
  return { txid: Buffer.from(h, 'hex'), index: Number(i) };
}
/** Saídas privadas são numeradas depois das transparentes no mesmo txid. */
export const shieldedOutpointIndex = (tx, j) => tx.tOut.length + j;
