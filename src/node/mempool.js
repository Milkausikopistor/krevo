// Mempool: transações válidas contra o estado do virtual, aguardando um bloco.
// Seleção para blocos: amostragem aleatória ponderada pela taxa (Efraimidis–Spirakis),
// para que mineradores paralelos escolham conjuntos diferentes e o DAG não
// desperdice espaço com a mesma transação em vários blocos simultâneos.

import { validateTxStateless, validateTxInContext, shieldedDelta } from '../consensus/txvalidation.js';
import { outpointKey } from '../consensus/tx.js';
import { toHex } from '../util/bytes.js';

export class Mempool {
  constructor(consensus, { maxSize = 20_000 } = {}) {
    this.c = consensus;
    this.params = consensus.params;
    this.txs = new Map();
    this.spent = new Map();
    this.kis = new Map();
    this.maxSize = maxSize;
    this.version = 0;
    consensus.on('virtual', () => this.revalidate());
  }

  /** Valida sem inserir (usado também na fase "haste" do Dandelion++). */
  check(tx) {
    const id = tx.idHex;
    if (this.c.txStatus(id).status === 'accepted') throw new Error('transação já confirmada');
    validateTxStateless(tx, this.params);
    for (const i of tx.tIn) if (this.spent.has(outpointKey(i.outpoint.txid, i.outpoint.index))) throw new Error('conflito com transação no mempool');
    for (const si of tx.sIn) if (this.kis.has(toHex(si.keyImage))) throw new Error('imagem de chave já usada no mempool');
    const v = this.c.virtual;
    const r = validateTxInContext(tx, v.view, v.gd.daaScore, this.params);
    if ((v.acceptance.shielded ?? 0n) + shieldedDelta(tx, r.tIn) < 0n) throw new Error('catraca: retiraria do pool privado mais KRV do que existe nele');
    if (tx.fee < BigInt(tx.mass) * this.params.minRelayFeeRate) throw new Error('taxa abaixo do mínimo de retransmissão');
  }

  add(tx) {
    const id = tx.idHex;
    if (this.txs.has(id)) return { ok: true, txid: id, duplicate: true };
    if (this.txs.size >= this.maxSize) return { ok: false, txid: id, reason: 'mempool cheio' };
    try { this.check(tx); } catch (e) { return { ok: false, txid: id, reason: e.message }; }
    this.txs.set(id, { tx, feeRate: Number(tx.fee) / Math.max(tx.mass, 1), added: Date.now() });
    for (const i of tx.tIn) this.spent.set(outpointKey(i.outpoint.txid, i.outpoint.index), id);
    for (const si of tx.sIn) this.kis.set(toHex(si.keyImage), id);
    this.version++;
    return { ok: true, txid: id };
  }

  remove(id) {
    const e = this.txs.get(id);
    if (!e) return;
    this.txs.delete(id);
    for (const i of e.tx.tIn) this.spent.delete(outpointKey(i.outpoint.txid, i.outpoint.index));
    for (const si of e.tx.sIn) this.kis.delete(toHex(si.keyImage));
    this.version++;
  }

  revalidate() {
    const v = this.c.virtual;
    for (const [id, e] of [...this.txs]) {
      try {
        if (v.acceptance.acceptedSet.has(id) || this.c.txIndex.has(id)) throw new Error('confirmada');
        validateTxInContext(e.tx, v.view, v.gd.daaScore, this.params);
      } catch { this.remove(id); }
    }
  }

  select(maxMass) {
    const items = [...this.txs.values()].map((e) => ({ e, key: Math.random() ** (1 / Math.max(e.feeRate, 1e-9)) }));
    items.sort((a, b) => b.key - a.key);
    const out = [];
    let mass = 0;
    for (const { e } of items) {
      if (mass + e.tx.mass > maxMass) continue;
      out.push(e.tx);
      mass += e.tx.mass;
    }
    return out;
  }
}
