// Interface JSON-RPC (HTTP POST) do nó — usada por carteiras e mineradores.
// Escuta só em 127.0.0.1 por padrão.
import http from 'node:http';
import { Block, merkleProof } from '../consensus/block.js';
import { Transaction, parseOutpointKey } from '../consensus/tx.js';
import { compactToTarget, calcWork } from '../consensus/pow.js';
import { decodeAddress, encodeAddress, parseAddressData, describeLock } from '../address.js';
import { checkName, nameFee, parseNameRecord } from '../consensus/names.js';
import { toHex, fromHex } from '../util/bytes.js';

// Obs.: JSON.stringify chama Buffer.toJSON antes do replacer, então lemos o valor
// original no objeto pai (this[k]) para serializar Buffers como hexadecimal.
const json = (o) => JSON.stringify(o, function (k, v) {
  const orig = this[k];
  if (Buffer.isBuffer(orig)) return toHex(orig);
  return typeof v === 'bigint' ? v.toString() : v;
});

export class RpcServer {
  constructor(node, { port, host }) {
    this.node = node; this.port = port; this.host = host;
    this.templateCache = new Map();
    this.waiters = new Set();
    node.consensus.on('virtual', () => this._wake());
  }

  start() {
    this.server = http.createServer((req, res) => this._handle(req, res));
    return new Promise((ok, err) => { this.server.once('error', err); this.server.listen(this.port, this.host, ok); });
  }
  stop() {
    for (const w of this.waiters) w();
    if (!this.server) return Promise.resolve();
    const done = new Promise((ok) => this.server.close(() => ok()));
    this.server.closeAllConnections?.(); // conexões keep-alive impediriam o fechamento
    return done;
  }
  _wake() { for (const w of [...this.waiters]) w(); this.waiters.clear(); }

  _handle(req, res) {
    if (req.method !== 'POST') { res.writeHead(405).end(); return; }
    let body = '';
    req.on('data', (d) => { body += d; if (body.length > 10_000_000) req.destroy(); });
    req.on('end', async () => {
      let id = null;
      try {
        const msg = JSON.parse(body);
        id = msg.id ?? null;
        const fn = this.methods[msg.method];
        if (!fn) throw new Error(`método desconhecido: ${msg.method}`);
        const result = await fn.call(this, msg.params ?? {});
        res.writeHead(200, { 'content-type': 'application/json' }).end(json({ id, result }));
      } catch (e) {
        res.writeHead(200, { 'content-type': 'application/json' }).end(json({ id, error: e.message }));
      }
    });
  }

  _shieldedEntry(index) {
    const v = this.node.consensus.virtual.view;
    const key = v.sAt(index);
    if (!key) return null;
    const e = v.getS(key);
    // o memo (payload da tx) segue junto: a carteira baixa tudo em lote e o nó não sabe o que é dela
    let memo;
    if (!e.coinbase) {
      const tx = this.node.consensus.findTx(key.split(':')[0]);
      if (tx && tx.payload.length) memo = tx.payload;
    }
    return { index, outpoint: key, P: e.P, C: e.C, encAmount: e.encAmount, viewTag: e.viewTag, R: e.R, j: e.j, daa: e.daa, coinbase: e.coinbase, memo };
  }

  /** Situação de um @nome no estado atual (virtual). */
  _nameInfo(rawName) {
    const c = this.node.consensus, p = c.params, v = c.virtual, daa = v.gd.daaScore;
    const name = checkName(rawName);
    const fee = nameFee(p, name);
    const live = v.view.nameEntries(name).map(({ key, e }) => ({ key, e, r: parseNameRecord(e.lock) }))
      .find((x) => daa <= x.r.expiry + p.nameGrace);
    if (!live) return { name, status: 'livre', fee, daaScore: daa };
    return {
      name, status: daa <= live.r.expiry ? 'ativo' : 'em carência', fee, daaScore: daa,
      target: encodeAddress(p, live.r.target), targetType: parseAddressData(live.r.target).type, targetData: live.r.target,
      owner: encodeAddress(p, live.r.owner), ownerLock: live.r.owner,
      expiry: live.r.expiry, expiresIn: (live.r.expiry - daa) / p.bps, graceEndsIn: (live.r.expiry + p.nameGrace - daa) / p.bps,
      outpoint: live.key, txid: live.key.split(':')[0], deposit: live.e.amount, since: live.e.daa,
    };
  }

  methods = {
    // ---------------------------------------------------------------- carteiras leves
    /**
     * Saídas privadas em formato COMPACTO para varredura no aparelho: por saída só
     * R (33) ‖ j (1) ‖ view tag (1) = 35 bytes, em hexadecimal. A carteira testa a view tag
     * localmente e só pede a saída completa das poucas que batem (~1 em 256).
     */
    getcompactoutputs({ start = 0, count = 5000 }) {
      const v = this.node.consensus.virtual, view = v.view;
      const end = Math.min(view.sCount, Number(start) + Math.min(Number(count) || 0, 20_000));
      const parts = [];
      for (let i = Number(start); i < end; i++) {
        const e = view.getS(view.sAt(i));
        parts.push(e.R, Buffer.from([e.j, e.viewTag]));
      }
      return { total: view.sCount, daaScore: v.gd.daaScore, start: Number(start), count: Math.max(0, end - Number(start)), data: Buffer.concat(parts) };
    },

    /**
     * Imagens de chave já usadas cujo hexadecimal começa com `prefix` (1 byte = 2 caracteres).
     * A carteira pergunta pelo "balde" inteiro, então o servidor não sabe qual imagem é dela.
     */
    getkeyimagebucket({ prefix }) {
      if (!/^[0-9a-f]{2}$/.test(String(prefix))) throw new Error('prefixo de imagem de chave inválido (use 1 byte, ex.: "a7")');
      const c = this.node.consensus, v = c.virtual.view;
      const spent = [];
      for (const k of v.base.ki) if (k.startsWith(prefix)) spent.push(k);
      for (const k of v.diff.addKI) if (k.startsWith(prefix)) spent.push(k);
      const stem = this.node.stemSpends();
      const mempool = [...this.node.mempool.kis.keys(), ...stem.kis].filter((k) => k.startsWith(prefix));
      return { prefix, spent, mempool };
    },

    /** Cabeçalho serializado (hex) de um bloco. */
    getheader({ hash }) {
      const h = this.node.consensus.headers.get(hash);
      if (!h) throw new Error('bloco desconhecido');
      return { hash, header: h.serialize() };
    },

    /**
     * Prova de aceitação para carteiras leves: o bloco da cadeia selecionada que aceitou a
     * transação, o caminho de Merkle até acceptedIdMerkleRoot e os `depth` cabeçalhos
     * seguintes da cadeia (cada um aponta para o anterior e tem prova de trabalho).
     */
    gettxproof({ txid, depth = 100 }) {
      const c = this.node.consensus;
      depth = Math.max(1, Math.min(Number(depth) || 100, 5000));
      const h = c.txIndex.get(txid);
      if (!h) throw new Error(c.txStatus(txid).status === 'accepted' ? 'aceita há pouco: a prova fica pronta no próximo bloco' : 'transação não aceita');
      const accepted = c.acc.get(h).accepted;
      const idx = accepted.indexOf(txid);
      const merkle = merkleProof(accepted.map(fromHex), idx);
      // blocos da cadeia selecionada depois de h (andando para trás a partir da ponta)
      const hScore = c.gd(h).blueScore;
      const after = [];
      let x = c.virtual.gd.selectedParent, steps = 0;
      while (x && x !== h) {
        const g = c.gd(x);
        if (g.blueScore <= hScore || ++steps > 3_000_000) throw new Error('o bloco de aceitação saiu da cadeia selecionada (reorganização): tente de novo');
        after.push(x);
        if (after.length > depth) after.shift(); // guarda só os mais próximos de h
        x = g.selectedParent;
      }
      if (!x) throw new Error('bloco de aceitação fora da cadeia');
      after.reverse();
      return {
        txid, block: h, header: c.headers.get(h).serialize(), merkle,
        chain: after.map((b) => c.headers.get(b).serialize()), available: after.length,
      };
    },

    /** @nome → endereço (e dono, vencimento, depósito). */
    resolvename({ name }) { return this._nameInfo(name); },

    /** Nomes vivos (ativos ou em carência); owners: travas (hex) para filtrar pelos donos. */
    listnames({ owners = null, limit = 1000 } = {}) {
      const want = owners ? new Set(owners) : null;
      const out = [];
      for (const n of [...this.node.consensus.virtual.view.allNames()].sort()) {
        const info = this._nameInfo(n);
        if (info.status === 'livre') continue;
        if (want && !want.has(toHex(info.ownerLock))) continue;
        out.push(info);
        if (out.length >= Math.min(Number(limit) || 1000, 5000)) break;
      }
      return out;
    },

    getinfo() {
      const n = this.node, c = n.consensus, v = c.virtual;
      const target = compactToTarget(v.bits);
      const bps = n.blockTimes.length / Math.min(60, Math.max(1, (Date.now() - n.startedAt) / 1000));
      return {
        network: c.params.name, genesis: c.genesisHash, blocks: c.store.gd.size, tips: c.tips.size,
        virtual: { blueScore: v.gd.blueScore, daaScore: v.gd.daaScore, selectedParent: v.gd.selectedParent, parents: v.parents.length },
        difficulty: Number(calcWork(v.bits)), target: target.toString(16),
        blocksPerSecond: Number(bps.toFixed(2)),
        hashrate: Math.round(Number(calcWork(v.bits)) * bps),
        mempool: n.mempool.txs.size, peers: [...n.p2p.peers].filter((p) => p.ready).length,
        ...c.supplyInfo(), shieldedOutputs: v.view.sCount, redBlocks: c.stats.reds, names: v.view.allNames().size,
      };
    },

    async getblocktemplate({ address, longpollid }) {
      const c = this.node.consensus;
      const addr = decodeAddress(c.params, address);
      if (longpollid && longpollid === this._templateId()) {
        await new Promise((ok) => { const w = () => ok(); this.waiters.add(w); setTimeout(() => { this.waiters.delete(w); ok(); }, 1000); });
      }
      const id = this._templateId();
      const key = id + addr.data.toString('hex');
      let t = this.templateCache.get(key);
      if (!t) {
        const txs = this.node.mempool.select(c.params.maxBlockMass - 20_000);
        const block = c.buildTemplate(addr.data, txs, Buffer.from('krevo-ref'));
        t = { block: toHex(block.serialize()), prePowHash: toHex(block.header.prePowHash()), bits: block.header.bits, longpollid: id, txs: txs.length };
        if (this.templateCache.size > 64) this.templateCache.clear();
        this.templateCache.set(key, t);
      }
      return t;
    },

    submitblock({ block }) {
      const b = Block.deserialize(fromHex(block));
      const r = this.node.receiveBlock(b, null);
      return { status: r.status, hash: r.hash, reason: r.reason };
    },

    sendrawtransaction({ tx }) {
      const t = Transaction.deserialize(fromHex(tx));
      const r = this.node.submitTx(t);
      if (!r.ok) throw new Error(r.reason);
      return { txid: r.txid, phase: r.phase };
    },

    gettransaction({ txid }) {
      const c = this.node.consensus;
      const m = this.node.mempool.txs.get(txid) ?? this.node.stem.get(txid);
      const tx = m ? m.tx : c.findTx(txid);
      if (!tx) throw new Error('transação desconhecida');
      const st = c.txStatus(txid);
      return {
        txid, tx: toHex(tx.serialize()), status: st.status === 'unknown' && m ? 'mempool' : st.status, confirmations: st.confirmations ?? 0,
        includedIn: c.txBlock.get(txid) ?? null, acceptingBlock: st.acceptingBlock ?? null,
      };
    },

    gettransactionstatus({ txid }) {
      const s = this.node.consensus.txStatus(txid);
      if (s.status === 'unknown' && (this.node.mempool.txs.has(txid) || this.node.stem.has(txid))) return { status: 'mempool' };
      return s;
    },

    getutxos({ locks }) {
      const c = this.node.consensus, daa = c.virtual.gd.daaScore;
      const stem = this.node.stemSpends(); // transações locais ainda na fase de haste do Dandelion++
      return { daaScore: daa, utxos: locks.flatMap((l) => c.utxosByLock(l).map((u) => ({
        outpoint: u.key, amount: u.amount, lock: u.lock, daa: u.daa, coinbase: u.coinbase,
        mature: !u.coinbase || daa - u.daa >= c.params.coinbaseMaturity,
        inMempool: this.node.mempool.spent.has(u.key) || stem.outs.has(u.key),
      }))) };
    },

    getshieldedoutputs({ start = 0, count = 1000 }) {
      const v = this.node.consensus.virtual;
      const out = [];
      for (let i = start; i < Math.min(start + Math.min(count, 5000), v.view.sCount); i++) out.push(this._shieldedEntry(i));
      return { total: v.view.sCount, daaScore: v.gd.daaScore, outputs: out };
    },

    getshieldedbyindex({ indices }) {
      const v = this.node.consensus.virtual;
      return { total: v.view.sCount, daaScore: v.gd.daaScore, outputs: indices.slice(0, 500).map((i) => this._shieldedEntry(i)).filter(Boolean) };
    },

    getkeyimages({ keyImages }) {
      const c = this.node.consensus, v = c.virtual.view;
      const stem = this.node.stemSpends();
      return keyImages.map((k) => ({ keyImage: k, spent: v.hasKI(k), inMempool: this.node.mempool.kis.has(k) || stem.kis.has(k) }));
    },

    /**
     * Âncora para provas de pertencimento: o maior N tal que as N primeiras saídas privadas
     * (na ordem da cadeia selecionada) já estão maduras para a regra de consenso.
     */
    getfcmpanchor() {
      const c = this.node.consensus, p = c.params;
      c._moveBase(c.virtual.gd.selectedParent);
      const base = c.utxo, daa = c.virtual.gd.daaScore, limit = daa - p.fcmpMaturity - 1;
      let lo = 0, hi = base.sList.length;
      while (lo < hi) {
        const mid = (lo + hi + 1) >> 1;
        if (base.s.get(base.sList[mid - 1]).daa <= limit) lo = mid; else hi = mid - 1;
      }
      return { anchor: lo, branch: p.fcmpBranch, total: base.sList.length, daaScore: daa };
    },

    /** Caminhos (entradas de cada nó até a raiz) de vários "pedaços" de nível 1 da árvore. */
    getfcmppath({ anchor, chunks }) {
      const c = this.node.consensus, b = c.params.fcmpBranch;
      c._moveBase(c.virtual.gd.selectedParent);
      const base = c.utxo;
      if (!Number.isSafeInteger(anchor) || anchor < 1 || anchor > base.sList.length) throw new Error('âncora inválida');
      const last = Math.ceil(anchor / b) - 1;
      const hex = (x) => x.toString(16).padStart(64, '0');
      return {
        anchor, branch: b,
        paths: (chunks ?? []).slice(0, 32).filter((k) => Number.isSafeInteger(k) && k >= 0 && k <= last).map((k) => ({
          chunk: k,
          levels: base.tree.pathForChunk(anchor, k).map((l) => ({ level: l.level, idx: l.idx, entries: l.entries.map(hex) })),
        })),
      };
    },

    getblock({ hash }) {
      const c = this.node.consensus;
      const b = c.blocks.get(hash);
      if (!b) throw new Error('bloco desconhecido');
      const gd = c.gd(hash), h = b.header, cb = b.txs[0];
      return {
        ...this._blockSummary(hash),
        bits: h.bits, nonce: h.nonce, blueWork: h.blueWork, selectedParent: gd.selectedParent,
        blues: gd.mergesetBlues, reds: gd.mergesetReds, status: c.status.get(hash), children: c.store.children.get(hash) ?? [],
        size: b.serialize().length, mass: b.txs.reduce((a, t) => a + t.mass, 0), utxoCommitment: h.utxoCommitment,
        txs: b.txs.map((t) => t.idHex),
        coinbase: {
          txid: cb.idHex,
          transparent: cb.tOut.map((o) => ({ address: describeLock(c.params, o.lock), amount: o.amount })),
          shielded: cb.sOut.length,
        },
        accepted: c.acc.get(hash)?.accepted?.length ?? 0,
      };
    },

    /** Blocos mais recentes (ordem de chegada) com cor GHOSTDAG e se estão na cadeia selecionada. */
    getdag({ limit = 80 }) {
      const c = this.node.consensus;
      return { virtualBlueScore: c.virtual.gd.blueScore, blocks: c.order.slice(-Math.min(Number(limit) || 80, 500)).map((h) => this._blockSummary(h)) };
    },

    getaddresshistory({ address, limit = 50 }) {
      const c = this.node.consensus;
      const a = decodeAddress(c.params, address);
      if (a.type === 's') throw new Error('endereço privado: o saldo e o histórico são invisíveis por projeto');
      const lockHex = toHex(a.data), daa = c.virtual.gd.daaScore;
      const utxos = c.utxosByLock(lockHex).map((u) => ({
        outpoint: u.key, amount: u.amount, daa: u.daa, coinbase: u.coinbase,
        mature: !u.coinbase || daa - u.daa >= c.params.coinbaseMaturity,
      }));
      const txids = (c.lockTxs.get(lockHex) ?? []).slice(-Math.min(Number(limit) || 50, 500)).reverse();
      return { type: a.type, utxos, txids, daaScore: daa };
    },

    /** Recompensa efetivamente paga a um bloco (para pools): pendente, paga (e se já amadureceu) ou vermelho. */
    getblockreward({ hash }) {
      const c = this.node.consensus;
      if (!c.has(hash)) return { status: 'unknown' };
      const r = c.rewardIndex.get(hash);
      if (!r) return { status: 'pending' };
      if (r.red) return { status: 'red', paidBy: r.paidBy };
      // a coinbase do bloco pagador entra no estado quando o filho dele na cadeia a aceita
      const age = c.virtual.gd.daaScore - c.gd(r.paidBy).daaScore;
      return { status: 'paid', amount: r.amount, paidBy: r.paidBy, age, mature: age > c.params.coinbaseMaturity + 2 };
    },

    getmempool({ limit = 50 }) {
      return [...this.node.mempool.txs.values()].sort((x, y) => y.added - x.added).slice(0, Math.min(Number(limit) || 50, 500))
        .map((e) => ({ txid: e.tx.idHex, fee: e.tx.fee, mass: e.tx.mass, size: e.tx.size, added: e.added }));
    },

    getpeers() { return [...this.node.p2p.peers].map((p) => ({ addr: p.listen ?? p.addr, outbound: p.outbound, ready: p.ready })); },
    addpeer({ addr }) { this.node.p2p.connect(addr); return true; },
    estimatefee() { return { feeRate: this.node.consensus.params.minRelayFeeRate }; },
  };

  /** Cadeia selecionada e blocos vermelhos recentes (cache por versão do virtual). */
  _colors() {
    const c = this.node.consensus;
    if (this._colorCache?.v === c.virtualVersion) return this._colorCache;
    const chain = new Set(c.selectedChain(600));
    const reds = new Set(c.virtual.gd.mergesetReds);
    for (const h of chain) for (const r of c.gd(h).mergesetReds) reds.add(r);
    this._colorCache = { v: c.virtualVersion, chain, reds };
    return this._colorCache;
  }

  _blockSummary(h) {
    const c = this.node.consensus, b = c.blocks.get(h), gd = c.gd(h), col = this._colors();
    let miner = null;
    try { miner = encodeAddress(c.params, c.minerData.get(h)); } catch { /* gênesis */ }
    return {
      hash: h, parents: c.store.parents.get(h), blueScore: gd.blueScore, daaScore: gd.daaScore, timestamp: b.header.timestamp,
      txs: b.txs.length - 1, txids: b.txs.slice(1).map((t) => t.idHex), chain: col.chain.has(h), color: col.reds.has(h) ? 'red' : 'blue', tip: c.tips.has(h), miner,
    };
  }

  _templateId() { return `${this.node.consensus.virtualVersion}-${this.node.mempool.version}`; }
}

export { parseOutpointKey };
