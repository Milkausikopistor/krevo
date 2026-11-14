// Motor de consenso do Krevo.
//
// Fluxo de um bloco novo:
//  1. cabeçalho: PoW, pais (antichain), GHOSTDAG, dificuldade, timestamp, profundidade de merge
//  2. corpo: coinbase bem formada, transações válidas isoladamente, Merkle, massa
//  3. estado UTXO: o bloco "aceita" as transações do seu mergeset, em ordem de consenso,
//     sobre o estado do pai selecionado. Transações conflitantes de blocos paralelos
//     não invalidam o bloco: a primeira na ordem vence, as outras são ignoradas.
//     O compromisso UTXO (MuHash) e a coinbase do cabeçalho precisam conferir;
//     senão o bloco fica "desqualificado da cadeia" (continua no DAG, sem estado).
//  4. "virtual": o bloco hipotético que aponta para todas as pontas. O estado do
//     virtual é o estado atual da rede — é contra ele que o mempool valida.
//
// Recompensas (sem pré-mineração, sem autoridade):
//  Cada bloco da cadeia paga, na sua coinbase, todos os blocos do seu mergeset:
//   azul     → subsídio + 1/2 das suas taxas + liberação do Fundo, para o minerador dele
//   vermelho → o mesmo valor vai para o minerador do bloco que o incorporou
//  A outra metade das taxas entra no "Fundo de Segurança", que é liberado aos poucos
//  (1/864.000 por bloco): isso suaviza a renda dos mineradores, reduz o incentivo a
//  ataques por taxas e ajuda a segurança de longo prazo quando a emissão acabar.

import { EventEmitter } from 'node:events';
import { Block, Header, merkleRoot } from './block.js';
import { Transaction, outpointKey } from './tx.js';
import { DagStore, Ghostdag, genesisGhostdag } from './ghostdag.js';
import { requiredBits, pastMedianTime } from './difficulty.js';
import { calcWork, checkPow, compactToTarget } from './pow.js';
import { UtxoSet, UtxoView, UtxoDiff, encodeTEntry, encodeSEntry, encodeKI } from './utxo.js';
import { validateTxStateless, validateTxInContext, shieldedDelta, TxRuleError } from './txvalidation.js';
import { cappedSubsidy } from './emission.js';
import { MuHash } from '../crypto/muhash.js';
import { makeShieldedOutput } from '../crypto/stealth.js';
import { hashToScalar } from '../crypto/secp256k1.js';
import { parseAddressData } from '../address.js';
import { Writer, Reader, toHex, fromHex, ZERO32 } from '../util/bytes.js';

export class BlockRuleError extends Error {}
const fail = (m) => { throw new BlockRuleError(m); };

export function coinbasePayload(blueScore, minerData, extra) {
  return new Writer().u64(blueScore).varbytes(minerData).varbytes(extra).done();
}
export function parseCoinbasePayload(buf) {
  const r = new Reader(buf);
  const blueScore = Number(r.u64());
  const minerData = r.varbytes(100);
  const extra = r.varbytes(200);
  r.end();
  return { blueScore, minerData, extra };
}

export function buildGenesis(params) {
  const g = params.genesis;
  const cb = new Transaction({ payload: coinbasePayload(0, Buffer.alloc(0), Buffer.from(g.message, 'utf8')) });
  const header = new Header({
    version: 1, parents: [], hashMerkleRoot: merkleRoot([cb.hash]), acceptedIdMerkleRoot: ZERO32,
    utxoCommitment: new MuHash().digest(), timestamp: g.timestamp, bits: g.bits, nonce: 0n,
    daaScore: 0, blueScore: 0, blueWork: 0n,
  });
  return new Block(header, [cb]);
}

export class Consensus extends EventEmitter {
  constructor(params) {
    super();
    this.params = params;
    this.store = new DagStore();
    this.ghostdag = new Ghostdag(this.store, params.ghostdagK);
    this.headers = new Map();
    this.blocks = new Map();
    this.minerData = new Map();     // hash → dados de endereço do minerador
    this.minerParsed = new Map();
    this.status = new Map();        // 'chain' (estado válido) | 'disq' (desqualificado)
    this.acc = new Map();           // dados de aceitação dos blocos com estado válido
    this.invalid = new Map();       // hash → motivo
    this.tips = new Set();
    this.utxo = new UtxoSet(params.fcmpBranch);
    this.txIndex = new Map();       // txid → bloco da cadeia que a aceitou (cadeia da base)
    this.txBlock = new Map();       // txid → primeiro bloco que contém a transação (índice local, não é consenso)
    this.lockTxs = new Map();       // trava transparente → txids que a tocam (índice local, para exploradores)
    this.rewardIndex = new Map();   // bloco → { amount, paidBy, red } recompensa efetivamente paga (índice local, para pools)
    this.order = [];                // hashes na ordem de chegada (índice local)
    this.powLimitBits = params.genesis.bits;
    this.virtual = null;
    this.virtualVersion = 0;
    this.stats = { blocks: 0, reds: 0 };

    const g = buildGenesis(params);
    const h = g.hashHex;
    this.genesisHash = h;
    this.headers.set(h, g.header);
    this.blocks.set(h, g);
    this.minerData.set(h, Buffer.alloc(0));
    const gd = genesisGhostdag();
    gd.mergesetAsc = [];
    this.store.add(h, [], gd, calcWork(g.header.bits));
    this.status.set(h, 'chain');
    this.acc.set(h, { diff: new UtxoDiff(), muhash: new MuHash(), pool: 0n, minted: 0n, accepted: [], shielded: 0n, cbShielded: 0n });
    this.tips.add(h);
    this.order.push(h);
    this.baseHash = h;
    this.resolveVirtual();
  }

  has(hash) { return this.store.has(hash); }
  gd(hash) { return this.store.gd.get(hash); }

  // ------------------------------------------------------------ entrada
  /**
   * Processa um bloco. Retorna { status: 'accepted'|'known'|'orphan'|'future'|'invalid', ... }.
   */
  addBlock(block, { now = Date.now(), trusted = false } = {}) {
    const hash = block.hashHex;
    if (this.store.has(hash)) return { status: 'known', hash };
    if (this.invalid.has(hash)) return { status: 'invalid', hash, reason: this.invalid.get(hash) };
    const h = block.header;
    const parents = h.parents.map(toHex);
    const missing = [...new Set(parents.filter((p) => !this.store.has(p)))];
    if (missing.length) return { status: 'orphan', hash, missing };
    if (!trusted && h.timestamp > now + this.params.maxFutureMs) return { status: 'future', hash };

    let gd, minerData;
    try {
      gd = this._validateHeader(block, parents);
      minerData = this._validateBody(block);
    } catch (e) {
      if (e instanceof BlockRuleError || e instanceof TxRuleError) {
        if (this.invalid.size > 10_000) this.invalid.clear();
        this.invalid.set(hash, e.message);
        return { status: 'invalid', hash, reason: e.message };
      }
      throw e;
    }

    this.headers.set(hash, h);
    this.blocks.set(hash, block);
    this.minerData.set(hash, minerData);
    this.store.add(hash, parents, gd, calcWork(h.bits));
    for (const p of parents) this.tips.delete(p);
    this.tips.add(hash);
    this.stats.blocks++;
    this.stats.reds += gd.mergesetReds.length;
    this.order.push(hash);
    for (const tx of block.txs) {
      const id = tx.idHex;
      if (this.txBlock.has(id)) continue;
      this.txBlock.set(id, hash);
      this._indexLocks(tx, id);
    }

    const chainValid = this._validateUtxo(hash);
    this.resolveVirtual();
    this.emit('block', { hash, block, chainValid });
    return { status: 'accepted', hash, chainValid };
  }

  _validateHeader(block, parents) {
    const p = this.params, h = block.header;
    if (h.version !== 1) fail('versão de cabeçalho desconhecida');
    if (parents.length < 1 || parents.length > p.maxParents) fail('número de pais inválido');
    for (let i = 1; i < parents.length; i++) if (!(parents[i - 1] < parents[i])) fail('pais fora de ordem ou repetidos');
    if (compactToTarget(h.bits) > compactToTarget(this.powLimitBits)) fail('alvo acima do limite');
    if (!checkPow(h)) fail('prova de trabalho insuficiente');
    for (let i = 0; i < parents.length; i++) {
      for (let j = 0; j < parents.length; j++) {
        if (i !== j && this.store.isAncestor(parents[i], parents[j])) fail('pais não formam uma antichain');
      }
    }
    const gd = this.ghostdag.run(parents);
    if (gd.mergesetBlues.length + gd.mergesetReds.length > p.mergesetSizeLimit) fail('mergeset grande demais');
    if (h.blueScore !== gd.blueScore || h.blueWork !== gd.blueWork || h.daaScore !== gd.daaScore) fail('dados GHOSTDAG do cabeçalho não conferem');
    if (h.bits !== requiredBits(p, this.store, this.headers, gd, this.powLimitBits)) fail('dificuldade incorreta');
    if (h.timestamp < pastMedianTime(p, this.store, this.headers, gd)) fail('timestamp anterior ao tempo mediano passado');
    for (const x of gd.mergesetAsc) {
      if (gd.blueScore - this.store.gd.get(x).blueScore > p.mergeDepth) fail('bloco antigo demais no mergeset (limite de merge)');
    }
    return gd;
  }

  _validateBody(block) {
    const p = this.params, txs = block.txs;
    if (txs.length < 1) fail('bloco sem coinbase');
    const cb = txs[0];
    if (!cb.isCoinbase() || cb.version !== 1) fail('primeira transação não é coinbase');
    if (cb.fee !== 0n || cb.mass !== 0 || cb.rangeProof.length || cb.bindingSig) fail('coinbase malformada');
    if (cb.payload.length > p.maxCoinbasePayload) fail('payload da coinbase grande demais');
    let pl;
    try { pl = parseCoinbasePayload(cb.payload); } catch { fail('payload da coinbase inválido'); }
    if (pl.blueScore !== block.header.blueScore) fail('blue score da coinbase não confere');
    let md;
    try { md = parseAddressData(pl.minerData); } catch { fail('endereço do minerador inválido'); }
    if (!['t', 's', 'm', 'q'].includes(md.type)) fail('endereço do minerador inválido (precisa ser krv, krs, krq ou multiassinatura)');
    let mass = 0;
    const ids = new Set([cb.idHex]);
    for (let i = 1; i < txs.length; i++) {
      const tx = txs[i];
      if (tx.isCoinbase()) fail('coinbase extra');
      validateTxStateless(tx, p);
      if (ids.has(tx.idHex)) fail('transação repetida no bloco');
      ids.add(tx.idHex);
      mass += tx.mass;
    }
    if (mass > p.maxBlockMass) fail('massa do bloco acima do limite');
    if (!merkleRoot(txs.map((t) => t.hash)).equals(block.header.hashMerkleRoot)) fail('raiz de Merkle incorreta');
    return pl.minerData;
  }

  _minerAddr(hash) {
    let a = this.minerParsed.get(hash);
    if (!a) { a = parseAddressData(this.minerData.get(hash)); this.minerParsed.set(hash, a); }
    return a;
  }

  _validateUtxo(hash) {
    const gd = this.store.gd.get(hash);
    if (this.status.get(gd.selectedParent) !== 'chain') { this.status.set(hash, 'disq'); return false; }
    const block = this.blocks.get(hash), h = block.header;
    const parentsKey = this.store.parents.get(hash).join();
    let res;
    if (this.virtual && this.virtual.parents.map(toHex).join() === parentsKey) {
      res = this.virtual.acceptance; // mesmos pais do virtual atual → mesma aceitação
    } else {
      this._moveBase(gd.selectedParent);
      res = this._computeAcceptance(gd);
    }
    let reason = null, cbShielded = 0n;
    if (!h.utxoCommitment.equals(res.muhash.digest())) reason = 'compromisso UTXO incorreto';
    else if (!h.acceptedIdMerkleRoot.equals(res.acceptedRoot)) reason = 'raiz de transações aceitas incorreta';
    else {
      const actual = block.txs[0];
      const extra = parseCoinbasePayload(actual.payload).extra;
      const expected = this._buildCoinbase(res, gd, this.store.parents.get(hash), this.minerData.get(hash), extra);
      if (!expected.serializeBody().equals(actual.serializeBody())) reason = 'coinbase não confere com as recompensas devidas';
      cbShielded = expected.shieldedTotal;
    }
    if (reason) {
      this.status.set(hash, 'disq');
      this.emit('disqualified', { hash, reason });
      return false;
    }
    this.acc.set(hash, {
      diff: res.view.diff, muhash: res.muhash, pool: res.pool, minted: res.minted, accepted: res.accepted,
      rewards: res.blueRewards, reds: gd.mergesetReds, shielded: res.shielded, cbShielded, nameFees: res.nameFees,
    });
    this.status.set(hash, 'chain');
    return true;
  }

  /** Move o estado materializado para o bloco `target` revertendo/aplicando diffs. */
  _moveBase(target) {
    if (this.baseHash === target) return;
    let a = this.baseHash, b = target;
    const revert = [], apply = [];
    while (a !== b) {
      if (this.ghostdag.cmp(a, b) > 0) { revert.push(a); a = this.store.gd.get(a).selectedParent; }
      else { apply.push(b); b = this.store.gd.get(b).selectedParent; }
    }
    for (const h of revert) {
      const acc = this.acc.get(h);
      this.utxo.revert(acc.diff);
      for (const id of acc.accepted) if (this.txIndex.get(id) === h) this.txIndex.delete(id);
      for (const r of acc.rewards ?? []) if (this.rewardIndex.get(r.hash)?.paidBy === h) this.rewardIndex.delete(r.hash);
      for (const r of acc.reds ?? []) if (this.rewardIndex.get(r)?.paidBy === h) this.rewardIndex.delete(r);
    }
    for (const h of apply.reverse()) {
      const acc = this.acc.get(h);
      if (!acc) throw new Error('bloco da cadeia sem estado: ' + h);
      this.utxo.apply(acc.diff);
      for (const id of acc.accepted) this.txIndex.set(id, h);
      for (const r of acc.rewards ?? []) this.rewardIndex.set(r.hash, { amount: r.amount, paidBy: h, red: false });
      for (const r of acc.reds ?? []) this.rewardIndex.set(r, { amount: 0n, paidBy: h, red: true }); // a recompensa de bloco vermelho vai para quem o fundiu
    }
    this.baseHash = target;
  }

  _applyTx(view, mh, tx, daa, coinbase) {
    for (const i of tx.tIn) {
      const k = outpointKey(i.outpoint.txid, i.outpoint.index);
      const e = view.getT(k);
      view.spendT(k, e);
      mh.remove(encodeTEntry(k, e));
    }
    for (const si of tx.sIn) {
      const ki = toHex(si.keyImage);
      view.addKI(ki);
      mh.add(encodeKI(ki));
    }
    tx.tOut.forEach((o, i) => {
      const k = outpointKey(tx.id, i);
      const e = { amount: o.amount, lock: o.lock, daa, coinbase };
      view.addT(k, e);
      mh.add(encodeTEntry(k, e));
    });
    tx.sOut.forEach((o, j) => {
      const k = outpointKey(tx.id, tx.tOut.length + j);
      const e = { P: o.P, C: o.C, encAmount: o.encAmount, viewTag: o.viewTag, R: o.R, j, daa, coinbase };
      view.addS(k, e);
      mh.add(encodeSEntry(k, e));
    });
  }

  /** Aceitação de um bloco (ou do virtual) com estes dados GHOSTDAG. Pré-condição: base = pai selecionado. */
  _computeAcceptance(gd) {
    const p = this.params;
    const sp = gd.selectedParent;
    if (this.baseHash !== sp) throw new Error('base fora de posição');
    const spAcc = this.acc.get(sp);
    const view = new UtxoView(this.utxo);
    const mh = spAcc.muhash.clone();
    const daa = gd.daaScore;
    const spCb = this.blocks.get(sp).txs[0];
    this._applyTx(view, mh, spCb, daa, true);
    // Catraca do pool privado (ZIP-209 do Zcash): saldo total dentro do pool privado,
    // contado pelos valores PÚBLICOS que cruzam a fronteira (blindar, desblindar e
    // recompensas pagas em endereço privado). Nunca pode ficar negativo: moedas
    // privadas forjadas (bug ou computador quântico) não conseguem sair do pool.
    let shielded = (spAcc.shielded ?? 0n) + (spAcc.cbShielded ?? 0n);
    const accepted = [spCb.idHex];
    const seen = new Set(accepted);
    const fees = new Map();
    let nameFees = 0n; // taxas de nomes (@nome): vão inteiras para o Fundo de Segurança
    const order = [sp, ...gd.mergesetAsc];
    for (const x of order) {
      let f = 0n;
      const txs = this.blocks.get(x).txs;
      for (let i = 1; i < txs.length; i++) {
        const tx = txs[i], id = tx.idHex;
        if (seen.has(id)) continue;
        let r;
        try { r = validateTxInContext(tx, view, daa, p); }
        catch (e) { if (e instanceof TxRuleError) continue; throw e; }
        const delta = shieldedDelta(tx, r.tIn);
        if (shielded + delta < 0n) continue; // violaria a catraca: transação ignorada
        shielded += delta;
        this._applyTx(view, mh, tx, daa, false);
        seen.add(id); accepted.push(id);
        f += tx.fee - r.nameFee;
        nameFees += r.nameFee;
      }
      fees.set(x, f);
    }
    let minted = spAcc.minted, pool = spAcc.pool;
    const release = spAcc.pool / p.feePoolDecay;
    const reds = new Set(gd.mergesetReds);
    const blueRewards = [];
    let redReward = 0n;
    for (const x of order) {
      if (x === this.genesisHash) continue; // o gênesis não tem recompensa: zero pré-mineração
      const sub = cappedSubsidy(this.store.gd.get(x).daaScore, minted, p);
      minted += sub;
      const fee = fees.get(x);
      const toPool = (fee * p.feePoolShareNum) / p.feePoolShareDen;
      pool += toPool - release;
      const reward = sub + (fee - toPool) + release;
      if (reds.has(x)) redReward += reward;
      else blueRewards.push({ hash: x, amount: reward });
    }
    pool += nameFees;
    let feeTotal = 0n;
    for (const f of fees.values()) feeTotal += f;
    return {
      view, muhash: mh.normalize(), accepted, acceptedSet: seen, acceptedRoot: merkleRoot(accepted.map(fromHex)),
      pool, minted, blueRewards, redReward, feeTotal, shielded, nameFees,
    };
  }

  _buildCoinbase(res, gd, parents, minerData, extra) {
    const recipients = res.blueRewards.map((r) => ({ addr: this._minerAddr(r.hash), amount: r.amount }));
    if (res.redReward > 0n) recipients.push({ addr: parseAddressData(minerData), amount: res.redReward });
    const tOut = [], sOut = [];
    let shieldedTotal = 0n;
    for (const { addr, amount } of recipients) {
      if (amount === 0n) continue;
      if (addr.type !== 's') tOut.push({ amount, lock: addr.data }); // transparente, multiassinatura ou quântico
      else {
        shieldedTotal += amount;
        // r público e determinístico (por saída): todos validam a mesma saída; o
        // minerador ainda recebe numa chave de uso único que só ele consegue gastar.
        const j = sOut.length;
        const r = hashToScalar('coinbase/r', ...parents.map(fromHex), gd.blueScore, j);
        const o = makeShieldedOutput({ A: addr.A, B: addr.B }, r, j, amount, true);
        sOut.push({ R: o.R.toBytes(), P: o.P.toBytes(), C: o.C.toBytes(), encAmount: o.encAmount, viewTag: o.viewTag });
      }
    }
    const cb = new Transaction({ tOut, sOut, payload: coinbasePayload(gd.blueScore, minerData, extra) });
    cb.shieldedTotal = shieldedTotal; // valor (público) que esta coinbase coloca no pool privado
    return cb;
  }

  // ------------------------------------------------------------- virtual
  resolveVirtual() {
    const p = this.params;
    const desc = (a, b) => -this.ghostdag.cmp(a, b);
    const tips = [...this.tips].sort(desc);
    const cand = [...tips], seen = new Set(cand);
    let selected = null;
    while (cand.length) {
      cand.sort(desc);
      const c = cand.shift();
      if (this.status.get(c) === 'chain') { selected = c; break; }
      for (const par of this.store.parents.get(c)) if (!seen.has(par)) { seen.add(par); cand.push(par); }
    }
    const vparents = [selected];
    for (const t of tips) {
      if (vparents.length >= p.maxParents) break;
      if (t === selected || this.status.get(t) !== 'chain') continue;
      if (vparents.some((v) => this.store.isAncestor(v, t) || this.store.isAncestor(t, v))) continue;
      vparents.push(t);
    }
    let gd;
    for (;;) {
      gd = this.ghostdag.run(vparents);
      const size = gd.mergesetBlues.length + gd.mergesetReds.length;
      const tooDeep = gd.mergesetAsc.some((x) => gd.blueScore - this.store.gd.get(x).blueScore > p.mergeDepth);
      if ((size <= p.mergesetSizeLimit && !tooDeep) || vparents.length === 1) break;
      vparents.pop();
    }
    if (gd.selectedParent !== selected) throw new Error('virtual: pai selecionado inconsistente');
    this._moveBase(selected);
    const acceptance = this._computeAcceptance(gd);
    const old = this.virtual;
    this.virtual = {
      parents: [...vparents].sort().map(fromHex),
      gd, acceptance, view: acceptance.view, version: ++this.virtualVersion,
      bits: requiredBits(p, this.store, this.headers, gd, this.powLimitBits),
      pmt: pastMedianTime(p, this.store, this.headers, gd),
    };
    this.emit('virtual', { old, virtual: this.virtual });
  }

  /** Modelo de bloco para mineração (o "virtual" com transações escolhidas). */
  buildTemplate(minerData, txs = [], extra = Buffer.alloc(0), now = Date.now()) {
    parseAddressData(minerData);
    const v = this.virtual;
    const cb = this._buildCoinbase(v.acceptance, v.gd, v.parents.map(toHex), minerData, extra);
    const all = [cb, ...txs];
    const header = new Header({
      version: 1, parents: v.parents, hashMerkleRoot: merkleRoot(all.map((t) => t.hash)),
      acceptedIdMerkleRoot: v.acceptance.acceptedRoot, utxoCommitment: v.acceptance.muhash.digest(),
      timestamp: Math.max(now, v.pmt), bits: v.bits, nonce: 0n,
      daaScore: v.gd.daaScore, blueScore: v.gd.blueScore, blueWork: v.gd.blueWork,
    });
    return new Block(header, all);
  }

  /** Modelo sobre pais arbitrários (testes/simulação de ramos concorrentes). */
  buildTemplateOn(parentHashes, minerData, txs = [], extra = Buffer.alloc(0), now = Date.now()) {
    const parents = [...parentHashes].sort();
    const gd = this.ghostdag.run(parents);
    this._moveBase(gd.selectedParent);
    const acc = this._computeAcceptance(gd);
    const cb = this._buildCoinbase(acc, gd, parents, minerData, extra);
    const all = [cb, ...txs];
    const header = new Header({
      version: 1, parents: parents.map(fromHex), hashMerkleRoot: merkleRoot(all.map((t) => t.hash)),
      acceptedIdMerkleRoot: acc.acceptedRoot, utxoCommitment: acc.muhash.digest(),
      timestamp: Math.max(now, pastMedianTime(this.params, this.store, this.headers, gd)),
      bits: requiredBits(this.params, this.store, this.headers, gd, this.powLimitBits), nonce: 0n,
      daaScore: gd.daaScore, blueScore: gd.blueScore, blueWork: gd.blueWork,
    });
    this._moveBase(this.virtual.gd.selectedParent);
    return new Block(header, all);
  }

  // ----------------------------------------------------------- consultas
  /** Situação de uma transação do ponto de vista do virtual. */
  txStatus(txidHex) {
    const v = this.virtual;
    if (v.acceptance.acceptedSet.has(txidHex)) {
      return { status: 'accepted', confirmations: 0, blueScore: v.gd.blueScore };
    }
    const h = this.txIndex.get(txidHex);
    if (h) {
      const bs = this.store.gd.get(h).blueScore;
      return { status: 'accepted', acceptingBlock: h, confirmations: v.gd.blueScore - bs, blueScore: bs };
    }
    return { status: 'unknown' };
  }

  /** Procura uma transação (não coinbase) em qualquer bloco conhecido. */
  /** Índice local de histórico por endereço transparente (saídas criadas e gastas). */
  _indexLocks(tx, id) {
    const add = (lockHex) => {
      let a = this.lockTxs.get(lockHex);
      if (!a) this.lockTxs.set(lockHex, (a = []));
      if (a[a.length - 1] !== id) { a.push(id); if (a.length > 5000) a.shift(); }
    };
    for (const o of tx.tOut) add(toHex(o.lock));
    for (const i of tx.tIn) {
      const prev = this.findTx(toHex(i.outpoint.txid));
      const o = prev?.tOut[i.outpoint.index];
      if (o) add(toHex(o.lock));
    }
  }

  findTx(txidHex) {
    const h = this.txBlock.get(txidHex);
    return h ? this.blocks.get(h).txs.find((t) => t.idHex === txidHex) ?? null : null;
  }

  utxosByLock(lockHex) {
    const v = this.virtual.view, out = [];
    const keys = new Set(this.utxo.byLock.get(lockHex) ?? []);
    for (const [k, e] of v.diff.addT) if (toHex(e.lock) === lockHex) keys.add(k);
    for (const k of keys) {
      const e = v.getT(k);
      if (e) out.push({ key: k, ...e });
    }
    return out;
  }

  supplyInfo() {
    const a = this.virtual.acceptance;
    // shieldedSupply: KRV dentro do pool privado (catraca) — público e auditável por qualquer um
    return { minted: a.minted, feePool: a.pool, shieldedSupply: a.shielded ?? 0n };
  }

  /** Cadeia selecionada do virtual (mais recente primeiro). */
  selectedChain(limit = 100) {
    const out = [];
    let h = this.virtual.gd.selectedParent;
    while (h && out.length < limit) { out.push(h); h = this.store.gd.get(h).selectedParent; }
    return out;
  }
}
