// Krevo consensus engine.
//
// Flow of a new block:
//  1. header: PoW, parents (antichain), GHOSTDAG, difficulty, timestamp, merge depth
//  2. body: well-formed coinbase, transactions valid in isolation, Merkle, mass
//  3. UTXO state: the block "accepts" the transactions of its mergeset, in consensus order,
//     on top of the selected parent's state. Conflicting transactions from parallel blocks
//     do not invalidate the block: the first in order wins, the others are ignored.
//     The UTXO commitment (MuHash) and the header's coinbase must match;
//     otherwise the block is "disqualified from the chain" (it stays in the DAG, without state).
//  4. "virtual": the hypothetical block that points to all tips. The virtual's state is the
//     current state of the network — the mempool validates against it.
//
// Rewards (no premine, no authority):
//  Each chain block pays, in its coinbase, every block of its mergeset:
//   blue     → subsidy + 1/2 of its fees + the Fund's release, to its miner
//   red      → the same amount goes to the miner of the block that merged it
//  The other half of the fees enters the "Security Fund", which is released gradually
//  (1/864,000 per block): this smooths miners' income, reduces the incentive for fee-driven
//  attacks and helps long-term security once emission ends.

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
    this.minerData = new Map();     // hash → miner address data
    this.minerParsed = new Map();
    this.status = new Map();        // 'chain' (valid state) | 'disq' (disqualified)
    this.acc = new Map();           // acceptance data of the blocks with a valid state
    this.invalid = new Map();       // hash → motivo
    this.tips = new Set();
    this.utxo = new UtxoSet(params.fcmpBranch);
    this.txIndex = new Map();       // txid → chain block that accepted it (base chain)
    this.txBlock = new Map();       // txid → first block that contains the transaction (local index, not consensus)
    this.lockTxs = new Map();       // transparent lock → txids that touch it (local index, for explorers)
    this.rewardIndex = new Map();   // block → { amount, paidBy, red } reward actually paid (local index, for pools)
    this.order = [];                // hashes in arrival order (local index)
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

  // ------------------------------------------------------------ input
  /**
   * Processes a block. Returns { status: 'accepted'|'known'|'orphan'|'future'|'invalid', ... }.
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
    if (h.version !== 1) fail('unknown header version');
    if (parents.length < 1 || parents.length > p.maxParents) fail('invalid number of parents');
    for (let i = 1; i < parents.length; i++) if (!(parents[i - 1] < parents[i])) fail('parents out of order or repeated');
    if (compactToTarget(h.bits) > compactToTarget(this.powLimitBits)) fail('target above the limit');
    if (!checkPow(h)) fail('insufficient proof of work');
    for (let i = 0; i < parents.length; i++) {
      for (let j = 0; j < parents.length; j++) {
        if (i !== j && this.store.isAncestor(parents[i], parents[j])) fail('parents do not form an antichain');
      }
    }
    const gd = this.ghostdag.run(parents);
    if (gd.mergesetBlues.length + gd.mergesetReds.length > p.mergesetSizeLimit) fail('mergeset too large');
    if (h.blueScore !== gd.blueScore || h.blueWork !== gd.blueWork || h.daaScore !== gd.daaScore) fail('header GHOSTDAG data does not match');
    if (h.bits !== requiredBits(p, this.store, this.headers, gd, this.powLimitBits)) fail('incorrect difficulty');
    if (h.timestamp < pastMedianTime(p, this.store, this.headers, gd)) fail('timestamp before the past median time');
    for (const x of gd.mergesetAsc) {
      if (gd.blueScore - this.store.gd.get(x).blueScore > p.mergeDepth) fail('block too old in the mergeset (merge depth limit)');
    }
    return gd;
  }

  _validateBody(block) {
    const p = this.params, txs = block.txs;
    if (txs.length < 1) fail('block without coinbase');
    const cb = txs[0];
    if (!cb.isCoinbase() || cb.version !== 1) fail('first transaction is not a coinbase');
    if (cb.fee !== 0n || cb.mass !== 0 || cb.rangeProof.length || cb.bindingSig) fail('malformed coinbase');
    if (cb.payload.length > p.maxCoinbasePayload) fail('coinbase payload too large');
    let pl;
    try { pl = parseCoinbasePayload(cb.payload); } catch { fail('invalid coinbase payload'); }
    if (pl.blueScore !== block.header.blueScore) fail('coinbase blue score does not match');
    let md;
    try { md = parseAddressData(pl.minerData); } catch { fail('invalid miner address'); }
    if (!['t', 's', 'm', 'q'].includes(md.type)) fail('invalid miner address (must be krv, krs, krq or multisig)');
    let mass = 0;
    const ids = new Set([cb.idHex]);
    for (let i = 1; i < txs.length; i++) {
      const tx = txs[i];
      if (tx.isCoinbase()) fail('extra coinbase');
      validateTxStateless(tx, p);
      if (ids.has(tx.idHex)) fail('transaction repeated in the block');
      ids.add(tx.idHex);
      mass += tx.mass;
    }
    if (mass > p.maxBlockMass) fail('block mass above the limit');
    if (!merkleRoot(txs.map((t) => t.hash)).equals(block.header.hashMerkleRoot)) fail('incorrect Merkle root');
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
      res = this.virtual.acceptance; // same parents as the current virtual → same acceptance
    } else {
      this._moveBase(gd.selectedParent);
      res = this._computeAcceptance(gd);
    }
    let reason = null, cbShielded = 0n;
    if (!h.utxoCommitment.equals(res.muhash.digest())) reason = 'incorrect UTXO commitment';
    else if (!h.acceptedIdMerkleRoot.equals(res.acceptedRoot)) reason = 'incorrect accepted-transactions root';
    else {
      const actual = block.txs[0];
      const extra = parseCoinbasePayload(actual.payload).extra;
      const expected = this._buildCoinbase(res, gd, this.store.parents.get(hash), this.minerData.get(hash), extra);
      if (!expected.serializeBody().equals(actual.serializeBody())) reason = 'coinbase does not match the rewards due';
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

  /** Moves the materialized state to block `target` by reverting/applying diffs. */
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
      if (!acc) throw new Error('chain block without state: ' + h);
      this.utxo.apply(acc.diff);
      for (const id of acc.accepted) this.txIndex.set(id, h);
      for (const r of acc.rewards ?? []) this.rewardIndex.set(r.hash, { amount: r.amount, paidBy: h, red: false });
      for (const r of acc.reds ?? []) this.rewardIndex.set(r, { amount: 0n, paidBy: h, red: true }); // a red block's reward goes to whoever merged it
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

  /** Acceptance of a block (or of the virtual) with this GHOSTDAG data. Precondition: base = selected parent. */
  _computeAcceptance(gd) {
    const p = this.params;
    const sp = gd.selectedParent;
    if (this.baseHash !== sp) throw new Error('base out of position');
    const spAcc = this.acc.get(sp);
    const view = new UtxoView(this.utxo);
    const mh = spAcc.muhash.clone();
    const daa = gd.daaScore;
    const spCb = this.blocks.get(sp).txs[0];
    this._applyTx(view, mh, spCb, daa, true);
    // Private-pool turnstile (Zcash's ZIP-209): total balance inside the private pool, counted
    // through the PUBLIC values that cross the border (shielding, unshielding and rewards paid
    // to private addresses). It can never go negative: forged private coins (a bug or a
    // quantum computer) cannot leave the pool.
    let shielded = (spAcc.shielded ?? 0n) + (spAcc.cbShielded ?? 0n);
    const accepted = [spCb.idHex];
    const seen = new Set(accepted);
    const fees = new Map();
    let nameFees = 0n; // name fees (@name): they all go to the Security Fund
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
        if (shielded + delta < 0n) continue; // would break the turnstile: transaction ignored
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
      if (x === this.genesisHash) continue; // the genesis has no reward: zero premine
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
      if (addr.type !== 's') tOut.push({ amount, lock: addr.data }); // transparent, multisig or quantum-safe
      else {
        shieldedTotal += amount;
        // public, deterministic r (per output): everyone validates the same output; the
        // miner still receives on a one-time key that only they can spend.
        const j = sOut.length;
        const r = hashToScalar('coinbase/r', ...parents.map(fromHex), gd.blueScore, j);
        const o = makeShieldedOutput({ A: addr.A, B: addr.B }, r, j, amount, true);
        sOut.push({ R: o.R.toBytes(), P: o.P.toBytes(), C: o.C.toBytes(), encAmount: o.encAmount, viewTag: o.viewTag });
      }
    }
    const cb = new Transaction({ tOut, sOut, payload: coinbasePayload(gd.blueScore, minerData, extra) });
    cb.shieldedTotal = shieldedTotal; // (public) amount this coinbase puts into the private pool
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
    if (gd.selectedParent !== selected) throw new Error('virtual: inconsistent selected parent');
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

  /** Block template for mining (the "virtual" with chosen transactions). */
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

  /** Template on arbitrary parents (tests/simulation of competing branches). */
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

  // ----------------------------------------------------------- queries
  /** State of a transaction from the virtual's point of view. */
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

  /** Looks up a transaction (not a coinbase) in any known block. */
  /** Local history index per transparent address (outputs created and spent). */
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
    // shieldedSupply: KRV inside the private pool (turnstile) — public and auditable by anyone
    return { minted: a.minted, feePool: a.pool, shieldedSupply: a.shielded ?? 0n };
  }

  /** Selected chain of the virtual (most recent first). */
  selectedChain(limit = 100) {
    const out = [];
    let h = this.virtual.gd.selectedParent;
    while (h && out.length < limit) { out.push(h); h = this.store.gd.get(h).selectedParent; }
    return out;
  }
}
