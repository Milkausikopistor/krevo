// Full node: consensus + mempool + P2P + RPC + storage.
import { EventEmitter } from 'node:events';
import path from 'node:path';
import { Consensus } from '../consensus/consensus.js';
import { Mempool } from './mempool.js';
import { P2P } from './p2p.js';
import { RpcServer } from './rpc.js';
import { BlockFile } from './storage.js';

export class Node extends EventEmitter {
  constructor({ params, datadir, p2pPort, rpcPort, rpcHost = '127.0.0.1', peers = [], log = console.log, persist = true }) {
    super();
    this.params = params;
    this.log = log;
    this.consensus = new Consensus(params);
    this.mempool = new Mempool(this.consensus);
    this.orphans = new Map();     // hash → { block, missing:Set }
    this.waiting = new Map();     // missing parent → Set(orphan children)
    this.future = new Map();
    this.stem = new Map();        // transactions in Dandelion++'s stem phase (not yet in the mempool)
    this.storage = persist ? new BlockFile(path.join(datadir, params.name)) : null;
    this.p2p = new P2P(this, { port: p2pPort ?? params.defaultP2pPort, peers, log });
    this.rpc = new RpcServer(this, { port: rpcPort ?? params.defaultRpcPort, host: rpcHost });
    this.startedAt = Date.now();
    this.blockTimes = [];
    this.consensus.on('disqualified', ({ hash, reason }) => log(`block ${hash.slice(0, 12)} disqualified: ${reason}`));
  }

  async start() {
    if (this.storage) {
      let n = 0;
      const t = Date.now();
      for (const b of this.storage.readAll()) {
        const r = this.consensus.addBlock(b, { trusted: true });
        if (r.status === 'accepted') n++;
      }
      if (n) this.log(`${n} blocks reloaded from disk in ${((Date.now() - t) / 1000).toFixed(1)} s`);
    }
    await this.rpc.start();
    this.p2p.start();
    this.futureTimer = setInterval(() => this._retryFuture(), 1000);
    this.log(`Krevo ${this.params.name} | P2P :${this.p2p.port} | RPC http://${this.rpc.host}:${this.rpc.port} | genesis ${this.consensus.genesisHash.slice(0, 16)}…`);
  }

  async stop() {
    clearInterval(this.futureTimer);
    this.p2p.stop();
    await this.rpc.stop();
  }

  /** Block from the network or from RPC. */
  receiveBlock(block, peer = null) {
    const res = this.consensus.addBlock(block);
    switch (res.status) {
      case 'accepted':
        this._onAccepted(block, peer);
        this._resolveOrphans(res.hash);
        break;
      case 'orphan': {
        if (this.orphans.size > 50_000) break;
        this.orphans.set(res.hash, { block, missing: new Set(res.missing) });
        for (const m of res.missing) {
          if (!this.waiting.has(m)) this.waiting.set(m, new Set());
          this.waiting.get(m).add(res.hash);
        }
        if (peer) this.p2p.requestBlocks(peer, res.missing);
        break;
      }
      case 'future':
        this.future.set(res.hash, { block, peer });
        break;
      case 'invalid':
        this.log(`invalid block ${res.hash.slice(0, 12)}: ${res.reason}`);
        if (peer) this.p2p._misbehave(peer, 50, res.reason);
        break;
      default:
        break;
    }
    return res;
  }

  _onAccepted(block, peer) {
    this.storage?.append(block);
    this.p2p.announceBlock(block.hashHex, peer);
    const now = Date.now();
    this.blockTimes.push(now);
    while (this.blockTimes.length && now - this.blockTimes[0] > 60_000) this.blockTimes.shift();
    this.emit('block', block);
  }

  _resolveOrphans(hash) {
    const queue = [hash];
    while (queue.length) {
      const h = queue.shift();
      const kids = this.waiting.get(h);
      if (!kids) continue;
      this.waiting.delete(h);
      for (const k of kids) {
        const o = this.orphans.get(k);
        if (!o) continue;
        o.missing.delete(h);
        if (o.missing.size) continue;
        this.orphans.delete(k);
        const r = this.consensus.addBlock(o.block);
        if (r.status === 'accepted') { this._onAccepted(o.block, null); queue.push(k); }
      }
    }
  }

  _retryFuture() {
    for (const [h, { block, peer }] of this.future) {
      if (block.header.timestamp <= Date.now() + this.params.maxFutureMs) {
        this.future.delete(h);
        this.receiveBlock(block, peer);
      }
    }
  }

  /** Local transaction (wallet) → Dandelion++. */
  submitTx(tx) { return this.p2p.receiveTx(tx, null, true); }

  /** Inputs and key images already committed by transactions in the stem phase. */
  stemSpends() {
    const now = Date.now(), outs = new Set(), kis = new Set();
    for (const [id, e] of this.stem) {
      if (now - e.at > 60_000) { this.stem.delete(id); continue; }
      for (const i of e.tx.tIn) outs.add(i.outpoint.txid.toString('hex') + ':' + i.outpoint.index);
      for (const si of e.tx.sIn) kis.add(si.keyImage.toString('hex'));
    }
    return { outs, kis };
  }
}
