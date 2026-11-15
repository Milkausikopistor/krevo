// Peer-to-peer network (TCP). Messages: [magic u32][length u32][JSON].
//
// DAG synchronization: on connecting, each node asks for the block inventory
// from its blue score; blocks with unknown parents stay as orphans and
// the parents are requested from the same peer.
//
// Network privacy — Dandelion++ (simplified): a new transaction first
// "walks along the stem" (it is relayed to ONE peer at a time) and only then "fluffs"
// (it is announced to everyone). So whoever watches the network does not learn the origin IP.

import net from 'node:net';
import { randomBytes } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { Block } from '../consensus/block.js';
import { Transaction } from '../consensus/tx.js';
import { toHex, fromHex } from '../util/bytes.js';

const PROTOCOL_VERSION = 1;
const MAX_MSG = 8 * 1024 * 1024;
const STEM_PROBABILITY = 0.9;

export class P2P extends EventEmitter {
  constructor(node, { port, host = '0.0.0.0', peers = [], maxPeers = 24, log = () => {} }) {
    super();
    this.node = node;
    this.params = node.params;
    this.port = port; this.host = host;
    this.seeds = peers;
    this.maxPeers = maxPeers;
    this.log = log;
    this.peers = new Set();
    this.nonce = toHex(randomBytes(8));
    this.known = new Set(peers);
    this.requested = new Map();     // hash → request timestamp
    this.stemPeer = null;
    this.stemSince = 0;
    this.embargo = new Map();       // txid → timer
  }

  start() {
    this.server = net.createServer((s) => this._attach(s, false, `${s.remoteAddress}:${s.remotePort}`));
    this.server.on('error', (e) => this.log('p2p error: ' + e.message));
    this.server.listen(this.port, this.host);
    for (const a of this.seeds) this.connect(a);
    this.timer = setInterval(() => this._maintenance(), 5000);
  }
  stop() {
    clearInterval(this.timer);
    for (const t of this.embargo.values()) clearTimeout(t);
    for (const p of this.peers) p.sock.destroy();
    this.server?.close();
  }

  connect(addr) {
    if ([...this.peers].some((p) => p.addr === addr)) return;
    const [host, port] = addr.split(':');
    const s = net.connect(Number(port), host);
    s.on('error', () => {});
    s.on('connect', () => this._attach(s, true, addr));
  }

  _attach(sock, outbound, addr) {
    if (this.peers.size >= this.maxPeers) { sock.destroy(); return; }
    const peer = { sock, outbound, addr, buf: Buffer.alloc(0), ready: false, score: 0, listen: null };
    this.peers.add(peer);
    sock.setNoDelay(true);
    sock.on('data', (d) => this._onData(peer, d));
    sock.on('close', () => { this.peers.delete(peer); if (this.stemPeer === peer) this.stemPeer = null; });
    sock.on('error', () => {});
    this.send(peer, {
      t: 'hello', version: PROTOCOL_VERSION, network: this.params.name, genesis: this.node.consensus.genesisHash,
      nonce: this.nonce, listen: this.port, blueScore: this.node.consensus.virtual.gd.blueScore,
    });
  }

  send(peer, msg) {
    const body = Buffer.from(JSON.stringify(msg));
    const head = Buffer.alloc(8);
    head.writeUInt32LE(this.params.p2pMagic, 0);
    head.writeUInt32LE(body.length, 4);
    peer.sock.write(Buffer.concat([head, body]));
  }
  broadcast(msg, except = null) {
    for (const p of this.peers) if (p.ready && p !== except) this.send(p, msg);
  }

  _onData(peer, data) {
    peer.buf = Buffer.concat([peer.buf, data]);
    while (peer.buf.length >= 8) {
      if (peer.buf.readUInt32LE(0) !== this.params.p2pMagic) return this._ban(peer, 'wrong magic');
      const len = peer.buf.readUInt32LE(4);
      if (len > MAX_MSG) return this._ban(peer, 'message too large');
      if (peer.buf.length < 8 + len) break;
      const body = peer.buf.subarray(8, 8 + len);
      peer.buf = peer.buf.subarray(8 + len);
      let msg;
      try { msg = JSON.parse(body.toString()); } catch { return this._ban(peer, 'invalid JSON'); }
      try { this._handle(peer, msg); } catch (e) { this._misbehave(peer, 10, e.message); }
    }
  }

  _misbehave(peer, n, why) {
    peer.score += n;
    if (peer.score >= 100) this._ban(peer, why);
  }
  _ban(peer, why) { this.log(`disconnecting ${peer.addr}: ${why}`); peer.sock.destroy(); this.peers.delete(peer); }

  _handle(peer, m) {
    if (!peer.ready && m.t !== 'hello') return;
    switch (m.t) {
      case 'hello': {
        if (m.nonce === this.nonce) return this._ban(peer, 'connection to itself');
        if (m.network !== this.params.name || m.genesis !== this.node.consensus.genesisHash) return this._ban(peer, 'different network');
        peer.ready = true;
        const host = peer.addr.split(':').slice(0, -1).join(':').replace('::ffff:', '');
        peer.listen = `${host}:${m.listen}`;
        this.known.add(peer.listen);
        this.log(`peer connected: ${peer.listen} (${peer.outbound ? 'outbound' : 'inbound'})`);
        const from = Math.max(0, this.node.consensus.virtual.gd.blueScore - 300);
        this.send(peer, { t: 'getdag', from });
        this.send(peer, { t: 'getaddr' });
        break;
      }
      case 'getdag': {
        const c = this.node.consensus;
        const hashes = [];
        for (const [h, gd] of c.store.gd) if (gd.blueScore >= m.from) hashes.push([gd.blueScore, h]);
        hashes.sort((a, b) => a[0] - b[0] || (a[1] < b[1] ? -1 : 1));
        for (let i = 0; i < hashes.length; i += 2000) {
          this.send(peer, { t: 'inv', blocks: hashes.slice(i, i + 2000).map((x) => x[1]) });
        }
        break;
      }
      case 'inv': {
        if (m.blocks) this.requestBlocks(peer, m.blocks);
        if (m.txs) {
          const want = m.txs.filter((id) => !this.node.mempool.txs.has(id) && !this._recentlyRequested(id));
          if (want.length) this.send(peer, { t: 'gettxs', txids: want.slice(0, 1000) });
        }
        break;
      }
      case 'getblocks': {
        for (const h of (m.hashes ?? []).slice(0, 1000)) {
          const b = this.node.consensus.blocks.get(h);
          if (b) this.send(peer, { t: 'block', data: toHex(b.serialize()) });
        }
        break;
      }
      case 'block': {
        const b = Block.deserialize(fromHex(m.data));
        this.requested.delete(b.hashHex);
        this.node.receiveBlock(b, peer);
        break;
      }
      case 'gettxs': {
        for (const id of (m.txids ?? []).slice(0, 1000)) {
          const e = this.node.mempool.txs.get(id);
          if (e) this.send(peer, { t: 'tx', data: toHex(e.tx.serialize()), stem: false });
        }
        break;
      }
      case 'tx': {
        const tx = Transaction.deserialize(fromHex(m.data));
        this.requested.delete(tx.idHex);
        this.receiveTx(tx, peer, !!m.stem);
        break;
      }
      case 'getaddr':
        this.send(peer, { t: 'addr', addrs: [...this.known].slice(0, 100) });
        break;
      case 'addr':
        for (const a of (m.addrs ?? []).slice(0, 100)) if (typeof a === 'string' && /^[\w.:-]+:\d+$/.test(a)) this.known.add(a);
        break;
      default:
        break;
    }
  }

  _recentlyRequested(h) {
    const t = this.requested.get(h);
    if (t && Date.now() - t < 10_000) return true;
    this.requested.set(h, Date.now());
    return false;
  }

  requestBlocks(peer, hashes) {
    const c = this.node.consensus;
    const want = hashes.filter((h) => !c.has(h) && !this.node.orphans.has(h) && !this._recentlyRequested(h));
    for (let i = 0; i < want.length; i += 500) this.send(peer, { t: 'getblocks', hashes: want.slice(i, i + 500) });
  }

  announceBlock(hash, except) { this.broadcast({ t: 'inv', blocks: [hash] }, except); }

  // ------------------------------------------------------- Dandelion++
  _pickStem(except) {
    const now = Date.now();
    const ok = [...this.peers].filter((p) => p.ready && p !== except);
    if (!this.stemPeer || !this.peers.has(this.stemPeer) || this.stemPeer === except || now - this.stemSince > 600_000) {
      this.stemPeer = ok.length ? ok[Math.floor(Math.random() * ok.length)] : null;
      this.stemSince = now;
    }
    return this.stemPeer && this.stemPeer !== except ? this.stemPeer : null;
  }

  /** Transaction created locally (RPC) or received from a peer. */
  receiveTx(tx, from, stem) {
    const id = tx.idHex;
    if (this.node.mempool.txs.has(id)) return { ok: true, txid: id, duplicate: true };
    if (stem) {
      try { this.node.mempool.check(tx); } catch (e) { if (from) this._misbehave(from, 5, e.message); return { ok: false, txid: id, reason: e.message }; }
      const next = Math.random() < STEM_PROBABILITY ? this._pickStem(from) : null;
      if (next) {
        this.send(next, { t: 'tx', data: toHex(tx.serialize()), stem: true });
        this.node.stem.set(id, { tx, at: Date.now() }); // remembered locally during the stem phase
        if (!this.embargo.has(id)) {
          // embargo: if nobody fluffs the transaction within a few seconds, we fluff it ourselves.
          this.embargo.set(id, setTimeout(() => { this.embargo.delete(id); this._fluff(tx, null); }, 2000 + Math.random() * 2000));
        }
        return { ok: true, txid: id, phase: 'haste' };
      }
    }
    return this._fluff(tx, from);
  }

  _fluff(tx, from) {
    const id = tx.idHex;
    this.node.stem.delete(id);
    const t = this.embargo.get(id);
    if (t) { clearTimeout(t); this.embargo.delete(id); }
    const r = this.node.mempool.add(tx);
    if (r.ok && !r.duplicate) {
      this.broadcast({ t: 'inv', txs: [id] }, from);
      this.node.emit('tx', tx);
    } else if (!r.ok && from) this._misbehave(from, 1, r.reason);
    return { ...r, phase: 'flor' };
  }

  _maintenance() {
    const outbound = [...this.peers].filter((p) => p.outbound).length;
    if (outbound < 8) {
      const connected = new Set([...this.peers].map((p) => p.listen ?? p.addr));
      const cand = [...this.known].filter((a) => !connected.has(a) && a !== `127.0.0.1:${this.port}`);
      for (const a of cand.slice(0, 8 - outbound)) this.connect(a);
    }
    const now = Date.now();
    for (const [h, t] of this.requested) if (now - t > 60_000) this.requested.delete(h);
  }
}
