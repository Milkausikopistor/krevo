// LIGHT WALLET: uses Krevo without running a node, talking to a public light server that it does
// NOT trust. What changes compared to the full wallet:
//
//   • keys: none leaves the device — neither the spend key nor the view key (default mode);
//   • scanning: downloads only 35 bytes per private output (R, index and a 1-byte view tag) and
//     tests them right here; only ~1 in 256 outputs needs to be downloaded in full — and each one
//     comes mixed with 15 decoys, so the server does not know which ones are yours;
//   • spends: asks for "buckets" of key images (1/256 of the total), never for its own;
//   • verification: every coin received only counts in the balance after a PROOF — the txid
//     matches the content, the output is in the transaction, the transaction is in the Merkle tree
//     of the block that accepted it, and N blocks with proof of work sit on top (src/light/verify.js);
//   • optional (--delegar): delegated scanning — the server receives the VIEW key and finds your
//     payments (saves battery; it can then see what you receive, but it still cannot spend nor
//     see what you spend).
//
// Building, signing and picking transaction decoys stays the same as in the full wallet.

import { randomInt } from 'node:crypto';
import { fetchRetry } from '../node/rpcclient.js';
import { Wallet } from '../wallet/wallet.js';
import { Point } from '../crypto/secp256k1.js';
import { viewTag, scanShieldedOutput, decryptMemo } from '../crypto/stealth.js';
import { Transaction } from '../consensus/tx.js';
import { toHex, fromHex } from '../util/bytes.js';
import { verifyAcceptanceProof, headerWork } from './verify.js';
import { pqAvailable } from '../crypto/pq.js';

const PAD = 16;          // each requested output comes with 15 decoys
const COMPACT_BATCH = 5000;

/** HTTP client for the light server; counts the bytes received (to measure usage). */
export class LightClient {
  constructor(base) { this.base = String(base).replace(/\/+$/, ''); this.bytes = 0; this.requests = 0; }

  async _req(path, { method = 'GET', body, binary = false } = {}) {
    let r;
    try {
      r = await fetchRetry(this.base + path, { method, body: body ? JSON.stringify(body) : undefined, headers: body ? { 'content-type': 'application/json' } : {} });
    } catch (e) { throw new Error(`could not reach the light server at ${this.base} (${e.cause?.code ?? e.message})`); }
    const buf = Buffer.from(await r.arrayBuffer());
    this.bytes += buf.length;
    this.requests++;
    if (!r.ok) {
      let msg = buf.toString();
      try { msg = JSON.parse(msg).error ?? msg; } catch { /* texto puro */ }
      throw new Error(msg);
    }
    return binary ? buf : JSON.parse(buf.toString());
  }

  info() { return this._req('/v1/info'); }
  async compact(start, count) {
    const b = await this._req(`/v1/compact?start=${start}&count=${count}`, { binary: true });
    if (b.length < 20) throw new Error('malformed compact response');
    const total = b.readUInt32LE(0), st = b.readUInt32LE(4), n = b.readUInt32LE(8), daaScore = Number(b.readBigUInt64LE(12));
    if (st !== start || b.length !== 20 + 35 * n) throw new Error('malformed compact response');
    const entries = [];
    for (let k = 0; k < n; k++) {
      const o = 20 + 35 * k;
      entries.push({ index: st + k, R: b.subarray(o, o + 33), j: b[o + 33], viewTag: b[o + 34] });
    }
    return { total, start: st, count: n, daaScore, entries };
  }
  outputs(indices) { return this._req('/v1/outputs', { method: 'POST', body: { indices } }); }
  keyImageBucket(prefix) { return this._req(`/v1/keyimages/${prefix}`); }
  utxos(locks) { return this._req('/v1/utxos', { method: 'POST', body: { locks } }); }
  tx(txid) { return this._req(`/v1/tx/${txid}`); }
  proof(txid, depth) { return this._req(`/v1/proof/${txid}?depth=${depth}`); }
  broadcast(tx) { return this._req('/v1/broadcast', { method: 'POST', body: { tx } }); }
  fcmpAnchor() { return this._req('/v1/fcmp/anchor'); }
  fcmpPath(anchor, chunks) { return this._req('/v1/fcmp/path', { method: 'POST', body: { anchor, chunks } }); }
  name(n) { return this._req(`/v1/name/${encodeURIComponent(n)}`); }
  names(owners) { return this._req('/v1/names', { method: 'POST', body: { owners } }); }
  history(a) { return this._req(`/v1/history/${encodeURIComponent(a)}`); }
  scan(body) { return this._req('/v1/scan', { method: 'POST', body }); }
}

/**
 * Light wallet. `serverUrl` may hold SEVERAL servers separated by commas
 * ("https://a,https://b"): the wallet compares their answers and warns when they disagree.
 *   • private outputs: the servers' compact data are compared batch by batch; if they differ
 *     (one hid or changed something), the wallet scans both — what one hides, the other shows;
 *
 *   • transparent coins only one server shows: if one of them PROVES the coin was spent
 *     (the spending transaction + acceptance proof), it is spent; if nobody proves it, it
 *     counts — whoever hid it is recorded;
 *   • private spends: it is enough that one server knows the key image;
 *   • broadcasting: the transaction goes to all of them (harder to censor).
 */
export class LightWallet extends Wallet {
  constructor(file, data, params, serverUrl, password, opts = {}) {
    super(file, data, params, serverUrl, password, opts);
    this.servers = String(serverUrl).split(',').map((u) => u.trim()).filter(Boolean).map((u) => new LightClient(u));
    if (!this.servers.length) throw new Error('enter the light server');
    this.server = this.servers[0];
    this.tUnverified = [];
  }

  get light() { return (this.data.light ??= { verified: {}, fraud: {}, fraudBy: {}, maxWork: '0', delegate: false, discrepancies: [] }); }
  get proofDepth() { return this.data.light?.depth ?? this.params.lightProofDepth; }
  get serverUrls() { return this.servers.map((s) => s.base); }
  /** Bytes and requests summed over all servers. */
  get traffic() { return { bytes: this.servers.reduce((a, s) => a + s.bytes, 0), requests: this.servers.reduce((a, s) => a + s.requests, 0) }; }
  /** Disagreements between servers found in the last sync. */
  get discrepancies() { return [...(this.data.light?.discrepancies ?? [])]; }
  /** Turns delegated scanning on/off (the server receives the view key). */
  setDelegated(on) { this.light.delegate = !!on; this.save(); }

  /** The same operations the full wallet asks of a node, translated for the light server. */
  async call(method, p = {}) {
    const s = this.server;
    switch (method) {
      case 'getutxos': return s.utxos(p.locks);
      case 'getshieldedoutputs': {
        if (p.count) throw new Error('the light wallet does not download full outputs in bulk');
        const i = await s.info();
        return { total: i.outputs, daaScore: i.daaScore, outputs: [] };
      }
      case 'getshieldedbyindex': return s.outputs(p.indices);
      case 'getfcmpanchor': return s.fcmpAnchor();
      case 'getfcmppath': return s.fcmpPath(p.anchor, p.chunks);
      case 'getkeyimages': return this._keyImageStatus(p.keyImages);
      case 'sendrawtransaction': {
        // to ALL servers: it is enough that one accepts
        const rs = await Promise.allSettled(this.servers.map((x) => x.broadcast(p.tx)));
        const ok = rs.find((r) => r.status === 'fulfilled');
        if (ok) return ok.value;
        throw rs[0].reason;
      }
      case 'gettransaction': return s.tx(p.txid);
      case 'gettransactionstatus': {
        let last = { status: 'unknown' };
        for (const x of this.servers) {
          try {
            const t = await x.tx(p.txid);
            if (t.status === 'accepted') return { status: 'accepted', confirmations: t.confirmations };
            last = { status: t.status };
          } catch (e) { if (!/unknown/.test(e.message) && this.servers.length === 1) throw e; }
        }
        return last;
      }
      case 'resolvename': return s.name(p.name);
      case 'listnames': return s.names(p.owners);
      case 'getaddresshistory': return s.history(p.address);
      case 'getinfo': {
        const i = await s.info();
        return { network: i.network, virtual: { daaScore: i.daaScore, blueScore: i.blueScore }, shieldedOutputs: i.outputs };
      }
      default: throw new Error(`"${method}" is not available in the light wallet`);
    }
  }

  /** Key images by prefix buckets, on all servers (it is enough that one knows the spend). */
  async _keyImageStatus(kis, notes = null) {
    const res = new Map(kis.map((k) => [k, { spentBy: [], mempool: false }]));
    const active = this._active ?? this.servers, lagging = this._lagging ?? new Set();
    for (const [n, srv] of active.entries()) {
      for (const prefix of new Set(kis.map((k) => k.slice(0, 2)))) {
        let b;
        try { b = await srv.keyImageBucket(prefix); } catch { continue; }
        const spent = new Set(b.spent), mem = new Set(b.mempool);
        for (const k of kis) if (k.startsWith(prefix)) { const r = res.get(k); if (spent.has(k)) r.spentBy.push(n); if (mem.has(k)) r.mempool = true; }
      }
    }
    return kis.map((k) => {
      const r = res.get(k);
      if (notes && r.spentBy.length && r.spentBy.length < active.length && !lagging.size) {
        notes.push(`the servers disagree on whether a private coin was already spent (${active.filter((_, i) => !r.spentBy.includes(i)).map((x) => x.base).join(', ')} says it was not) — considered spent`);
      }
      return { keyImage: k, spent: r.spentBy.length > 0, inMempool: r.mempool };
    });
  }

  /** Candidates of a range, tested HERE by the view tag. */
  _testCompact(entries, srvIndex, out) {
    const ok = [], Rs = [];
    for (const e of entries) {
      try { Rs.push(Point.fromBytes(e.R)); ok.push(e); } catch { /* invalid point: not ours */ }
    }
    const sss = this.keys.vault.sharedMany(Rs); // a·R computed in the vault, in a batch
    ok.forEach((e, n) => { if (viewTag(sss[n], e.j) === e.viewTag) out.push({ srv: srvIndex, index: e.index }); });
  }

  /** Scans [start, total of each server); compares the batches between servers. */
  async _localCandidates(start, totals, notes) {
    const out = [];
    const common = Math.min(...totals);
    let diverged = false;
    for (let i = start; i < common;) {
      const n = Math.min(COMPACT_BATCH, common - i);
      const batches = await Promise.all(this._active.map((s) => s.compact(i, n)));
      const eq = (e, f) => !!e && !!f && e.j === f.j && e.viewTag === f.viewTag && Buffer.compare(e.R, f.R) === 0;
      const same = batches.every((b) => b.count === batches[0].count && b.entries.every((e, k) => eq(e, batches[0].entries[k])));
      if (same) this._testCompact(batches[0].entries, 0, out);
      else {
        let k = 0;
        while (k < n && batches.every((b) => eq(b.entries[k], batches[0].entries[k]))) k++;
        if (!diverged) notes.push(`the servers show DIFFERENT private outputs from position ${i + k} on — one of them hid or altered data; the wallet checked both`);
        diverged = true;
        batches.forEach((b, s) => this._testCompact(b.entries, s, out));
      }
      if (!batches[0].count) break;
      i += batches[0].count;
    }
    // what only the servers that are further ahead already have
    for (const [s, srv] of this._active.entries()) {
      for (let i = Math.max(start, common); i < totals[s];) {
        const c = await srv.compact(i, Math.min(COMPACT_BATCH, totals[s] - i));
        this._testCompact(c.entries, s, out);
        if (!c.count) break;
        i += c.count;
      }
    }
    return out;
  }

  /** Delegated scanning (first server only): it receives the view key. */
  async _delegatedCandidates(start, total) {
    const out = [];
    for (let i = start; i < total; i += 20_000) {
      const r = await this.server.scan({ viewKey: this.keys.viewKey(this.params), start: i, count: Math.min(20_000, total - i), subaddresses: this.subCount + 50 });
      out.push(...r.matches.map((index) => ({ srv: 0, index })));
    }
    return out;
  }

  /** Downloads the requested outputs from each server, mixed with decoys (PAD − 1 per real output). */
  async _fetchPadded(cands, totals) {
    const map = new Map();
    for (const [s, srv] of this._active.entries()) {
      const mine = cands.filter((c) => c.srv === s).map((c) => c.index);
      if (!mine.length) continue;
      const want = new Set(mine);
      for (let k0 = 0; k0 < mine.length; k0++) {
        for (let k = 0, tries = 0; k < PAD - 1 && tries < PAD * 4; tries++) {
          const d = randomInt(totals[s]);
          if (!want.has(d)) { want.add(d); k++; }
        }
      }
      const all = [...want].sort(() => Math.random() - 0.5);
      for (let k = 0; k < all.length; k += 512) {
        const r = await srv.outputs(all.slice(k, k + 512));
        for (const e of r.outputs) map.set(`${s}:${e.index}`, e);
      }
    }
    return map;
  }

  /**
   * Proves that output `key` (txid:index) exists and was accepted by the network, trying each
   * server. check(tx, index) checks the content. "Not enough blocks yet" only postpones; false data
   * (txid, content, Merkle, PoW) is recorded as fraud by that server.
   */
  async _verifyOutput(key, check) {
    const L = this.light;
    if (L.verified[key]) return true;
    const [txid, ix] = key.split(':');
    L.fraudBy ??= {};
    for (const srv of this._active ?? this.servers) {
      if ((L.fraudBy[txid] ?? []).includes(srv.base)) continue;
      const flag = (why) => { L.fraud[txid] = why; (L.fraudBy[txid] ??= []).push(srv.base); };
      let t, proof, tx;
      try { t = await srv.tx(txid); } catch { continue; }
      try { tx = Transaction.deserialize(fromHex(t.tx)); } catch { flag('unreadable transaction'); continue; }
      if (tx.idHex !== txid) { flag('the transaction content does not match the txid'); continue; }
      if (!check(tx, Number(ix))) { flag('the reported output does not exist in that transaction'); continue; }
      try { proof = await srv.proof(txid, this.proofDepth); } catch { continue; }
      if ((proof.chain?.length ?? 0) < this.proofDepth) continue;
      try {
        const r = verifyAcceptanceProof(txid, proof, { minDepth: this.proofDepth, minWork: BigInt(L.maxWork) / 4n });
        if (r.maxWork > BigInt(L.maxWork)) L.maxWork = r.maxWork.toString();
        L.verified[key] = { block: r.block, depth: r.depth };
        return true;
      } catch (e) { flag(e.message); }
    }
    return false;
  }

  /** Does any server PROVE that this transparent coin was spent? (spending transaction + proof) */
  async _spendProven(u) {
    const address = u.kind === 'q' ? this.qAddress : this.tAddress;
    for (const srv of this._active) {
      let h;
      try { h = await srv.history(address); } catch { continue; }
      for (const txid of (h.txids ?? []).slice(0, 100)) {
        let t;
        try { t = await srv.tx(txid); } catch { continue; }
        const tx = Transaction.deserialize(fromHex(t.tx));
        if (tx.idHex !== txid || !tx.tIn.some((i) => `${toHex(i.outpoint.txid)}:${i.outpoint.index}` === u.outpoint)) continue;
        if (await this._verifyOutput(`${txid}:spend`, () => true)) return srv.base;
      }
    }
    return null;
  }

  /** Warnings about false data received (txid → reason). */
  get fraudReports() { return { ...(this.data.light?.fraud ?? {}) }; }

  async sync() {
    const L = this.light, notes = [];
    // 0) who is online, on the right network, with a tip that has valid PoW
    const infos = await Promise.all(this.servers.map((s) => s.info().catch((e) => ({ error: e.message }))));
    const up = [];
    infos.forEach((info, n) => {
      const srv = this.servers[n];
      if (info.error) { if (this.servers.length > 1) notes.push(`server ${srv.base} is offline (${info.error})`); return; }
      if (info.network !== this.params.name) throw new Error(`the server ${srv.base} is on the ${info.network} network, not ${this.params.name}`);
      const tip = headerWork(info.tip.header);
      if (tip.work > BigInt(L.maxWork)) L.maxWork = tip.work.toString();
      up.push({ srv, info });
    });
    if (!up.length) throw new Error(infos[0].error ?? 'no light server answered');
    this._active = up.map((x) => x.srv);
    this.server = this._active[0];
    const top = Math.max(...up.map((x) => x.info.daaScore));
    const lagTol = this.params.bps * 120;
    this._lagging = new Set();
    up.forEach((x, n) => { if (top - x.info.daaScore > lagTol) { this._lagging.add(n); notes.push(`server ${x.srv.base} is behind (${Math.round((top - x.info.daaScore) / this.params.bps)} s)`); } });
    this.data.daa = top;
    const tips = up.map((x) => x.info.daaScore);

    // 1) transparent coins: union of the answers, checking what only one server shows
    const tLock = toHex(this.keys.tKey(0).lock), qLock = pqAvailable() ? toHex(this.keys.qKey(0).lock) : null;
    const locks = qLock ? [tLock, qLock] : [tLock];
    const lists = await Promise.all(this._active.map((s) => s.utxos(locks).then((r) => r.utxos).catch(() => null)));
    const seen = new Map();
    lists.forEach((list, n) => {
      for (const u of list ?? []) {
        const e = seen.get(u.outpoint) ?? { u: { ...u, kind: u.lock === qLock ? 'q' : 't' }, by: new Set() };
        e.by.add(n);
        if (u.inMempool) e.u.inMempool = true;
        seen.set(u.outpoint, e);
      }
    });
    const all = [];
    for (const { u, by } of seen.values()) {
      const missing = this._active.map((_, n) => n).filter((n) => !by.has(n) && lists[n] !== null);
      // it is only "lag" if the tip of the server that does not show the coin is BEFORE the block
      // that created it (~1 s tolerance); otherwise someone is hiding or inventing
      const explainedByLag = missing.every((n) => tips[n] < u.daa + Math.ceil(this.params.bps));
      if (missing.length && !explainedByLag) {
        const spentBy = await this._spendProven(u);
        if (spentBy) { notes.push(`${[...by].map((n) => this._active[n].base).join(', ')} showed as available a coin that was already spent (the wallet has the PROOF of the spend) — ignored`); continue; }
        notes.push(`${missing.map((n) => this._active[n].base).join(', ')} hid a transparent coin of ${u.amount} grains (nobody proved it was spent) — it counts`);
      }
      all.push(u);
    }

    // 2) private outputs: candidates by view tag (comparing servers), then the full ones
    const LOOKAHEAD = 50;
    let scanKeys = this.keys.scanKeysFor(this.subCount + LOOKAHEAD);
    const totals = up.map((x) => x.info.outputs);
    const maxT = Math.max(...totals);
    up.forEach((x, n) => {
      if (totals[n] < maxT && top - x.info.daaScore <= Math.ceil(this.params.bps)) {
        notes.push(`server ${x.srv.base} shows ${maxT - totals[n]} fewer private output(s) with the network at the same point — it hid data; the wallet used the other one`);
      }
    });
    const start = Math.max(0, Math.min(this.data.sScanned ?? 0, ...totals) - 200);
    const owned = new Map(this.data.sOwned.filter((o) => o.index < start).map((o) => [o.outpoint, o]));
    const cands = L.delegate ? await this._delegatedCandidates(start, totals[0]) : await this._localCandidates(start, totals, notes);
    const full = await this._fetchPadded(cands, totals);
    for (const c of cands) {
      const e = full.get(`${c.srv}:${c.index}`);
      if (!e || owned.has(e.outpoint)) continue;
      const o = { P: Point.fromBytes(fromHex(e.P)), C: Point.fromBytes(fromHex(e.C)), encAmount: fromHex(e.encAmount), viewTag: e.viewTag };
      const got = scanShieldedOutput(scanKeys, Point.fromBytes(fromHex(e.R)), e.j, o);
      if (!got) continue; // view tag false positive (expected: ~1 in 256)
      if (got.index >= this.subCount) {
        while (this.subCount <= got.index) (this.data.subaddresses ??= []).push({ label: '', created: Date.now(), recovered: true });
        scanKeys = this.keys.scanKeysFor(this.subCount + LOOKAHEAD);
      }
      const memo = e.memo ? decryptMemo(fromHex(e.memo), got.ss, e.j) : null;
      owned.set(e.outpoint, {
        index: e.index, outpoint: e.outpoint, amount: got.v.toString(), mask: got.x.toString(), k: got.k.toString(16),
        P: e.P, C: e.C, daa: e.daa, coinbase: e.coinbase, keyImage: toHex(this.keys.spender(got.k, got.index).keyImage(o.P).toBytes()),
        memo: memo || null, sub: got.index,
      });
    }
    const ownedList = [...owned.values()].sort((a, b) => a.index - b.index);
    this.data.sScanned = Math.min(...totals);

    // 3) what was already spent (by key-image buckets, on all servers)
    if (ownedList.length) {
      const st = await this._keyImageStatus(ownedList.map((o) => o.keyImage), notes);
      st.forEach((x, n) => { ownedList[n].spent = x.spent; ownedList[n].pending = x.inMempool; });
    }

    // 4) proofs: only what was proven counts in the balance (and can be spent)
    for (const o of ownedList) {
      if (o.spent) continue;
      o.unverified = !(await this._verifyOutput(o.outpoint, (tx, ix) => {
        const so = tx.sOut[ix - tx.tOut.length];
        return !!so && toHex(so.P) === o.P && toHex(so.C) === o.C;
      }));
    }
    const verified = [], unverified = [];
    for (const u of all) {
      const ok = await this._verifyOutput(u.outpoint, (tx, ix) => {
        const to = tx.tOut[ix];
        return !!to && BigInt(to.amount) === BigInt(u.amount) && toHex(to.lock) === u.lock && (u.coinbase === tx.isCoinbase());
      });
      (ok ? verified : unverified).push(u);
    }
    this.tUtxos = verified;
    this.tUnverified = unverified;
    this.data.sOwned = ownedList;
    L.discrepancies = [...new Set(notes)];
    this.save();
    return { candidates: cands.length, ...this.traffic, servers: this._active.length, discrepancies: L.discrepancies };
  }
}
