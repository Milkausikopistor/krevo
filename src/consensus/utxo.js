// UTXO state: three sets.
//   T  — unspent transparent outputs (removed when spent)
//   S  — private outputs (never removed: nobody knows which ones were spent!)
//   KI — key images already used (prevents double spending of private outputs)
// plus the curve tree over ALL private outputs, in global order (for full-chain membership
// proofs — see src/fcmp/tree.js).
// The state is materialized at ONE chain block (the "base") and moves along the chain by
// applying/reverting diffs — that is how reorganizations are handled.

import { Writer, toHex } from '../util/bytes.js';
import { parseOutpointKey } from './tx.js';
import { nameOfLock } from './names.js';
import { CurveTree } from '../fcmp/tree.js';

export function encodeTEntry(key, e) {
  const { txid, index } = parseOutpointKey(key);
  return new Writer().u8(0x54).bytes(txid, 32).u32(index).u64(e.amount).varbytes(e.lock)
    .u64(e.daa).u8(e.coinbase ? 1 : 0).done();
}
export function encodeSEntry(key, e) {
  const { txid, index } = parseOutpointKey(key);
  return new Writer().u8(0x53).bytes(txid, 32).u32(index).bytes(e.P, 33).bytes(e.C, 33)
    .bytes(e.encAmount, 8).u8(e.viewTag).bytes(e.R, 33).u32(e.j).u64(e.daa).u8(e.coinbase ? 1 : 0).done();
}
export const encodeKI = (kiHex) => Buffer.concat([Buffer.from([0x4b]), Buffer.from(kiHex, 'hex')]);

export class UtxoDiff {
  constructor() {
    this.addT = new Map(); this.remT = new Map();
    this.addS = []; this.addSMap = new Map();
    this.addKI = []; this.addKISet = new Set();
    this.names = new Map();         // name → Set(keys) of records created in this diff
  }
}

/** Materialized state. */
export class UtxoSet {
  constructor(fcmpBranch = 256) {
    this.t = new Map(); this.s = new Map(); this.ki = new Set();
    this.sList = [];                 // global order of private outputs (= tree leaves)
    this.tree = new CurveTree(fcmpBranch, (i) => { const k = this.sList[i], e = this.s.get(k); return { key: k, P: e.P, C: e.C }; });
    this.byLock = new Map();         // index: lock (hex) → Set(keys) — for wallets
    this.byName = new Map();         // index: name → Set(keys) of records (@name) — consensus rule
  }
  _idxAdd(key, e) {
    const l = toHex(e.lock);
    let s = this.byLock.get(l);
    if (!s) this.byLock.set(l, (s = new Set()));
    s.add(key);
    const n = nameOfLock(e.lock);
    if (n) { let ns = this.byName.get(n); if (!ns) this.byName.set(n, (ns = new Set())); ns.add(key); }
  }
  _idxDel(key, e) {
    const l = toHex(e.lock), s = this.byLock.get(l);
    if (s) { s.delete(key); if (!s.size) this.byLock.delete(l); }
    const n = nameOfLock(e.lock), ns = n && this.byName.get(n);
    if (ns) { ns.delete(key); if (!ns.size) this.byName.delete(n); }
  }
  apply(d) {
    for (const [k, e] of d.remT) { this.t.delete(k); this._idxDel(k, e); }
    for (const [k, e] of d.addT) { this.t.set(k, e); this._idxAdd(k, e); }
    for (const [k, e] of d.addS) { this.s.set(k, e); this.sList.push(k); }
    for (const ki of d.addKI) this.ki.add(ki);
  }
  revert(d) {
    for (const ki of d.addKI) this.ki.delete(ki);
    for (let i = d.addS.length - 1; i >= 0; i--) {
      const [k] = d.addS[i];
      this.s.delete(k);
      const last = this.sList.pop();
      if (last !== k) throw new Error('inconsistent private output order');
    }
    if (d.addS.length) this.tree.truncate(this.sList.length);
    for (const [k, e] of d.addT) { this.t.delete(k); this._idxDel(k, e); }
    for (const [k, e] of d.remT) { this.t.set(k, e); this._idxAdd(k, e); }
  }
}

/** View = base + diff under construction. Used to validate transactions in sequence. */
export class UtxoView {
  constructor(base, diff = new UtxoDiff()) { this.base = base; this.diff = diff; }
  getT(k) {
    const a = this.diff.addT.get(k);
    if (a) return a;
    if (this.diff.remT.has(k)) return undefined;
    return this.base.t.get(k);
  }
  getS(k) { return this.diff.addSMap.get(k) ?? this.base.s.get(k); }
  hasKI(ki) { return this.diff.addKISet.has(ki) || this.base.ki.has(ki); }
  spendT(k, e) {
    if (this.diff.addT.has(k)) this.diff.addT.delete(k);
    else this.diff.remT.set(k, e);
  }
  addT(k, e) {
    this.diff.addT.set(k, e);
    const n = nameOfLock(e.lock);
    if (n) { let s = this.diff.names.get(n); if (!s) this.diff.names.set(n, (s = new Set())); s.add(k); }
  }
  /** (Unspent) records of a name: [{ key, e }]. Includes expired ones — the rule decides. */
  nameEntries(name) {
    const keys = new Set([...(this.base.byName.get(name) ?? []), ...(this.diff.names.get(name) ?? [])]);
    const out = [];
    for (const key of keys) { const e = this.getT(key); if (e) out.push({ key, e }); }
    return out;
  }
  /** Every name with some unspent record. */
  allNames() { return new Set([...this.base.byName.keys(), ...this.diff.names.keys()]); }
  addS(k, e) { this.diff.addS.push([k, e]); this.diff.addSMap.set(k, e); }
  addKI(ki) { this.diff.addKI.push(ki); this.diff.addKISet.add(ki); }
  get sCount() { return this.base.sList.length + this.diff.addS.length; }
  sAt(i) {
    const n = this.base.sList.length;
    if (i < n) return this.base.sList[i];
    const d = this.diff.addS[i - n];
    return d ? d[0] : undefined;
  }
}
