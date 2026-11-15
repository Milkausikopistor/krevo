// Blocks and headers. Each block points to SEVERAL parents (every DAG tip the miner knew
// about) — that is what makes the BlockDAG parallel.

import { H } from '../crypto/hash.js';
import { Writer, Reader, toHex, ZERO32, bytesToBigBE, bigToBytesBE } from '../util/bytes.js';
import { Transaction } from './tx.js';

export class Header {
  constructor(f = {}) {
    this.version = f.version ?? 1;
    this.parents = f.parents ?? [];             // Buffer[32]
    this.hashMerkleRoot = f.hashMerkleRoot ?? ZERO32;
    this.acceptedIdMerkleRoot = f.acceptedIdMerkleRoot ?? ZERO32;
    this.utxoCommitment = f.utxoCommitment ?? ZERO32;
    this.timestamp = f.timestamp ?? 0;          // ms
    this.bits = f.bits ?? 0;
    this.nonce = f.nonce ?? 0n;
    this.daaScore = f.daaScore ?? 0;
    this.blueScore = f.blueScore ?? 0;
    this.blueWork = f.blueWork ?? 0n;
  }
  serialize(forPow = false) {
    const w = new Writer();
    w.u16(this.version);
    w.varint(this.parents.length);
    for (const p of this.parents) w.bytes(p, 32);
    w.bytes(this.hashMerkleRoot, 32);
    w.bytes(this.acceptedIdMerkleRoot, 32);
    w.bytes(this.utxoCommitment, 32);
    w.u64(forPow ? 0 : this.timestamp);
    w.u32(this.bits);
    w.u64(forPow ? 0n : this.nonce);
    w.u64(this.daaScore);
    w.u64(this.blueScore);
    const bw = this.blueWork === 0n ? Buffer.alloc(0) : bigToBytesBE(this.blueWork, Math.ceil(this.blueWork.toString(16).length / 2));
    w.varbytes(bw);
    return w.done();
  }
  static read(r) {
    const h = new Header();
    h.version = r.u16();
    const n = r.varint(64);
    for (let i = 0; i < n; i++) h.parents.push(r.bytes(32));
    h.hashMerkleRoot = r.bytes(32);
    h.acceptedIdMerkleRoot = r.bytes(32);
    h.utxoCommitment = r.bytes(32);
    h.timestamp = Number(r.u64());
    h.bits = r.u32();
    h.nonce = r.u64();
    h.daaScore = Number(r.u64());
    h.blueScore = Number(r.u64());
    const bw = r.varbytes(64);
    if (bw.length && bw[0] === 0) throw new Error('non-canonical blueWork');
    h.blueWork = bytesToBigBE(bw);
    return h;
  }
  get hash() { return H('block/hash', this.serialize()); }
  get hashHex() { return toHex(this.hash); }
  /** Pre-PoW hash: excludes timestamp and nonce (the PoW matrix is fixed per template). */
  prePowHash() { return H('block/prepow', this.serialize(true)); }
}

export class Block {
  constructor(header, txs) { this.header = header; this.txs = txs; this._hash = null; }
  serialize() {
    const w = new Writer();
    w.bytes(this.header.serialize());
    w.varint(this.txs.length);
    for (const tx of this.txs) w.varbytes(tx.serialize());
    return w.done();
  }
  static deserialize(buf) {
    const r = new Reader(buf);
    const header = Header.read(r);
    const n = r.varint(100_000);
    const txs = [];
    for (let i = 0; i < n; i++) txs.push(Transaction.deserialize(r.varbytes(4_000_000)));
    r.end();
    return new Block(header, txs);
  }
  get hash() { return (this._hash ??= this.header.hash); }
  get hashHex() { return toHex(this.hash); }
}

/** Merkle root without duplicating the last node (avoids Bitcoin's CVE-2012-2459). */
export function merkleRoot(hashes) {
  if (hashes.length === 0) return ZERO32;
  let level = hashes;
  while (level.length > 1) {
    const next = [];
    for (let i = 0; i < level.length; i += 2) {
      next.push(i + 1 < level.length ? H('merkle', level[i], level[i + 1]) : level[i]);
    }
    level = next;
  }
  return H('merkle/root', level[0], hashes.length);
}

/**
 * Inclusion proof (light wallets): the "siblings" at each level up to the root.
 * { index, count, path: [hex | null] } — null when the node goes up alone (last odd one).
 */
export function merkleProof(hashes, index) {
  if (index < 0 || index >= hashes.length) throw new Error('index outside the tree');
  const path = [];
  let level = hashes, i = index;
  while (level.length > 1) {
    const sib = i ^ 1;
    path.push(sib < level.length ? toHex(level[sib]) : null);
    const next = [];
    for (let k = 0; k < level.length; k += 2) next.push(k + 1 < level.length ? H('merkle', level[k], level[k + 1]) : level[k]);
    level = next;
    i >>= 1;
  }
  return { index, count: hashes.length, path };
}

/** Checks a merkleProof proof against the root. */
export function verifyMerkleProof(leaf, proof, root) {
  const { index, count, path } = proof;
  if (!Number.isInteger(index) || !Number.isInteger(count) || index < 0 || index >= count) return false;
  let h = Buffer.from(leaf), i = index, n = count;
  for (const sib of path) {
    if (n <= 1) return false;
    const hasSib = (i ^ 1) < n;
    if (hasSib !== (sib !== null)) return false;
    if (hasSib) {
      const s = Buffer.from(sib, 'hex');
      h = i & 1 ? H('merkle', s, h) : H('merkle', h, s);
    }
    i >>= 1;
    n = Math.ceil(n / 2);
  }
  if (n !== 1) return false;
  return H('merkle/root', h, count).equals(root);
}
