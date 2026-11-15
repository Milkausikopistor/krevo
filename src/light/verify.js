// "SPV" verification for light wallets: the wallet does not trust the server.
//
// For every transaction that pays it, it asks for an acceptance proof and checks on its own:
//   1. the Merkle path leads the txid to the acceptedIdMerkleRoot of the header of the block that
//      accepted the transaction (the txid is the hash of the content, which the wallet also recomputes);
//   2. that header and the next N of the selected chain have valid proof of work, each points to
//      the previous one as a parent, and blue score/blue work only grow;
//   3. the difficulty of each one is not much lower than the highest the wallet has seen
//      (prevents a server from cheaply "mining" fake headers).
// Inventing a payment would require mining N blocks at real difficulty — expensive on purpose.

import { Header, verifyMerkleProof } from '../consensus/block.js';
import { checkPow, calcWork } from '../consensus/pow.js';
import { Reader, fromHex } from '../util/bytes.js';

export function parseHeader(hex) {
  const r = new Reader(fromHex(hex));
  const h = Header.read(r);
  r.end();
  return h;
}

/** Checks the PoW of a header and returns its work (to learn the current difficulty). */
export function headerWork(hex) {
  const h = parseHeader(hex);
  if (!checkPow(h)) throw new Error('tip header without valid proof of work');
  return { header: h, work: calcWork(h.bits) };
}

/**
 * Throws if the proof is invalid. minDepth: blocks required on top;
 * minWork: minimum work per block (BigInt). Returns { block, depth, workOnTop, maxWork }.
 */
export function verifyAcceptanceProof(txid, proof, { minDepth, minWork = 0n }) {
  const hdrs = [proof.header, ...(proof.chain ?? [])].map(parseHeader);
  if (hdrs[0].hashHex !== proof.block) throw new Error('the header does not match the reported block');
  if (!verifyMerkleProof(fromHex(txid), proof.merkle, hdrs[0].acceptedIdMerkleRoot)) {
    throw new Error('invalid Merkle path: that block did not accept the transaction');
  }
  let workOnTop = 0n, maxWork = 0n;
  hdrs.forEach((h, i) => {
    if (!checkPow(h)) throw new Error('header without valid proof of work');
    const w = calcWork(h.bits);
    if (w < minWork) throw new Error('difficulty too low for the network (suspicious header)');
    if (w > maxWork) maxWork = w;
    if (i > 0) {
      const prev = hdrs[i - 1];
      if (!h.parents.some((p) => p.equals(prev.hash))) throw new Error('headers are not chained');
      if (h.blueScore <= prev.blueScore || h.blueWork <= prev.blueWork) throw new Error('inconsistent header chain');
      workOnTop += w;
    }
  });
  if (hdrs.length - 1 < minDepth) throw new Error(`only ${hdrs.length - 1} blocks on top (${minDepth} required)`);
  return { block: proof.block, depth: hdrs.length - 1, workOnTop, maxWork };
}
