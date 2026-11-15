// PROOF OF RESERVES — for exchanges (or any custodian) to prove they hold their customers'
// money, without exposing who the customers are.
//
// 1) ASSETS: what the exchange's wallet controls NOW, bound to a message of the moment
//    (e.g. "Exchange X — audit of 2026-11-13"), which prevents reusing old proofs.
//      • transparent coins: one Schnorr signature per coin with the address key;
//      • private coins: reveals amount and mask (opens the commitment C = x·G + v·H), the key
//        image I and a DLEQ proof that log_G(P) = log_Hp(P)(I) — that is, the prover has the
//        output's key and I is its image. Since I does not appear on the network yet, the coin was
//        NOT spent, and two exchanges cannot count the same coin (the same output has a single I).
//      Privacy cost: the EXCHANGE's outputs become identified (the customers' do not).
//
// 2) LIABILITIES: Merkle tree with SUMS (Maxwell). Each leaf is H(account, salt, balance) — each
//    customer's salt is handed only to them —, each node sums its children and the root carries
//    the total owed. Each customer checks that their balance is in the published root; the
//    exchange proves ASSETS ≥ root total.

import { randomBytes } from 'node:crypto';
import { Point, mulG, modN, randomScalar, hedgedScalar, hashToScalar, scalarToBytes } from '../crypto/secp256k1.js';
import { schnorrSign, schnorrVerify } from '../crypto/schnorr.js';
import { commit } from '../crypto/pedersen.js';
import { hashPointForKeyImage, keyImage } from '../crypto/clsag.js';
import { H } from '../crypto/hash.js';
import { dleqVerify as dleqCheck } from '../crypto/dleq.js';
import { transparentData } from '../address.js';
import { formatKRV, parseKRV } from '../params.js';
import { rpc } from '../node/rpcclient.js';
import { toHex, fromHex, scalarToBytesHex } from './reserves-util.js';

const ctxOf = (network, message, outpoint) => H('reserves/ctx', network, message, outpoint);

// the DLEQ proof is made in the vault (src/crypto/vault.js → src/crypto/dleq.js in plan B)
const dleqHex = ({ c, s }) => ({ c: scalarToBytesHex(c), s: scalarToBytesHex(s) });
const dleqVerify = (P, I, ctx, proof) => dleqCheck(P, I, ctx, { c: BigInt('0x' + proof.c), s: BigInt('0x' + proof.s) });

/** Builds the asset proof with ALL the wallet's unspent coins (already synced). */
export async function proveReserves(wallet, message) {
  if (!message || message.length < 8) throw new Error('use a message of the moment, e.g. "Exchange X — audit of 2026-11-13"');
  await wallet.sync();
  const network = wallet.params.name;
  const t = wallet.keys.tKey(0);
  const transparent = wallet.tUtxos.filter((u) => u.kind === 't' && !u.inMempool).map((u) => ({
    outpoint: u.outpoint, amount: String(u.amount), pubkey: toHex(t.P.toBytes()),
    sig: toHex(t.signer.sign(ctxOf(network, message, u.outpoint), 'reserves')),
  }));
  const priv = wallet.data.sOwned.filter((o) => !o.spent && !o.pending && !o.unverified).map((o) => {
    if (o.k === undefined) throw new Error('sync the wallet first (old format)');
    const P = Point.fromBytes(fromHex(o.P)), spend = wallet.keys.spender(BigInt('0x' + o.k), o.sub ?? 0);
    const I = spend.keyImage(P);
    return {
      index: o.index, outpoint: o.outpoint, amount: o.amount, mask: scalarToBytesHex(BigInt(o.mask)), keyImage: toHex(I.toBytes()),
      proof: dleqHex(spend.dleq(P, I, ctxOf(network, message, o.outpoint))),
    };
  });
  const total = [...transparent, ...priv].reduce((a, x) => a + BigInt(x.amount), 0n);
  return { krevo: 'proof-of-reserves', version: 1, network, message, createdAt: Date.now(), transparent, private: priv, total: total.toString() };
}

/**
 * Checks the proof against a node. Returns { valid, total, transparent, private, issues }.
 * Only adds up what passes ALL the checks; any problem goes to `issues`.
 */
export async function verifyReserves(params, rpcUrl, proof, { message } = {}) {
  const issues = [];
  if (!['proof-of-reserves', 'prova-de-reservas'].includes(proof.krevo) || proof.network !== params.name) throw new Error('the file is not a proof of reserves for this network');
  if (message !== undefined && message !== proof.message) issues.push('the proof\'s message differs from the agreed one (it may be an old proof)');
  const seen = new Set();
  let tTotal = 0n, sTotal = 0n;
  // transparent: they exist, are not being spent, the amount matches and the signature is the owner's
  const byLock = new Map();
  for (const e of proof.transparent ?? []) {
    if (seen.has(e.outpoint)) { issues.push(`repeated coin ${e.outpoint.slice(0, 16)}…`); continue; }
    seen.add(e.outpoint);
    let P;
    try { P = Point.fromBytes(fromHex(e.pubkey)); } catch { issues.push('invalid public key'); continue; }
    if (!schnorrVerify(P, ctxOf(params.name, proof.message, e.outpoint), fromHex(e.sig), 'reserves')) { issues.push(`invalid signature on ${e.outpoint.slice(0, 16)}…`); continue; }
    const lock = toHex(transparentData(P));
    (byLock.get(lock) ?? byLock.set(lock, []).get(lock)).push(e);
  }
  for (const [lock, entries] of byLock) {
    const { utxos } = await rpc(rpcUrl, 'getutxos', { locks: [lock] });
    const live = new Map(utxos.filter((u) => !u.inMempool).map((u) => [u.outpoint, BigInt(u.amount)]));
    for (const e of entries) {
      if (!live.has(e.outpoint)) { issues.push(`transparent coin ${e.outpoint.slice(0, 16)}… does not exist or was already spent`); continue; }
      if (live.get(e.outpoint) !== BigInt(e.amount)) { issues.push(`wrong declared amount on ${e.outpoint.slice(0, 16)}…`); continue; }
      tTotal += live.get(e.outpoint);
    }
  }
  // private: the output exists, the commitment opens to the declared amount, DLEQ checks out and I was not used
  const privs = (proof.private ?? []).filter((e) => {
    if (seen.has(e.outpoint)) { issues.push(`repeated coin ${e.outpoint.slice(0, 16)}…`); return false; }
    seen.add(e.outpoint);
    return true;
  });
  const kis = new Set();
  const okPriv = [];
  for (let k = 0; k < privs.length; k += 500) {
    const chunk = privs.slice(k, k + 500);
    const r = await rpc(rpcUrl, 'getshieldedbyindex', { indices: chunk.map((e) => Number(e.index)) });
    const byIndex = new Map(r.outputs.map((o) => [o.index, o]));
    for (const e of chunk) {
      const o = byIndex.get(Number(e.index));
      if (!o || o.outpoint !== e.outpoint) { issues.push(`private output ${e.outpoint.slice(0, 16)}… does not exist at that index`); continue; }
      const P = Point.fromBytes(fromHex(o.P)), C = Point.fromBytes(fromHex(o.C));
      let I;
      try { I = Point.fromBytes(fromHex(e.keyImage)); } catch { issues.push('invalid key image'); continue; }
      if (kis.has(e.keyImage)) { issues.push('repeated key image'); continue; }
      if (!commit(BigInt(e.amount), BigInt('0x' + e.mask)).equals(C)) { issues.push(`declared amount does not open the commitment of ${e.outpoint.slice(0, 16)}…`); continue; }
      if (!dleqVerify(P, I, ctxOf(params.name, proof.message, e.outpoint), e.proof)) { issues.push(`invalid proof of ownership on ${e.outpoint.slice(0, 16)}…`); continue; }
      kis.add(e.keyImage);
      okPriv.push(e);
    }
  }
  if (okPriv.length) {
    const st = await rpc(rpcUrl, 'getkeyimages', { keyImages: okPriv.map((e) => e.keyImage) });
    st.forEach((s, n) => {
      if (s.spent || s.inMempool) issues.push(`private coin ${okPriv[n].outpoint.slice(0, 16)}… was already spent`);
      else sTotal += BigInt(okPriv[n].amount);
    });
  }
  const total = tTotal + sTotal;
  if (total !== BigInt(proof.total ?? 0)) issues.push(`declared total ${formatKRV(BigInt(proof.total ?? 0))}, proven total ${formatKRV(total)}`);
  return { valid: issues.length === 0, total, transparent: tTotal, private: sTotal, coins: seen.size, issues };
}

// ------------------------------------------------------------------ liabilities (sum tree)
const leafHash = (id, salt, balance) => H('reserves/leaf', id, salt, balance);
const nodeHash = (l, r) => H('reserves/node', l.hash, l.sum, r.hash, r.sum);

/** accounts: [{ id, balance (grains) }] → { root, proofs } (one proof per account, to hand to the customer). */
export function buildLiabilities(accounts, { label = '' } = {}) {
  if (!accounts.length) throw new Error('no accounts');
  const ids = new Set();
  const leaves = accounts.map((a) => {
    const balance = BigInt(a.balance);
    if (balance < 0n) throw new Error(`negative balance in account ${a.id}`);
    if (ids.has(a.id)) throw new Error(`repeated account: ${a.id}`);
    ids.add(a.id);
    const salt = randomBytes(16);
    return { id: String(a.id), salt, balance, hash: leafHash(String(a.id), salt, balance), sum: balance };
  });
  const levels = [leaves];
  while (levels[levels.length - 1].length > 1) {
    const cur = levels[levels.length - 1], next = [];
    for (let i = 0; i < cur.length; i += 2) {
      next.push(i + 1 < cur.length ? { hash: nodeHash(cur[i], cur[i + 1]), sum: cur[i].sum + cur[i + 1].sum } : cur[i]);
    }
    levels.push(next);
  }
  const top = levels[levels.length - 1][0];
  const root = { krevo: 'liabilities-root', version: 1, label, hash: toHex(top.hash), total: top.sum.toString(), accounts: leaves.length, createdAt: Date.now() };
  const proofs = leaves.map((leaf, idx) => {
    const path = [];
    let i = idx;
    for (let l = 0; l < levels.length - 1; l++) {
      const sib = i ^ 1;
      if (sib < levels[l].length) path.push({ side: sib < i ? 'L' : 'R', hash: toHex(levels[l][sib].hash), sum: levels[l][sib].sum.toString() });
      else path.push(null); // an odd node goes up alone
      i >>= 1;
    }
    return { krevo: 'liability-proof', version: 1, rootHash: root.hash, id: leaf.id, salt: toHex(leaf.salt), balance: leaf.balance.toString(), path };
  });
  return { root, proofs };
}

/** The customer checks that THEIR account, with THEIR balance, is summed into the published root. */
export function verifyLiability(proof, root) {
  if (proof.rootHash !== root.hash) return { valid: false, reason: 'the proof is for another root' };
  let node = { hash: leafHash(proof.id, fromHex(proof.salt), BigInt(proof.balance)), sum: BigInt(proof.balance) };
  for (const step of proof.path) {
    if (step === null) continue;
    const sib = { hash: fromHex(step.hash), sum: BigInt(step.sum) };
    if (sib.sum < 0n) return { valid: false, reason: 'negative sum in the tree' };
    node = step.side === 'L' ? { hash: nodeHash(sib, node), sum: sib.sum + node.sum } : { hash: nodeHash(node, sib), sum: node.sum + sib.sum };
  }
  if (toHex(node.hash) !== root.hash) return { valid: false, reason: 'the path does not lead to the published root' };
  if (node.sum.toString() !== root.total) return { valid: false, reason: 'the total does not match the root' };
  return { valid: true, balance: BigInt(proof.balance), total: BigInt(root.total) };
}

/**
 * Reads one account per line: "account;balance" (balance with a decimal comma, e.g. ana;12,5) or
 * "account,balance" (balance with a decimal point, e.g. ana,12.5). Ignores a header and empty lines.
 */
export function parseAccountsCsv(text) {
  const out = [];
  for (const line of String(text).split(/\r?\n/)) {
    const t = line.trim();
    if (!t || /^(conta|id|account)\s*[,;]/i.test(t)) continue;
    const parts = t.split(t.includes(';') ? ';' : ',').map((x) => x.trim());
    if (parts.length !== 2 || !parts[0]) throw new Error(`invalid line: "${t}" (use account;balance — or account,balance with a decimal point)`);
    out.push({ id: parts[0], balance: parseKRV(parts[1]) });
  }
  return out;
}
