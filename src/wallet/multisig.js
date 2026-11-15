// M-of-N multisig coordination (the wallet side).
//
//  1. Each participant shows their multisig key (krk1…).
//  2. Anyone creates the group with M and the N keys → krv1… address and a "descriptor"
//     (krm1…) for the others to import. Same keys + same M = same address.
//  3. Payment: someone creates a PROPOSAL (JSON file) with the unsigned transaction.
//     The file circulates; each signer checks WHAT they are signing — reading the transaction
//     itself, not the proposer's summary — and adds their signature.
//  4. With M signatures, anyone merges everything and sends it to the network.
//
// Since the txid does not include the signatures, everyone signs exactly the same message and
// the order in which they sign does not matter (each one can sign when they can, offline).

import { encode, decode } from '../util/bech32m.js';
import { Point, hashToScalar, mulG, modN } from '../crypto/secp256k1.js';
import { schnorrSign, schnorrVerify } from '../crypto/schnorr.js';
import { outputScalar, decryptAmount, blindingFactor, sharedSecret, decryptMemo } from '../crypto/stealth.js';
import { commit } from '../crypto/pedersen.js';
import { encodePolicy, encodePolicyPaths, parsePolicy, multisigLock, encodeWitness, verifyMultisigWitness } from '../consensus/policy.js';
import { encodeAddress, decodeAddress } from '../address.js';
import { Transaction, parseOutpointKey } from '../consensus/tx.js';
import { buildTransaction } from './builder.js';
import { rpc } from '../node/rpcclient.js';
import { toHex, fromHex } from '../util/bytes.js';

// ------------------------------------------------------------ keys and group
/** The participant's multisig key, derived from the seed (recoverable from the phrase). */
export function multisigKey(keys) {
  const signer = keys.multisigSigner(); // the key stays in the vault
  return { P: signer.P, signer };
}
export const encodeMultisigKey = (params, P) => encode(params.hrp.k, P.toBytes());
export function decodeMultisigKey(params, s) {
  const { hrp, bytes } = decode(String(s).trim());
  if (hrp !== params.hrp.k) throw new Error(`multisig key from another network or format (${hrp})`);
  return Point.fromBytes(bytes);
}

export class MultisigGroup {
  constructor(params, policyBytes, name = '') {
    this.params = params;
    this.policy = parsePolicy(policyBytes);
    if (this.policy.bytes.length !== policyBytes.length) throw new Error('descriptor with extra bytes');
    this.bytes = this.policy.bytes;
    this.name = name;
    this.lock = multisigLock(this.bytes);
  }
  static create(params, m, keyStrings, name) {
    return new MultisigGroup(params, encodePolicy(m, keyStrings.map((k) => decodeMultisigKey(params, k))), name);
  }
  static fromDescriptor(params, descriptor, name) {
    const { hrp, bytes } = decode(String(descriptor).trim());
    if (hrp !== params.hrp.m) throw new Error(`descriptor from another network or format (${hrp})`);
    return new MultisigGroup(params, bytes, name);
  }
  /** Inheritance: path 0 = owner (alone, no wait); path 1 = heirs (M-of-N after the wait). */
  static createInheritance(params, ownerKey, heirKeys, heirM, delayBlocks, name) {
    const dec = (k) => (typeof k === 'string' ? decodeMultisigKey(params, k) : k);
    const bytes = encodePolicyPaths([
      { m: 1, keys: [dec(ownerKey)], delay: 0 },
      { m: heirM, keys: heirKeys.map(dec), delay: delayBlocks },
    ]);
    return new MultisigGroup(params, bytes, name);
  }
  get paths() { return this.policy.paths; }
  get isInheritance() { return this.policy.paths.length === 2 && this.policy.paths[1].delay > 0; }
  get m() { return this.policy.m; }
  get n() { return this.policy.n; }
  get address() { return encodeAddress(this.params, this.lock); }
  get descriptor() { return encode(this.params.hrp.m, this.bytes); }
  indexOf(P, path = 0) { return this.policy.paths[path].keys.findIndex((k) => k.equals(P)); }
}

// ------------------------------------------------------------- proposals
export async function groupUtxos(rpcUrl, group) {
  const r = await rpc(rpcUrl, 'getutxos', { locks: [toHex(group.lock)] });
  return r.utxos;
}

/** Creates the payment proposal (without signatures). */
export async function proposePayment({ params, rpcUrl, group, to, amount, memo, path = 0, sweep = false }) {
  const dest = decodeAddress(params, to);
  if (memo && dest.type !== 's') throw new Error('a memo is only possible for a private address (krs1…)');
  const p = group.paths[path];
  if (!p) throw new Error('path does not exist in this policy');
  const { daaScore, utxos } = await rpc(rpcUrl, 'getutxos', { locks: [toHex(group.lock)] });
  // only outputs that already met this path's wait
  const coins = utxos.filter((u) => u.mature && !u.inMempool && daaScore - u.daa >= p.delay)
    .sort((a, b) => (BigInt(b.amount) > BigInt(a.amount) ? 1 : -1));
  const tInputs = [];
  let acc = 0n;
  for (const u of coins) {
    if (!sweep && acc >= amount + 1_000_000n) break;
    tInputs.push({ outpoint: parseOutpointKey(u.outpoint), amount: BigInt(u.amount), policy: group.bytes, path });
    acc += BigInt(u.amount);
  }
  if (!tInputs.length || (!sweep && acc < amount)) {
    const locked = utxos.filter((u) => daaScore - u.daa < p.delay);
    if (locked.length) {
      const wait = Math.min(...locked.map((u) => p.delay - (daaScore - u.daa)));
      throw new Error(`balance still time-locked on this path (unlocks in ${wait} blocks ≈ ${formatWait(wait, params)})`);
    }
    throw new Error('insufficient group balance');
  }
  const outDesc = dest.type === 's' ? { type: 's', A: dest.A, B: dest.B } : { type: 't', lock: dest.data };
  const { tx, fee, change, r } = sweep
    ? buildTransaction({ params, tInputs, sweep: outDesc, memo })
    : buildTransaction({ params, tInputs, outputs: [{ ...outDesc, amount }], change: { type: 't', lock: group.lock }, memo });
  if (sweep) amount = acc - fee;
  return {
    krevo: 'multisig-proposal', version: 1, network: params.name, group: group.descriptor, path,
    txid: tx.idHex, tx: toHex(tx.serialize()), to, amount: amount.toString(), fee: fee.toString(), change: change.toString(),
    inputs: tInputs.map((i) => ({ outpoint: `${toHex(i.outpoint.txid)}:${i.outpoint.index}`, amount: i.amount.toString() })),
    // secret of the recipient's private output: lets the signers check amount and destination
    outputSecret: dest.type === 's' && r ? r.toString(16) : null,
    signatures: {},
  };
}

/**
 * Reads the proposal's transaction and describes, independently, what it does.
 * It does not trust the proposer's summary: it recomputes destination, amount and change from the tx.
 */
export function describeProposal(params, prop) {
  if (!['multisig-proposal', 'proposta-multiassinatura'].includes(prop.krevo) || prop.network !== params.name) throw new Error('the file is not a proposal for this network');
  const group = MultisigGroup.fromDescriptor(params, prop.group);
  const tx = Transaction.deserialize(fromHex(prop.tx));
  if (tx.idHex !== prop.txid) throw new Error('tampered proposal (txid does not match)');
  const lockHex = toHex(group.lock);
  const payments = [];
  let change = 0n;
  for (const o of tx.tOut) {
    if (toHex(o.lock) === lockHex) change += o.amount;
    else payments.push({ to: encodeAddress(params, o.lock), amount: o.amount, private: false });
  }
  if (tx.sOut.length) {
    // the 1st private output is the recipient's; the secret r allows checking amount and address
    const dest = decodeAddress(params, prop.to);
    let verified = false, amount = null, memo = null;
    if (prop.outputSecret && dest.type === 's') {
      const r = BigInt('0x' + prop.outputSecret), o = tx.sOut[0];
      const ss = sharedSecret(r, dest.A);
      const P = mulG(outputScalar(ss, 0)).add(dest.B);
      if (dest.B.mul(r).equals(Point.fromBytes(o.R)) && P.equals(Point.fromBytes(o.P))) {
        amount = decryptAmount(o.encAmount, ss, 0);
        verified = commit(amount, blindingFactor(ss, 0)).equals(Point.fromBytes(o.C));
        memo = decryptMemo(tx.payload, ss, 0) || null;
      }
    }
    if (!verified) throw new Error('could not check the proposal\'s private output — do NOT sign');
    payments.push({ to: prop.to, amount, private: true, memo });
    if (tx.sOut.length > 1) throw new Error('proposal with extra private outputs — do NOT sign');
  }
  const signers = Object.keys(prop.signatures).map(Number).sort((a, b) => a - b);
  const path = prop.path ?? 0;
  if (!group.paths[path]) throw new Error('path does not exist in the policy');
  return {
    group, tx, payments, change, fee: tx.fee, inputs: tx.tIn.length, signers, have: signers.length,
    need: group.paths[path].m, path, delay: group.paths[path].delay,
  };
}

/** Checks on the network that the inputs belong to the group and sums the amounts (consistent fee). */
export async function checkProposalInputs(params, rpcUrl, prop) {
  const d = describeProposal(params, prop);
  const utxos = new Map((await groupUtxos(rpcUrl, d.group)).map((u) => [u.outpoint, BigInt(u.amount)]));
  let total = 0n;
  for (const i of d.tx.tIn) {
    const k = `${toHex(i.outpoint.txid)}:${i.outpoint.index}`;
    if (!utxos.has(k)) throw new Error(`input ${k.slice(0, 16)}… is not an available balance of the group`);
    total += utxos.get(k);
  }
  const out = d.payments.reduce((a, p) => a + p.amount, 0n) + d.change;
  if (total !== out + d.fee) throw new Error('the proposal\'s amounts do not add up (inputs ≠ outputs + fee)');
  return { ...d, totalIn: total };
}

/** Adds this participant's signature. */
export function signProposal(params, prop, keys) {
  const d = describeProposal(params, prop);
  const { signer, P } = multisigKey(keys);
  const idx = d.group.indexOf(P, d.path);
  if (idx < 0) throw new Error(d.path ? 'your key is not part of this policy path' : 'your key is not part of this group');
  const sig = signer.sign(d.tx.sighash());
  prop.signatures[idx] = toHex(sig);
  return { index: idx, have: Object.keys(prop.signatures).length, need: d.need };
}

/** Merges signatures from several copies of the same proposal. */
export function mergeProposals(props) {
  const base = { ...props[0], signatures: { ...props[0].signatures } };
  for (const p of props.slice(1)) {
    if (p.txid !== base.txid) throw new Error('the proposals are for different transactions');
    Object.assign(base.signatures, p.signatures);
  }
  return base;
}

/** Builds the witnesses with M valid signatures and returns the ready transaction. */
export function finalizeProposal(params, prop) {
  const d = describeProposal(params, prop);
  const msg = d.tx.sighash();
  const sigs = new Map();
  for (const [i, s] of Object.entries(prop.signatures)) {
    const idx = Number(i), sig = fromHex(s);
    const key = d.group.paths[d.path].keys[idx];
    if (key && schnorrVerify(key, msg, sig)) sigs.set(idx, sig);
  }
  if (sigs.size < d.need) throw new Error(`valid signatures: ${sigs.size} of ${d.need} required`);
  const witness = encodeWitness(d.group.bytes, sigs, d.path);
  d.tx.tIn.forEach((i) => { i.sig = witness; });
  d.tx.invalidate();
  for (const i of d.tx.tIn) if (!verifyMultisigWitness(d.group.lock, i.sig, msg)) throw new Error('invalid witness');
  return d.tx;
}
export { modN };

// ------------------------------------------------------------------ inheritance
export function formatWait(blocks, params) {
  const sec = blocks / params.bps;
  if (sec < 120) return `${Math.ceil(sec)} s`;
  if (sec < 7200) return `${Math.ceil(sec / 60)} min`;
  if (sec < 172800) return `${(sec / 3600).toFixed(1).replace('.', ',')} h`;
  return `${(sec / 86400).toFixed(1).replace('.', ',')} dias`;
}

const UNITS = { s: 1, seg: 1, min: 60, h: 3600, d: 86400, m: 2629800, mes: 2629800, meses: 2629800, a: 31557600, y: 31557600, ano: 31557600, anos: 31557600 };

/** Converts "365d", "6m" (months), "1y" (years), "12h", "30min", "20s" or "5000b" (blocks) into blocks. */
export function parseWait(str, params) {
  const m = /^(\d+(?:[.,]\d+)?)\s*([a-z]+)?$/i.exec(String(str).trim());
  const unit = (m?.[2] ?? 'd').toLowerCase();
  if (!m || (!(unit in UNITS) && unit !== 'b' && unit !== 'blocks' && unit !== 'blocos')) {
    throw new Error(`invalid time: "${str}" (examples: 365d, 6m, 1y, 12h, 30min, 20s)`);
  }
  const n = Number(m[1].replace(',', '.'));
  return Math.round(unit === 'b' || unit === 'blocks' || unit === 'blocos' ? n : n * UNITS[unit] * params.bps);
}

/** State of an inheritance plan: balance and when the heirs will be able to spend. */
export async function inheritanceStatus(params, rpcUrl, group) {
  const delay = group.paths[1].delay;
  const { daaScore, utxos } = await rpc(rpcUrl, 'getutxos', { locks: [toHex(group.lock)] });
  const items = utxos.map((u) => ({ amount: BigInt(u.amount), left: Math.max(0, delay - (daaScore - u.daa)) }));
  return {
    balance: items.reduce((a, i) => a + i.amount, 0n),
    claimable: items.filter((i) => i.left === 0).reduce((a, i) => a + i.amount, 0n),
    delay, count: items.length,
    nextUnlock: items.length ? Math.min(...items.map((i) => i.left)) : null, // first output to unlock
    fullUnlock: items.length ? Math.max(...items.map((i) => i.left)) : null, // when the whole balance unlocks
  };
}

/** Spend through a path that needs only ONE signature (owner, or heir in a 1-of-N plan). */
export async function spendAlone({ params, rpcUrl, group, path, keys, to, amount, sweep = false, memo }) {
  if (group.paths[path].m !== 1) throw new Error('this path requires more than one signature: use multisig propose/sign/send with --path');
  const prop = await proposePayment({ params, rpcUrl, group, to, amount, memo, path, sweep });
  signProposal(params, prop, keys);
  const tx = finalizeProposal(params, prop);
  const res = await rpc(rpcUrl, 'sendrawtransaction', { tx: toHex(tx.serialize()) });
  return { txid: res.txid, fee: tx.fee, amount: BigInt(prop.amount) };
}
