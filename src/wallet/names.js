// Human-readable names in the wallet: register @bakery, point it to an address, renew,
// transfer and release. The rules live in consensus (src/consensus/names.js); here we only
// build the transactions.
//
// Two-step registration (protection against someone copying the name halfway):
//   nameCommit  → publishes only a hash of the name (nobody knows which one)
//   nameReveal  → after nameCommitMin blocks, reveals the name and creates the record
// The commitment's "salt" comes from the 24-word phrase: it can be revealed even from another copy.

import { H } from '../crypto/hash.js';
import { toHex, fromHex } from '../util/bytes.js';
import { parseOutpointKey } from '../consensus/tx.js';
import { checkName, nameFee, encodeNameRecord, nameCommitHash, nameCommitLock, commitWitnessPrefix } from '../consensus/names.js';
import { decodeAddress } from '../address.js';
import { buildTransaction } from './builder.js';
import { pqAvailable } from '../crypto/pq.js';

const COMMIT_VALUE = 1_000_000n; // 0.01 KRV in the commitment; it returns as change in the reveal
const expiryMargin = (p) => Math.min(600, Math.floor(p.namePeriod / 20));
const saltFor = (w, name, n) => w.keys.vault.nameSalt(name, n); // H("wallet/name/salt", seed, name, n), in the vault

/** Key of this wallet that matches the owner lock (hex), or null. */
function signerFor(w, lock) {
  const h = typeof lock === 'string' ? lock.toLowerCase() : toHex(lock); // the RPC returns hex
  const t = w.keys.tKey(0), q = pqAvailable() ? w.keys.qKey(0) : null;
  if (toHex(t.lock) === h) return { lock: t.lock, signer: t.signer };
  if (q && toHex(q.lock) === h) return { lock: q.lock, signer: q.signer, pq: q };
  return null;
}
/** Default owner: the krv address — or the krq one, if the wallet is in quantum mode. */
function defaultOwner(w) { return signerFor(w, w.quantum ? w.keys.qKey(0).lock : w.keys.tKey(0).lock); }

/** Where the name points to: 'private' (main krs), 'transparent', or an address. */
export function targetData(w, target = 'private') {
  if (target === 'private' || target === 'privado') return w.keys.shieldedData;
  if (target === 'transparent' || target === 'transparente') return w._changeLock;
  const a = decodeAddress(w.params, target);
  if (!['t', 's', 'm', 'q'].includes(a.type)) throw new Error('a name can only point to a krv, krs, krq or multisig address');
  return a.data;
}

function ownerLockFrom(w, address) {
  const a = decodeAddress(w.params, address);
  if (!['t', 'm', 'q'].includes(a.type)) throw new Error('the new owner must be a krv, krq or multisig address (krs cannot sign)');
  return a.data;
}

/** Step 1: commitment. Returns { name, txid, waitSeconds, nameFee }. */
export async function nameCommit(w, raw, { target = 'private', feeRate } = {}) {
  const name = checkName(raw);
  const info = await w.resolveName(name);
  if (info.status !== 'free') throw new Error(`@${name} already has an owner (${info.status})`);
  const owner = defaultOwner(w);
  const tgt = targetData(w, target);
  const n = (w.data.nameSaltN = (w.data.nameSaltN ?? 0) + 1);
  const lock = nameCommitLock(nameCommitHash(name, saltFor(w, name, n), owner.lock));
  const r = await w.sendOutputs([{ type: 't', lock, amount: COMMIT_VALUE }], { feeRate });
  (w.data.names ??= {})[name] = { name, saltN: n, owner: toHex(owner.lock), target: toHex(tgt), commitTxid: r.txid, state: 'committed', time: Date.now() };
  w.save();
  return { name, txid: r.txid, fee: r.fee, nameFee: BigInt(info.fee), waitSeconds: w.params.nameCommitMin / w.params.bps };
}

async function pendingCommit(w, name) {
  const p = w.data.names?.[name];
  if (!p || !['committed', 'compromisso'].includes(p.state)) throw new Error(`there is no pending commitment for @${name} in this wallet`);
  const owner = signerFor(w, p.owner);
  if (!owner) throw new Error('the commitment key does not belong to this wallet');
  const salt = saltFor(w, name, p.saltN);
  const r = await w.call('getutxos', { locks: [toHex(nameCommitLock(nameCommitHash(name, salt, owner.lock)))] });
  const u = r.utxos.find((x) => !x.inMempool);
  return { p, owner, salt, u, daa: r.daaScore };
}

/** How many seconds are left before revealing (0 = now; null = commitment not confirmed yet). */
export async function nameRevealWait(w, raw) {
  const { u, daa } = await pendingCommit(w, checkName(raw));
  if (!u) return null;
  return Math.max(0, w.params.nameCommitMin - (daa - u.daa)) / w.params.bps;
}

/** Step 2: reveal — creates the record (pays the yearly fee, which goes to the Security Fund). */
export async function nameReveal(w, raw, { feeRate } = {}) {
  const name = checkName(raw);
  const { p, owner, salt, u, daa } = await pendingCommit(w, name);
  if (!u) throw new Error('the commitment has not been confirmed yet');
  const missing = w.params.nameCommitMin - (daa - u.daa);
  if (missing > 0) throw new Error(`wait ${Math.ceil(missing / w.params.bps)} more seconds before revealing`);
  const info = await w.resolveName(name);
  if (info.status !== 'free') throw new Error(`@${name} was registered by someone else first`);
  const expiry = daa + w.params.namePeriod - expiryMargin(w.params);
  const record = encodeNameRecord({ name, expiry, owner: owner.lock, target: fromHex(p.target) });
  const commitIn = { outpoint: parseOutpointKey(u.outpoint), amount: BigInt(u.amount), signer: owner.signer, pq: owner.pq, prefix: commitWitnessPrefix(name, salt, owner.lock) };
  const fee = nameFee(w.params, name);
  const res = await w.sendOutputs([{ type: 't', lock: record, amount: w.params.nameMinDeposit }], { extraInputs: [commitIn], extraFee: fee, feeRate });
  p.state = 'registered'; p.revealTxid = res.txid;
  w.save();
  return { name, txid: res.txid, fee: res.fee, nameFee: fee, expiry };
}

/** Spends the current record (only the owner can) and recreates it with changes — or releases it. */
async function recordOp(w, raw, { target, newOwner, renew = false, release = false, feeRate } = {}) {
  const name = checkName(raw);
  const info = await w.resolveName(name);
  if (info.status === 'free') throw new Error(`@${name} is not registered`);
  const signer = signerFor(w, info.ownerLock);
  if (!signer) throw new Error(`@${name} does not belong to this wallet (owner: ${info.owner})`);
  const input = { outpoint: parseOutpointKey(info.outpoint), amount: BigInt(info.deposit), signer: signer.signer, pq: signer.pq };
  if (release) {
    const { tx, fee } = buildTransaction({ params: w.params, tInputs: [input], sweep: { type: 't', lock: w._changeLock }, feeRate });
    const res = await w.call('sendrawtransaction', { tx: toHex(tx.serialize()) });
    return { name, txid: res.txid, fee, refunded: BigInt(info.deposit) - fee };
  }
  if (info.status !== 'active' && !renew) throw new Error(`@${name} expired: renew it to keep it`);
  const expiry = renew ? Math.max(info.expiry, info.daaScore) + w.params.namePeriod - expiryMargin(w.params) : info.expiry;
  const record = encodeNameRecord({
    name, expiry,
    owner: newOwner ? ownerLockFrom(w, newOwner) : fromHex(info.ownerLock),
    target: target ? targetData(w, target) : fromHex(info.targetData),
  });
  const extraFee = renew ? nameFee(w.params, name) : 0n;
  const res = await w.sendOutputs([{ type: 't', lock: record, amount: BigInt(info.deposit) }], { extraInputs: [input], extraFee, feeRate });
  return { name, txid: res.txid, fee: res.fee, nameFee: extraFee, expiry };
}

export const nameRenew = (w, name, o = {}) => recordOp(w, name, { ...o, renew: true });
export const nameUpdate = (w, name, target, o = {}) => recordOp(w, name, { ...o, target });
export const nameTransfer = (w, name, to, o = {}) => recordOp(w, name, { ...o, newOwner: to });
export const nameRelease = (w, name, o = {}) => recordOp(w, name, { ...o, release: true });

/** Names that belong to this wallet (by the krv or krq address) — works after restoring the phrase. */
export function myNames(w) {
  const owners = [toHex(w.keys.tKey(0).lock)];
  if (pqAvailable()) owners.push(toHex(w.keys.qKey(0).lock));
  return w.call('listnames', { owners });
}
