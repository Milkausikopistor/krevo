// Transaction validity rules.
//
// validateTxStateless — independent of the state (structure, limits, range proofs).
// validateTxInContext — against a UTXO view (existence, maturity, double spends,
//                        signatures, ring signatures, balance).
//
// Balance rule (applies to ANY transparent/private mix):
//   E = Σ pseudo_commitments + (Σ transparent_inputs)·H
//       − Σ output_commitments − (Σ transparent_outputs + fee)·H
// Without private parts: E = 0 is required numerically.
// With private parts: E must be k·G and the sender proves knowledge of k with a Schnorr
// signature (the "balance signature"). Since nobody knows log_G(H), this is only possible
// if the AMOUNTS cancel out exactly — no coins are created.
//
// Names (@name, src/consensus/names.js): at most one record per transaction; a name can only
// have one live record; registering requires revealing a mature commitment and paying the fee;
// renewing requires the fee; updating/transferring requires the owner's signature (who spends the record).

import { MAX_SUPPLY } from '../params.js';
import { Point, INF, sumPoints } from '../crypto/secp256k1.js';
import { schnorrVerify } from '../crypto/schnorr.js';
import { mulH } from '../crypto/pedersen.js';
import { verifyRange, rangeProofSize, MAX_AGGREGATION } from '../crypto/bulletproofs.js';
import { clsagVerify, decodeClsag, clsagSize } from '../crypto/clsag.js';
import { fcmpProofSize, fcmpVerifyInto, newFcmpBatch } from '../fcmp/fcmp.js';
import { parseAddressData } from '../address.js';
import { verifyMultisigWitness, witnessDelay, LOCK_MULTISIG } from './policy.js';
import { verifyPqWitness } from './pqlock.js';
import { LOCK_NAME, LOCK_NAME_COMMIT, parseNameRecord, parseCommitWitness, nameCommitHash, nameFee } from './names.js';
import { computeMass, storageMass } from './mass.js';
import { outpointKey } from './tx.js';
import { toHex } from '../util/bytes.js';

export class TxRuleError extends Error {}
const fail = (m) => { throw new TxRuleError(m); };

// Cryptographic verification caches (the data referenced by an outpoint are immutable — the
// txid commits to the outputs — so the result is deterministic).
const rangeOk = new Set();
const cryptoOk = new Set();
function remember(set, k) { if (set.size > 100_000) set.clear(); set.add(k); }

const OWNER_TYPES = new Set(['t', 'm', 'q']); // who can own a name (spendable locks)

/**
 * Name records and commitments are spent with the OWNER's witness. Returns
 * { lock, witness, commit? } with the "inner" lock and witness, or null if it does not match.
 */
function unwrapSpend(lock, witness) {
  if (lock[0] === LOCK_NAME) {
    try { return { lock: parseNameRecord(lock).owner, witness }; } catch { return null; }
  }
  if (lock[0] === LOCK_NAME_COMMIT) {
    const c = parseCommitWitness(witness);
    if (!c || !nameCommitHash(c.name, c.salt, c.owner).equals(lock.subarray(1))) return null;
    return { lock: c.owner, witness: c.inner, commit: c };
  }
  return { lock, witness };
}

/** Name rules. Returns the name fee paid (it all goes to the Security Fund). */
function checkNameRules(tx, view, povDaa, params, inners, entries) {
  const out = tx.tOut.find((o) => o.lock[0] === LOCK_NAME);
  if (!out) return 0n;
  const rec = parseNameRecord(out.lock);
  const fee = nameFee(params, rec.name);
  if (out.amount < params.nameMinDeposit) fail(`a name record must hold a deposit of at least ${params.nameMinDeposit} grains`);
  if (rec.expiry <= povDaa) fail('name expiry in the past (renew by paying the fee)');
  const spent = new Set(tx.tIn.map((i) => outpointKey(i.outpoint.txid, i.outpoint.index)));
  let prev = null;
  for (const { key, e } of view.nameEntries(rec.name)) {
    const r = parseNameRecord(e.lock);
    if (povDaa > r.expiry + params.nameGrace) continue; // past the grace period: no longer valid
    if (!spent.has(key)) fail(`@${rec.name} already has an owner`);
    prev = r;
  }
  if (prev) {
    // the owner (whose signature is required to spend the record) updates, transfers or renews
    if (rec.expiry <= prev.expiry) return 0n;
    if (tx.fee < fee) fail(`renewing @${rec.name} costs ${fee} grains`);
    if (rec.expiry > Math.max(prev.expiry, povDaa) + params.namePeriod) fail('renewal beyond one period');
    return fee;
  }
  if (tx.fee < fee) fail(`registering @${rec.name} costs ${fee} grains`);
  if (rec.expiry > povDaa + params.namePeriod) fail('registration beyond one period');
  const ok = inners.some((u, n) => u.commit && u.commit.name === rec.name && u.commit.owner.equals(rec.owner)
    && povDaa - entries[n].daa >= params.nameCommitMin && povDaa - entries[n].daa <= params.nameCommitMax);
  if (!ok) fail(`registering @${rec.name} requires revealing a commitment made between ${params.nameCommitMin} and ${params.nameCommitMax} blocks ago`);
  return fee;
}

export function validateTxStateless(tx, params) {
  if (tx.version !== 1) fail('unknown transaction version');
  if (tx.isCoinbase()) fail('transaction without inputs');
  if (tx.tOut.length + tx.sOut.length === 0) fail('transaction without outputs');
  if (tx.payload.length > params.maxTxPayload) fail('payload too large');
  if (tx.fee > MAX_SUPPLY) fail('invalid fee');
  const seen = new Set();
  for (const i of tx.tIn) {
    const k = outpointKey(i.outpoint.txid, i.outpoint.index);
    if (seen.has(k)) fail('duplicate input');
    seen.add(k);
  }
  const kis = new Set();
  for (const si of tx.sIn) {
    if (!si.ring.length) {
      // full-chain membership proof against the tree of the first `anchor` outputs
      if (!Number.isSafeInteger(si.anchor) || si.anchor < 1) fail('invalid private input anchor');
      if (!si.fcmp || si.fcmp.length !== fcmpProofSize(si.anchor, params.fcmpBranch)) fail('membership proof with invalid size');
    } else {
      if (!params.ringInputs) fail('ring signatures are not accepted on this network: the private input must prove it belongs to the tree of ALL outputs (FCMP)');
      if (si.ring.length !== params.ringSize) fail(`the ring must have ${params.ringSize} members`);
      const members = new Set(si.ring.map((m) => outpointKey(m.txid, m.index)));
      if (members.size !== si.ring.length) fail('repeated ring member');
      if (si.clsag.length !== clsagSize(si.ring.length)) fail('ring signature with invalid size');
    }
    const ki = toHex(si.keyImage);
    if (kis.has(ki)) fail('key image repeated in the transaction');
    kis.add(ki);
    try { Point.fromBytes(si.pseudo); Point.fromBytes(si.keyImage); } catch { fail('invalid point in private input'); }
  }
  let outSum = 0n, nameOuts = 0;
  for (const o of tx.tOut) {
    if (o.amount < 1n || o.amount > MAX_SUPPLY) fail('invalid output amount');
    outSum += o.amount;
    let a;
    try { a = parseAddressData(o.lock); } catch { fail('invalid output lock'); }
    if (a.type === 's') fail('invalid output lock');
    if (a.type === 'n') {
      nameOuts++;
      let owner, target;
      try { owner = parseAddressData(a.record.owner); target = parseAddressData(a.record.target); } catch { fail('name record with invalid owner or destination'); }
      if (!OWNER_TYPES.has(owner.type)) fail('the owner of a name must be a krv, krq or multisig address');
      if (!['t', 's', 'm', 'q'].includes(target.type)) fail('invalid name destination');
    }
  }
  if (nameOuts > 1) fail('at most one name record per transaction');
  if (outSum + tx.fee > MAX_SUPPLY) fail('sum of outputs above the maximum supply');
  const hasShielded = tx.sIn.length > 0 || tx.sOut.length > 0;
  if (tx.sOut.length) {
    if (tx.sOut.length > MAX_AGGREGATION) fail('too many private outputs');
    if (tx.rangeProof.length !== rangeProofSize(tx.sOut.length)) fail('range proof with invalid size');
    let Cs;
    try { Cs = tx.sOut.map((o) => { Point.fromBytes(o.R); Point.fromBytes(o.P); return Point.fromBytes(o.C); }); }
    catch { fail('invalid point in private output'); }
    const key = tx.hashHex;
    if (!rangeOk.has(key)) {
      if (!verifyRange(Cs, tx.rangeProof)) fail('invalid range proof');
      remember(rangeOk, key);
    }
  } else if (tx.rangeProof.length) fail('range proof without private outputs');
  if (hasShielded !== !!tx.bindingSig) fail('balance signature missing or unexpected');
  const cm = computeMass(tx, params);
  if (tx.mass < cm) fail(`declared mass (${tx.mass}) below the compute mass (${cm})`);
  if (tx.mass > params.maxTxMass) fail('transaction too heavy');
}

/**
 * Validates against the UTXO view. Returns { fee } or throws TxRuleError.
 * povDaa = daaScore of the point of view (the block that accepts the transaction).
 */
export function validateTxInContext(tx, view, povDaa, params) {
  const tInAmounts = [];
  const inners = [], entries = [];
  for (const i of tx.tIn) {
    const e = view.getT(outpointKey(i.outpoint.txid, i.outpoint.index));
    if (!e) fail('input does not exist or is already spent');
    if (e.coinbase && povDaa - e.daa < params.coinbaseMaturity) fail('immature coinbase');
    const u = unwrapSpend(e.lock, i.sig);
    if (!u) fail('witness does not match the output (wrong name commitment?)');
    if (u.lock[0] === LOCK_MULTISIG) {
      // relative time lock: always checked (it depends on the moment, not only on the transaction)
      const delay = witnessDelay(u.witness);
      if (delay === null) fail('malformed multisig witness');
      if (povDaa - e.daa < delay) fail(`time-locked: ${delay - (povDaa - e.daa)} blocks to go`);
    }
    tInAmounts.push(e.amount);
    inners.push(u);
    entries.push(e);
  }
  const rings = [];
  for (const si of tx.sIn) {
    if (view.hasKI(toHex(si.keyImage))) fail('double spend (key image already used)');
    if (!si.ring.length) {
      // The anchor must be in the selected parent's state (the global order is the selected
      // chain's) and mature: EVERY output of the chosen tree can already be spent.
      const base = view.base;
      if (si.anchor > base.sList.length) fail('anchor beyond the known private outputs');
      const last = base.s.get(base.sList[si.anchor - 1]);
      if (povDaa - last.daa < params.fcmpMaturity) fail(`anchor too recent: use a tree at least ${params.fcmpMaturity} blocks old`);
      rings.push(null);
      continue;
    }
    const ring = [];
    for (const m of si.ring) {
      const e = view.getS(outpointKey(m.txid, m.index));
      if (!e) fail('nonexistent ring member');
      const need = e.coinbase ? Math.max(params.ringMaturity, params.coinbaseMaturity) : params.ringMaturity;
      if (povDaa - e.daa < need) fail('immature ring member');
      ring.push(e);
    }
    rings.push(ring);
  }
  if (storageMass(tx, tInAmounts, params) > tx.mass) fail('storage mass above the declared one');
  const nameFeePaid = checkNameRules(tx, view, povDaa, params, inners, entries);

  const tIn = tInAmounts.reduce((a, b) => a + b, 0n);
  const tOut = tx.tOut.reduce((a, o) => a + o.amount, 0n);
  const hasShielded = tx.sIn.length > 0 || tx.sOut.length > 0;
  if (!hasShielded && tIn !== tOut + tx.fee) fail('inputs ≠ outputs + fee');

  const key = tx.hashHex;
  if (!cryptoOk.has(key)) {
    const msg = tx.sighash();
    tx.tIn.forEach((i, n) => {
      const { lock: inner, witness } = inners[n];
      let lock;
      try { lock = parseAddressData(inner); } catch { fail('unspendable lock'); }
      if (lock.type === 'm') {
        if (!verifyMultisigWitness(lock.data, witness, msg)) fail('invalid multisig (missing signatures or one does not match)');
      } else if (lock.type === 'q') {
        if (!verifyPqWitness(lock.data, witness, msg)) fail('invalid quantum-safe hybrid signature (both Schnorr and ML-DSA must match)');
      } else if (lock.type === 't') {
        if (witness.length !== 64 || !schnorrVerify(lock.pubkey, msg, witness)) fail('invalid signature');
      } else fail('this output cannot be spent');
    });
    const pseudos = [];
    const batch = newFcmpBatch();
    let fcmps = 0;
    tx.sIn.forEach((si, n) => {
      const pseudo = Point.fromBytes(si.pseudo);
      pseudos.push(pseudo);
      if (!si.ring.length) {
        try {
          fcmpVerifyInto(batch, { branch: params.fcmpBranch, N: si.anchor, root: view.base.tree.root(si.anchor), proof: si.fcmp, keyImage: Point.fromBytes(si.keyImage), pseudo, msg });
        } catch (e) { fail('invalid membership proof (' + e.message + ')'); }
        fcmps++;
        return;
      }
      const ring = rings[n].map((e) => ({ P: Point.fromBytes(e.P), C: Point.fromBytes(e.C) }));
      const sig = decodeClsag(si.clsag, si.ring.length, Point.fromBytes(si.keyImage));
      if (!clsagVerify(msg, ring, pseudo, sig)) fail('invalid ring signature');
    });
    // all membership proofs of the transaction in a single multi-exponentiation per curve
    if (fcmps && !(batch.e1.check() && batch.e2.check())) fail('invalid membership proof');
    if (hasShielded) {
      const outC = sumPoints(tx.sOut.map((o) => Point.fromBytes(o.C)));
      const E = sumPoints(pseudos).add(mulH(tIn)).sub(outC).sub(mulH(tOut + tx.fee));
      if (E.isInf() || !schnorrVerify(E, msg, tx.bindingSig, 'binding')) fail('invalid balance');
    }
    remember(cryptoOk, key);
  }
  return { fee: tx.fee, tIn, nameFee: nameFeePaid };
}

/**
 * How much a transaction changes the balance of the private pool (turnstile, like Zcash's ZIP-209).
 * Computed only from PUBLIC values: (transparent inputs) − (transparent outputs + fee).
 *   > 0  → coins entered the private pool (shielding)
 *   < 0  → coins left the private pool (unshielding)
 * Purely transparent transactions do not touch the pool (delta 0).
 */
export function shieldedDelta(tx, tInSum) {
  if (!tx.sIn.length && !tx.sOut.length) return 0n;
  return tInSum - tx.tOut.reduce((a, o) => a + o.amount, 0n) - tx.fee;
}
export { INF };
