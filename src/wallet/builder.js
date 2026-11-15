// Building and signing transactions (any transparent/private mix).
//
// tInputs:  [{ outpoint:{txid,index}, amount, signer }]   (signer = key in the vault, src/crypto/vault.js)
//           or { …, x } with the raw private key (tests, tools)
//           or { outpoint, amount, policy, path? } — multisig: the witness gets a placeholder of
//           the exact size and is filled in later by the signers
//           or { outpoint, amount, x, pq:{ sPub, mldsa:{priv,pub} } } — quantum-safe address (krq1…):
//           hybrid Schnorr + ML-DSA-44 signature
//           + prefix (optional): bytes before the signature (e.g. a name commitment reveal)
// sInputs:  [{ outpoint, amount, mask, spend (or raw p), P, C, fcmp:{ branch, anchor, path, leafPos } }]
//           — full-chain membership proof (default); or, on simnet only (legacy):
//           [{ outpoint, amount, mask, p, ring:[{outpoint, P, C}] }]     (ring includes the real one)
// outputs:  [{ type:'t', lock, amount } | { type:'s', A, B, amount }]
// change:   change output (same format, without amount) — used if value is left over
// feeRate:  grains per gram of mass
// memo:     optional text, encrypted to the recipient of the 1st private output (only they read it)
// sweep:    instead of outputs, ONE output that takes everything minus the fee (renew / reclaim)
// extraFee: additional fee on top of the mass fee (e.g. the yearly fee of an @name)

import { randomScalar, modN } from '../crypto/secp256k1.js';
import { schnorrSign } from '../crypto/schnorr.js';
import { commit } from '../crypto/pedersen.js';
import { makeShieldedOutput, encryptMemo } from '../crypto/stealth.js';
import { proveRange, rangeProofSize } from '../crypto/bulletproofs.js';
import { clsagSign, keyImage, encodeClsag, clsagSize } from '../crypto/clsag.js';
import { fcmpProve, fcmpFinish, fcmpProofSize } from '../fcmp/fcmp.js';
import { Transaction } from '../consensus/tx.js';
import { computeMass, storageMass } from '../consensus/mass.js';
import { toHex } from '../util/bytes.js';
import { witnessSize } from '../consensus/policy.js';
import { PQ_WITNESS_SIZE, PQ_WITNESS_VERSION, encodePqWitness } from '../consensus/pqlock.js';
import { mldsaSign } from '../crypto/pq.js';

// placeholder with the right version byte, so the mass is measured exactly
const pqPlaceholder = () => { const w = Buffer.alloc(PQ_WITNESS_SIZE); w[0] = PQ_WITNESS_VERSION; return w; };

const withPrefix = (i, w) => (i.prefix ? Buffer.concat([i.prefix, w]) : w);
// signature of a transparent input: by the vault (signer) or with the raw key (x)
const signT = (i, msg) => (i.signer ? i.signer.sign(msg) : schnorrSign(i.x, msg));
const signPq = (i, msg) => (i.pq.mldsa.sign ? i.pq.mldsa.sign(msg) : mldsaSign(i.pq.mldsa.priv, msg));
const kiOf = (si, P) => (si.spend ? si.spend.keyImage(P) : keyImage(si.p, P));

const DUST_T = 100_000n; // transparent change smaller than this becomes fee (avoids high storage mass)

function assembleBody({ tInputs, sInputs, outputs, fee, payload, memo }) {
  const sSecrets = [];
  const rs = [];   // one secret r_j per private output (R_j = r_j·D goes in the output itself)
  let firstSS = null;
  const tOut = [], sOut = [];
  for (const o of outputs) {
    if (o.type === 't') tOut.push({ amount: o.amount, lock: o.lock });
    else {
      const r = randomScalar();
      const so = makeShieldedOutput({ A: o.A, B: o.B }, r, sOut.length, o.amount);
      if (firstSS === null) firstSS = so.ss;
      rs.push(r);
      sOut.push({ R: so.R.toBytes(), P: so.P.toBytes(), C: so.C.toBytes(), encAmount: so.encAmount, viewTag: so.viewTag });
      sSecrets.push({ v: o.amount, x: so.x });
    }
  }
  // Every transaction with a private output carries a fixed-size memo block (empty if there is
  // no text): observers cannot tell transactions with and without a message apart.
  if (firstSS !== null) payload = encryptMemo(memo ?? '', firstSS, 0);
  const pseudoMasks = sInputs.map(() => randomScalar());
  const sIn = sInputs.map((si, i) => {
    if (si.fcmp) {
      return {
        ring: [], anchor: si.fcmp.anchor,
        pseudo: commit(si.amount, pseudoMasks[i]).toBytes(),
        keyImage: kiOf(si, si.P).toBytes(),
        fcmp: Buffer.alloc(fcmpProofSize(si.fcmp.anchor, si.fcmp.branch)),
      };
    }
    const real = si.ring.find((m) => toHex(m.outpoint.txid) === toHex(si.outpoint.txid) && m.outpoint.index === si.outpoint.index);
    if (!real) throw new Error('the ring does not contain the real output');
    return {
      ring: si.ring.map((m) => m.outpoint),
      pseudo: commit(si.amount, pseudoMasks[i]).toBytes(),
      keyImage: kiOf(si, real.P).toBytes(),
      clsag: Buffer.alloc(clsagSize(si.ring.length)),
    };
  });
  const tx = new Transaction({
    tIn: tInputs.map((i) => ({ outpoint: i.outpoint, sig: withPrefix(i, i.pq ? pqPlaceholder() : Buffer.alloc(i.policy ? witnessSize(i.policy, i.path ?? 0) : 64)) })),
    sIn, tOut, sOut, fee, payload: payload ?? Buffer.alloc(0),
    rangeProof: sOut.length ? Buffer.alloc(rangeProofSize(sOut.length)) : Buffer.alloc(0),
    bindingSig: (sIn.length || sOut.length) ? Buffer.alloc(64) : null,
  });
  return { tx, r: rs[0] ?? null, sSecrets, pseudoMasks };
}

function measure(parts, params) {
  const { tx } = assembleBody(parts);
  tx.mass = 0xffffffff; // fixed field size
  tx.invalidate();
  const cm = computeMass(tx, params);
  const sm = storageMass(tx, parts.tInputs.map((i) => i.amount), params);
  return Math.max(cm, sm);
}

/**
 * Builds and signs. Returns { tx, fee, change, r } (r = secret of the 1st private output, serves as
 * proof of payment for private outputs).
 */
export function buildTransaction({ params, tInputs = [], sInputs = [], outputs, change, feeRate = params.minRelayFeeRate, payload, memo, sweep, extraFee = 0n }) {
  if (sweep) return buildSweep({ params, tInputs, sInputs, sweep, feeRate, payload, memo, extraFee });
  if (!outputs.length) throw new Error('no outputs');
  if (memo && outputs[0].type !== 's') {
    throw new Error('a memo is only possible in payments to a private address (krs1…): in a transparent payment it would be public');
  }
  const inTotal = tInputs.reduce((a, i) => a + i.amount, 0n) + sInputs.reduce((a, i) => a + i.amount, 0n);
  const outTotal = outputs.reduce((a, o) => a + o.amount, 0n);
  let fee = 0n, outs = outputs, mass = 0, changeAmt = 0n, done = false;
  for (let iter = 0; iter < 20 && !done; iter++) {
    const rest = inTotal - outTotal - fee;
    if (rest < 0n) throw new Error(`insufficient balance (missing ${-rest} grains)`);
    outs = outputs; changeAmt = 0n;
    if (rest > 0n && change && !(change.type === 't' && rest < DUST_T)) {
      outs = [...outputs, { ...change, amount: rest }];
      changeAmt = rest;
    }
    const effFee = inTotal - outTotal - changeAmt; // without change, the leftover becomes fee
    mass = measure({ tInputs, sInputs, outputs: outs, fee: 0n, payload, memo }, params);
    const need = BigInt(mass) * feeRate + extraFee;
    if (effFee >= need) { fee = effFee; done = true; } else fee = need;
  }
  if (!done) throw new Error('could not compute the fee');
  return finish({ params, tInputs, sInputs, outs, fee, mass, payload, memo, changeAmt });
}

/** A single output with the whole balance of the inputs, minus the fee. */
function buildSweep({ params, tInputs, sInputs, sweep, feeRate, payload, memo, extraFee = 0n }) {
  const inTotal = tInputs.reduce((a, i) => a + i.amount, 0n) + sInputs.reduce((a, i) => a + i.amount, 0n);
  let fee = 0n, mass = 0, outs, done = false;
  for (let iter = 0; iter < 20 && !done; iter++) {
    if (inTotal - fee <= 0n) throw new Error('insufficient balance to pay the fee');
    outs = [{ ...sweep, amount: inTotal - fee }];
    mass = measure({ tInputs, sInputs, outputs: outs, fee: 0n, payload, memo }, params);
    const need = BigInt(mass) * feeRate + extraFee;
    if (fee >= need) done = true; else fee = need;
  }
  if (!done) throw new Error('could not compute the fee');
  return finish({ params, tInputs, sInputs, outs, fee, mass, payload, memo, changeAmt: 0n });
}

function finish({ params, tInputs, sInputs, outs, fee, mass, payload, memo, changeAmt }) {
  if (mass > params.maxTxMass) throw new Error(`transaction too heavy (${mass} > ${params.maxTxMass}); use fewer inputs or larger amounts`);

  const { tx, r, sSecrets, pseudoMasks } = assembleBody({ tInputs, sInputs, outputs: outs, fee, payload, memo });
  tx.mass = mass;
  if (sSecrets.length) {
    tx.rangeProof = proveRange(sSecrets.map((s) => s.v), sSecrets.map((s) => s.x)).proof;
  }
  tx.invalidate();
  const msg = tx.sighash(); // the body (including mass and fee) is final; signatures do not change the id
  tInputs.forEach((i, n) => {
    if (i.policy) return; // multisig: the signers fill it in later
    const w = i.pq ? encodePqWitness(i.pq.sPub, i.pq.mldsa.pub, signT(i, msg), signPq(i, msg)) : signT(i, msg);
    tx.tIn[n].sig = withPrefix(i, w);
  });
  sInputs.forEach((si, n) => {
    if (si.fcmp) {
      const { branch, anchor, path, leafPos } = si.fcmp;
      const secrets = { p: si.p, spend: si.spend, x: si.mask, v: si.amount, pseudoMask: pseudoMasks[n], msg };
      // expensive part already prepared (in parallel, see src/fcmp/parallel.js) or everything here, sequentially
      const { proof } = si.fcmp.pre ? fcmpFinish(si.fcmp.pre, { ...secrets, P: si.P })
        : fcmpProve({ branch, N: anchor, path, leafPos, C: si.C, ...secrets, P: si.P });
      tx.sIn[n].fcmp = proof;
      return;
    }
    const ring = si.ring.map((m) => ({ P: m.P, C: m.C }));
    const pi = si.ring.findIndex((m) => toHex(m.outpoint.txid) === toHex(si.outpoint.txid) && m.outpoint.index === si.outpoint.index);
    const pseudo = commit(si.amount, pseudoMasks[n]);
    const z = modN(si.mask - pseudoMasks[n]);
    const sig = si.spend ? si.spend.clsag(msg, ring, pseudo, pi, z) : clsagSign(msg, ring, pseudo, pi, si.p, z);
    tx.sIn[n].clsag = encodeClsag(sig);
  });
  if (tx.bindingSig) {
    let e = pseudoMasks.reduce((a, x) => a + x, 0n) - sSecrets.reduce((a, s) => a + s.x, 0n);
    e = modN(e);
    tx.bindingSig = schnorrSign(e, msg, 'binding');
  }
  tx.invalidate();
  return { tx, fee, change: changeAmt, r };
}
