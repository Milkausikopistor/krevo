import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getParams, COIN } from '../src/params.js';
import { Consensus } from '../src/consensus/consensus.js';
import { Keys } from '../src/wallet/keys.js';
import { buildTransaction } from '../src/wallet/builder.js';
import { schnorrSign } from '../src/crypto/schnorr.js';
import { encodePolicyPaths, parsePolicy, multisigLock, encodeWitness, verifyMultisigWitness, witnessDelay, MAX_PATHS } from '../src/consensus/policy.js';
import { multisigKey, encodeMultisigKey, MultisigGroup, parseWait } from '../src/wallet/multisig.js';
import { toHex } from '../src/util/bytes.js';
import { Clock, mine, matureTUtxos, tUtxos } from './helpers.js';

const params = getParams('simnet');

test('inheritance: policy with paths and a wait', () => {
  const [owner, h1, h2] = [Keys.random(), Keys.random(), Keys.random()].map(multisigKey);
  const g = MultisigGroup.createInheritance(params, encodeMultisigKey(params, owner.P), [h1.P, h2.P].map((P) => encodeMultisigKey(params, P)), 1, 315_576_000, 'Grandma');
  assert.ok(g.isInheritance);
  assert.deepEqual(g.paths.map((p) => [p.m, p.n, p.delay]), [[1, 1, 0], [1, 2, 315_576_000]]);
  assert.equal(MultisigGroup.fromDescriptor(params, g.descriptor).address, g.address);
  // changing the wait changes the address (the wait is part of the commitment)
  assert.notEqual(MultisigGroup.createInheritance(params, owner.P, [h1.P, h2.P], 1, 100, 'x').address, g.address);
  const msg = Buffer.from('tx');
  const wOwner = encodeWitness(g.bytes, new Map([[0, owner.signer.sign(msg)]]), 0);
  const wHeir = encodeWitness(g.bytes, new Map([[g.indexOf(h2.P, 1), h2.signer.sign(msg)]]), 1);
  assert.ok(verifyMultisigWitness(g.lock, wOwner, msg));
  assert.ok(verifyMultisigWitness(g.lock, wHeir, msg));
  assert.equal(witnessDelay(wOwner), 0);
  assert.equal(witnessDelay(wHeir), 315_576_000);
  // the owner cannot use the heirs' path, nor an heir the owner's
  assert.equal(verifyMultisigWitness(g.lock, encodeWitness(g.bytes, new Map([[0, owner.signer.sign(msg)]]), 1), msg), false);
  assert.equal(verifyMultisigWitness(g.lock, encodeWitness(g.bytes, new Map([[0, h1.signer.sign(msg)]]), 0), msg), false);
  // forging an identical policy but without the wait does not open the original address
  const noWait = encodePolicyPaths([{ m: 1, keys: [owner.P], delay: 0 }, { m: 1, keys: [h1.P, h2.P], delay: 0 }]);
  const h1Idx = new MultisigGroup(params, noWait).indexOf(h1.P, 1); // the keys are sorted: the position varies
  const wForged = encodeWitness(noWait, new Map([[h1Idx, h1.signer.sign(msg)]]), 1);
  assert.ok(verifyMultisigWitness(multisigLock(noWait), wForged, msg));
  assert.equal(verifyMultisigWitness(g.lock, wForged, msg), false);
  assert.throws(() => encodePolicyPaths(Array.from({ length: MAX_PATHS + 1 }, () => ({ m: 1, keys: [owner.P], delay: 0 }))));
  assert.equal(parsePolicy(g.bytes).paths.length, 2);
  assert.equal(parseWait('1a', getParams('mainnet')), 315_576_000);
});

test('inheritance on the network: heir only after the wait; owner at any time; moving the funds renews', () => {
  const DELAY = 6;
  const c = new Consensus(params);
  const clock = new Clock();
  const alice = Keys.random(), heirWallet = Keys.random();
  const [owner, h1, h2] = [Keys.random(), Keys.random(), Keys.random()].map(multisigKey);
  const g = MultisigGroup.createInheritance(params, owner.P, [h1.P, h2.P], 1, DELAY, 'Grandma');
  const mineN = (n, txs = []) => { for (let i = 0; i < n; i++) mine(c, alice.tKey(0).lock, i === 0 ? txs : [], clock); };
  mineN(30);

  const fund = buildTransaction({ params, tInputs: matureTUtxos(c, alice).slice(0, 10), outputs: [{ type: 't', lock: g.lock, amount: 4n * COIN }], change: { type: 't', lock: alice.tKey(0).lock } });
  mineN(1, [fund.tx]);
  const coin = () => {
    const u = c.utxosByLock(toHex(g.lock))[0];
    const [txid, index] = u.key.split(':');
    return { outpoint: { txid: Buffer.from(txid, 'hex'), index: Number(index) }, amount: u.amount, policy: g.bytes };
  };
  const signed = (inp, path, signer, outputs) => {
    const { tx } = buildTransaction({ params, tInputs: [{ ...inp, path }], ...outputs });
    const idx = g.indexOf(signer.P, path);
    tx.tIn[0].sig = encodeWitness(g.bytes, new Map([[idx, signer.signer.sign(tx.sighash())]]), path);
    tx.invalidate();
    return tx;
  };
  const toHeir = { sweep: { type: 't', lock: heirWallet.tKey(0).lock } };

  // 1) the heir tries right away: the network ignores it (time-locked)
  const early = signed(coin(), 1, h2, toHeir);
  mineN(1, [early]);
  assert.equal(c.txStatus(early.idHex).status, 'unknown');

  // 2) the owner spends part now (no wait); the change goes back to the plan with age zero
  const ownerSpend = signed(coin(), 0, owner, { outputs: [{ type: 't', lock: alice.tKey(0).lock, amount: COIN }], change: { type: 't', lock: g.lock } });
  mineN(1, [ownerSpend]);
  assert.equal(c.txStatus(ownerSpend.idHex).status, 'accepted');

  // 3) only part of the wait has passed since the movement: still locked
  mineN(DELAY - 3);
  const stillEarly = signed(coin(), 1, h1, toHeir);
  mineN(1, [stillEarly]);
  assert.equal(c.txStatus(stillEarly.idHex).status, 'unknown', 'the owner\'s movement renewed the wait');

  // 4) after the full wait, the heir claims everything
  mineN(DELAY);
  const claim = signed(coin(), 1, h1, toHeir);
  mineN(1, [claim]);
  assert.equal(c.txStatus(claim.idHex).status, 'accepted');
  assert.equal(c.utxosByLock(toHex(g.lock)).length, 0, 'plan emptied');
  assert.equal(tUtxos(c, heirWallet)[0].amount, 3n * COIN - ownerSpend.fee - claim.fee);
});
