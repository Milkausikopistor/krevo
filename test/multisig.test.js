import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getParams, COIN } from '../src/params.js';
import { Consensus } from '../src/consensus/consensus.js';
import { Keys } from '../src/wallet/keys.js';
import { buildTransaction } from '../src/wallet/builder.js';
import { schnorrSign } from '../src/crypto/schnorr.js';
import { randomScalar } from '../src/crypto/secp256k1.js';
import { encodePolicy, multisigLock, encodeWitness, verifyMultisigWitness } from '../src/consensus/policy.js';
import { multisigKey, encodeMultisigKey, MultisigGroup } from '../src/wallet/multisig.js';
import { decodeAddress } from '../src/address.js';
import { toHex } from '../src/util/bytes.js';
import { Clock, mine, matureTUtxos, tUtxos } from './helpers.js';

const params = getParams('simnet');

test('multisig: canonical policy, address, validity rules', () => {
  const [k1, k2, k3, out] = [Keys.random(), Keys.random(), Keys.random(), Keys.random()].map(multisigKey);
  const strs = [k1, k2, k3].map((k) => encodeMultisigKey(params, k.P));
  const g = MultisigGroup.create(params, 2, strs, 'Empresa');
  assert.match(g.address, /^krvsim1/);
  assert.equal(decodeAddress(params, g.address).type, 'm');
  // the order of the keys does not matter; the descriptor recreates the same group
  assert.equal(MultisigGroup.create(params, 2, [strs[2], strs[0], strs[1]]).address, g.address);
  assert.equal(MultisigGroup.fromDescriptor(params, g.descriptor).address, g.address);
  assert.notEqual(MultisigGroup.create(params, 3, strs).address, g.address, '3-of-3 is another address');
  assert.throws(() => MultisigGroup.create(params, 4, strs), /invalid policy/);
  assert.throws(() => MultisigGroup.create(params, 1, [strs[0], strs[0]]), /repeated/);

  const msg = Buffer.from('transaction message');
  const sig = (k) => k.signer.sign(msg);
  const idx = (k) => g.indexOf(k.P);
  const good = encodeWitness(g.bytes, new Map([[idx(k1), sig(k1)], [idx(k3), sig(k3)]]));
  assert.ok(verifyMultisigWitness(g.lock, good, msg), '2-of-3 valid');
  // only 1 signature
  assert.throws(() => encodeWitness(g.bytes, new Map([[idx(k1), sig(k1)]])), /missing signatures/);
  const one = Buffer.concat([g.bytes, Buffer.from([1, idx(k1)]), sig(k1)]);
  assert.equal(verifyMultisigWitness(g.lock, one, msg), false);
  // the same person signing twice
  const twice = Buffer.concat([g.bytes, Buffer.from([2, idx(k1)]), sig(k1), Buffer.from([idx(k1)]), sig(k1)]);
  assert.equal(verifyMultisigWitness(g.lock, twice, msg), false);
  // an outsider signing in place of a participant
  const outsider = encodeWitness(g.bytes, new Map([[idx(k1), sig(k1)], [idx(k2), out.signer.sign(msg)]]));
  assert.equal(verifyMultisigWitness(g.lock, outsider, msg), false);
  // valid signatures, but from another transaction
  assert.equal(verifyMultisigWitness(g.lock, good, Buffer.from('another transaction')), false);
  // swapping the policy (e.g. turning it into 1-of-3) does not match the address hash
  const p1 = encodePolicy(1, [k1.P, k2.P, k3.P]);
  const w1 = Buffer.concat([p1, Buffer.from([1, 0]), [k1, k2, k3].find((k) => k.P.toBytes().equals(p1.subarray(3, 36))).signer.sign(msg)]);
  assert.ok(verifyMultisigWitness(multisigLock(p1), w1, msg), 'valid for the 1-of-3 address…');
  assert.equal(verifyMultisigWitness(g.lock, w1, msg), false, '…but not for the 2-of-3 address');
});

test('multisig on the network: 2-of-3 spends, 1-of-3 does not', () => {
  const c = new Consensus(params);
  const clock = new Clock();
  const alice = Keys.random(), carol = Keys.random();
  const ks = [Keys.random(), Keys.random(), Keys.random()].map(multisigKey);
  const g = MultisigGroup.create(params, 2, ks.map((k) => encodeMultisigKey(params, k.P)));
  for (let i = 0; i < 30; i++) mine(c, alice.tKey(0).lock, [], clock);

  // Alice deposits 3 KRV at the group's address
  const fund = buildTransaction({ params, tInputs: matureTUtxos(c, alice).slice(0, 12), outputs: [{ type: 't', lock: g.lock, amount: 3n * COIN }], change: { type: 't', lock: alice.tKey(0).lock } });
  mine(c, alice.tKey(0).lock, [fund.tx], clock);
  const gu = c.utxosByLock(toHex(g.lock));
  assert.equal(gu.length, 1);
  assert.equal(gu[0].amount, 3n * COIN);

  const spend = () => buildTransaction({
    params, tInputs: [{ outpoint: { txid: fund.tx.id, index: 0 }, amount: 3n * COIN, policy: g.bytes }],
    outputs: [{ type: 't', lock: carol.tKey(0).lock, amount: COIN }], change: { type: 't', lock: g.lock },
  }).tx;

  // attempt with only one signature: the block gets in, the transaction does not
  const bad = spend();
  const sig0 = ks[0].signer.sign(bad.sighash());
  bad.tIn[0].sig = Buffer.concat([g.bytes, Buffer.from([1, g.indexOf(ks[0].P)]), sig0, Buffer.alloc(65)]); // same size, 1 signature
  bad.invalidate();
  mine(c, alice.tKey(0).lock, [bad], clock);
  assert.equal(c.txStatus(bad.idHex).status, 'unknown');
  assert.equal(tUtxos(c, carol).length, 0);

  // two signatures (participants 2 and 3, in any order): accepted
  const ok = spend();
  const msg = ok.sighash();
  ok.tIn[0].sig = encodeWitness(g.bytes, new Map([ks[2], ks[1]].map((k) => [g.indexOf(k.P), k.signer.sign(msg)])));
  ok.invalidate();
  mine(c, alice.tKey(0).lock, [ok], clock);
  assert.equal(c.txStatus(ok.idHex).status, 'accepted');
  assert.equal(tUtxos(c, carol)[0].amount, COIN);
  const left = c.utxosByLock(toHex(g.lock));
  assert.equal(left.length, 1, 'the change went back to the group');
  assert.equal(left[0].amount, 2n * COIN - ok.fee);
  assert.ok(ok.fee < 20_000n, `small fee: ${ok.fee} grains`);
  void randomScalar;
});
