// Human-readable names (@name): format, consensus rules (commitment/reveal, fee, owner,
// expiry, grace period) and the full flow in the wallet (register, pay to @name, update,
// transfer to a quantum-safe address, renew, release).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getParams, COIN } from '../src/params.js';
import { Consensus } from '../src/consensus/consensus.js';
import { Keys } from '../src/wallet/keys.js';
import { buildTransaction } from '../src/wallet/builder.js';
import { validateTxStateless } from '../src/consensus/txvalidation.js';
import { parseAddressData, describeLock } from '../src/address.js';
import {
  checkName, isValidName, normalizeName, nameFee, encodeNameRecord, parseNameRecord, nameCommitHash, nameCommitLock,
  commitWitnessPrefix, parseCommitWitness,
} from '../src/consensus/names.js';
import { Clock, mine, matureTUtxos, freePorts } from './helpers.js';
import { Node } from '../src/node/node.js';
import { Wallet } from '../src/wallet/wallet.js';
import { rpc } from '../src/node/rpcclient.js';
import { Block } from '../src/consensus/block.js';
import { solve } from '../src/node/solver.js';
import { fromHex, toHex } from '../src/util/bytes.js';
import { nameCommit, nameReveal, nameRevealWait, nameUpdate, nameTransfer, nameRenew, nameRelease, myNames } from '../src/wallet/names.js';

const params = getParams('simnet');
const DEP = params.nameMinDeposit;

test('names: syntax, fees by length and record format', () => {
  assert.equal(normalizeName('  @Bakery '), 'bakery');
  for (const ok of ['abc', 'sun-bakery', 'shop24', 'a1b', 'x'.repeat(32)]) assert.ok(isValidName(ok), ok);
  for (const bad of ['ab', '-abc', 'abc-', 'a--b', 'açaí', 'pão', 'ABC', 'a b c', 'x'.repeat(33), 'a_b', 'xn--abc']) assert.equal(isValidName(bad), false, bad);
  assert.throws(() => checkName('@pão'), /invalid name/);
  assert.equal(nameFee(params, 'abc'), 100n * COIN);
  assert.equal(nameFee(params, 'abcd'), 20n * COIN);
  assert.equal(nameFee(params, 'abcde'), 5n * COIN);
  assert.equal(nameFee(params, 'bakery'), COIN);
  const k = Keys.random();
  const rec = { name: 'bakery', expiry: 123456, owner: k.tKey(0).lock, target: k.shieldedData };
  const lock = encodeNameRecord(rec);
  assert.deepEqual(parseNameRecord(lock), rec);
  assert.equal(parseAddressData(lock).type, 'n');
  assert.equal(describeLock(params, lock), '@bakery (name record)');
  const salt = Buffer.alloc(32, 7);
  const w = Buffer.concat([commitWitnessPrefix('bakery', salt, rec.owner), Buffer.alloc(64, 1)]);
  const c = parseCommitWitness(w);
  assert.equal(c.name, 'bakery');
  assert.ok(nameCommitHash(c.name, c.salt, c.owner).equals(nameCommitHash('bakery', salt, rec.owner)));
  assert.equal(c.inner.length, 64);
});

/** Helpers to build name transactions directly against consensus. */
function nameKit(c, clock, funder) {
  const daa = () => c.virtual.gd.daaScore;
  const mineN = (n, txs = []) => { for (let i = 0; i < n; i++) mine(c, funder.tKey(0).lock, i === 0 ? txs : [], clock); };
  const fund = (keys, n = 4) => matureTUtxos(c, keys).sort((a, b) => (a.amount > b.amount ? -1 : 1)).slice(0, n);
  const status = (tx) => c.txStatus(tx.idHex).status;
  const commit = (owner, name, salt) => buildTransaction({
    params, tInputs: fund(owner), outputs: [{ type: 't', lock: nameCommitLock(nameCommitHash(name, salt, owner.tKey(0).lock)), amount: 1_000_000n }],
    change: { type: 't', lock: owner.tKey(0).lock },
  }).tx;
  const reveal = (owner, name, salt, commitTx, { target = owner.shieldedData, fee = nameFee(params, name), expiry = daa() + params.namePeriod - 5, payer = owner } = {}) => buildTransaction({
    params,
    tInputs: [{ outpoint: { txid: commitTx.id, index: 0 }, amount: 1_000_000n, signer: owner.tKey(0).signer, prefix: commitWitnessPrefix(name, salt, owner.tKey(0).lock) }, ...fund(payer)],
    outputs: [{ type: 't', lock: encodeNameRecord({ name, expiry, owner: owner.tKey(0).lock, target }), amount: DEP }],
    change: { type: 't', lock: payer.tKey(0).lock }, extraFee: fee,
  }).tx;
  const record = (name) => {
    const live = c.virtual.view.nameEntries(name).map(({ key, e }) => ({ key, e, r: parseNameRecord(e.lock) }))
      .filter((x) => daa() <= x.r.expiry + params.nameGrace);
    return live[0] ?? null;
  };
  /** Spends the current record (signed by `signer`) recreating it with changes. */
  const spendRecord = (name, signer, payer, { target, owner, expiry, fee = 0n, release = false } = {}) => {
    const cur = record(name);
    const [txid, index] = cur.key.split(':');
    const input = { outpoint: { txid: Buffer.from(txid, 'hex'), index: Number(index) }, amount: cur.e.amount, signer: signer.tKey(0).signer };
    if (release) return buildTransaction({ params, tInputs: [input], sweep: { type: 't', lock: signer.tKey(0).lock } }).tx;
    const lock = encodeNameRecord({ name, expiry: expiry ?? cur.r.expiry, owner: owner ?? cur.r.owner, target: target ?? cur.r.target });
    return buildTransaction({ params, tInputs: [input, ...fund(payer)], outputs: [{ type: 't', lock, amount: cur.e.amount }], change: { type: 't', lock: payer.tKey(0).lock }, extraFee: fee }).tx;
  };
  return { daa, mineN, fund, status, commit, reveal, record, spendRecord };
}

test('consensus: commitment → reveal, a single owner, fee to the Fund, update, renew, expire', () => {
  const c = new Consensus(params);
  const clock = new Clock();
  const alice = Keys.random(), bob = Keys.random();
  for (let i = 0; i < 40; i++) mine(c, alice.tKey(0).lock, [], clock);
  for (let i = 0; i < 40; i++) mine(c, bob.tKey(0).lock, [], clock);
  const k = nameKit(c, clock, alice);
  const saltA = Buffer.alloc(32, 0xa1), saltB = Buffer.alloc(32, 0xb2);

  // 1) Alice's commitment; revealing too early is ignored
  const cA = k.commit(alice, 'bakery', saltA);
  k.mineN(1, [cA]);
  const early = k.reveal(alice, 'bakery', saltA, cA);
  k.mineN(1, [early]);
  assert.equal(k.status(early), 'unknown', 'reveal before the minimum wait');
  k.mineN(params.nameCommitMin);
  // 2) without the fee: rejected; with the fee: registered
  const cheap = k.reveal(alice, 'bakery', saltA, cA, { fee: 0n });
  k.mineN(1, [cheap]);
  assert.equal(k.status(cheap), 'unknown', 'record without the fee');
  const ok = k.reveal(alice, 'bakery', saltA, cA);
  k.mineN(2, [ok]);
  assert.equal(k.status(ok), 'accepted');
  let rec = k.record('bakery');
  assert.ok(rec.r.owner.equals(alice.tKey(0).lock));
  assert.ok(rec.r.target.equals(alice.shieldedData));
  // the whole fee went to the Security Fund (not to the miner)
  const nameFees = [...c.acc.values()].reduce((a, x) => a + (x.nameFees ?? 0n), 0n);
  assert.equal(nameFees, nameFee(params, 'bakery'));

  // 3) Bob cannot register the same name, even with a mature commitment
  const cB = k.commit(bob, 'bakery', saltB);
  k.mineN(1 + params.nameCommitMin, [cB]);
  const steal = k.reveal(bob, 'bakery', saltB, cB);
  k.mineN(1, [steal]);
  assert.equal(k.status(steal), 'unknown', 'the name already has an owner');
  // ...nor touch Alice's record
  const hijack = k.spendRecord('bakery', bob, bob, { target: bob.shieldedData });
  k.mineN(1, [hijack]);
  assert.equal(k.status(hijack), 'unknown', 'only the owner updates');

  // 4) Alice changes the destination (no fee) — but cannot stretch the expiry without paying
  const upd = k.spendRecord('bakery', alice, alice, { target: alice.tKey(0).lock });
  k.mineN(1, [upd]);
  assert.equal(k.status(upd), 'accepted');
  assert.ok(k.record('bakery').r.target.equals(alice.tKey(0).lock));
  const stretch = k.spendRecord('bakery', alice, alice, { expiry: k.record('bakery').r.expiry + 50 });
  k.mineN(1, [stretch]);
  assert.equal(k.status(stretch), 'unknown', 'stretching the expiry without the fee');
  const oldExpiry = k.record('bakery').r.expiry;
  const renew = k.spendRecord('bakery', alice, alice, { expiry: oldExpiry + 100, fee: nameFee(params, 'bakery') });
  k.mineN(1, [renew]);
  assert.equal(k.status(renew), 'accepted', 'paid renewal');
  rec = k.record('bakery');
  assert.equal(rec.r.expiry, oldExpiry + 100);

  // 5) expired, but in the grace period: only the owner can renew; Bob cannot register yet
  k.mineN(rec.r.expiry - k.daa() + 2);
  assert.ok(k.daa() > rec.r.expiry);
  const cB2 = k.commit(bob, 'bakery', Buffer.alloc(32, 0xb3));
  k.mineN(1 + params.nameCommitMin, [cB2]);
  const graceSteal = k.reveal(bob, 'bakery', Buffer.alloc(32, 0xb3), cB2);
  k.mineN(1, [graceSteal]);
  assert.equal(k.status(graceSteal), 'unknown', 'the grace period protects the owner');
  const noFee = k.spendRecord('bakery', alice, alice, { target: alice.shieldedData });
  k.mineN(1, [noFee]);
  assert.equal(k.status(noFee), 'unknown', 'in the grace period, updating without renewing does not count');

  // 6) after the grace period the name is free: Bob registers; the former owner gets the deposit back
  k.mineN(rec.r.expiry + params.nameGrace - k.daa() + 2);
  const cB3 = k.commit(bob, 'bakery', Buffer.alloc(32, 0xb4));
  k.mineN(1 + params.nameCommitMin, [cB3]);
  const bobReg = k.reveal(bob, 'bakery', Buffer.alloc(32, 0xb4), cB3);
  k.mineN(1, [bobReg]);
  assert.equal(k.status(bobReg), 'accepted', 'name free again');
  assert.ok(k.record('bakery').r.owner.equals(bob.tKey(0).lock));
  const dead = c.virtual.view.nameEntries('bakery').find((x) => parseNameRecord(x.e.lock).owner.equals(alice.tKey(0).lock));
  const [dtxid, dix] = dead.key.split(':');
  const refund = buildTransaction({ params, tInputs: [{ outpoint: { txid: Buffer.from(dtxid, 'hex'), index: Number(dix) }, amount: dead.e.amount, signer: alice.tKey(0).signer }], sweep: { type: 't', lock: alice.tKey(0).lock } }).tx;
  k.mineN(1, [refund]);
  assert.equal(k.status(refund), 'accepted', 'the deposit goes back to the former owner');
  assert.ok(k.record('bakery').r.owner.equals(bob.tKey(0).lock), 'and the name stays with Bob');
});

test('consensus: two records in the same transaction, an invalid owner and a miner with a name lock are rejected', () => {
  const k = Keys.random();
  const r1 = encodeNameRecord({ name: 'shop-one', expiry: 999, owner: k.tKey(0).lock, target: k.shieldedData });
  const r2 = encodeNameRecord({ name: 'shop-two', expiry: 999, owner: k.tKey(0).lock, target: k.shieldedData });
  const base = (outs) => buildTransaction({ params, tInputs: [{ outpoint: { txid: Buffer.alloc(32, 1), index: 0 }, amount: 10n * COIN, signer: k.tKey(0).signer }], outputs: outs, change: { type: 't', lock: k.tKey(0).lock } }).tx;
  assert.throws(() => validateTxStateless(base([{ type: 't', lock: r1, amount: DEP }, { type: 't', lock: r2, amount: DEP }]), params), /one name record/);
  const privOwner = encodeNameRecord({ name: 'shop-three', expiry: 999, owner: k.shieldedData, target: k.shieldedData });
  assert.throws(() => validateTxStateless(base([{ type: 't', lock: privOwner, amount: DEP }]), params), /owner of a name/);
  // a miner cannot create records through the coinbase
  const c = new Consensus(params);
  assert.throws(() => mine(c, r1, [], new Clock()));
});

async function mineVia(url, address, n) {
  for (let i = 0; i < n; i++) {
    const t = await rpc(url, 'getblocktemplate', { address });
    const b = Block.deserialize(fromHex(t.block));
    assert.ok(solve(b));
    const r = await rpc(url, 'submitblock', { block: toHex(b.serialize()) });
    assert.equal(r.status, 'accepted', r.reason);
  }
}

test('wallet on the network: register @bakery, pay to @bakery, update, transfer to krq, renew, release', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krv-names-'));
  const port = await freePorts(4);
  const node = new Node({ params, datadir: dir, p2pPort: port, rpcPort: port + 1, log: () => {}, persist: false });
  await node.start();
  const url = `http://127.0.0.1:${port + 1}`;
  try {
    const alice = Wallet.create(path.join(dir, 'a.json'), params, url);
    const bob = Wallet.create(path.join(dir, 'b.json'), params, url);
    const miner = Keys.random().tAddress(params);
    await mineVia(url, alice.tAddress, 30);
    await mineVia(url, bob.tAddress, 30);
    await mineVia(url, miner, 12);
    const mineN = (n = 1) => mineVia(url, miner, n);

    // two-step registration
    const c1 = await nameCommit(alice, '@Bakery', { target: 'private' });
    assert.equal(c1.name, 'bakery');
    assert.equal(c1.nameFee, COIN);
    await assert.rejects(() => nameReveal(alice, 'bakery'), /confirmed|wait/);
    await mineN(1);
    await assert.rejects(() => nameReveal(alice, 'bakery'), /wait/);
    await mineN(params.nameCommitMin);
    assert.equal(await nameRevealWait(alice, 'bakery'), 0);
    await nameReveal(alice, 'bakery');
    await mineN(1);
    let info = await alice.resolveName('@bakery');
    assert.equal(info.status, 'active');
    assert.equal(info.target, alice.sAddress, 'points to Alice\'s private address');
    assert.equal(info.owner, alice.tAddress);

    // Bob pays to @bakery — the payment goes to Alice's private address
    const pay = await bob.send({ to: '@bakery', amount: COIN });
    assert.equal(pay.name, 'bakery');
    assert.equal(pay.to, alice.sAddress);
    await mineN(1);
    await alice.sync();
    const b = alice.balance();
    assert.ok(b.shielded + b.shieldedImmature >= COIN, 'Alice received it as private');

    // name taken; only the owner updates
    await assert.rejects(() => nameCommit(bob, 'bakery'), /already has an owner/);
    await assert.rejects(() => nameUpdate(bob, 'bakery', 'private'), /does not belong/);
    await nameUpdate(alice, 'bakery', 'transparent');
    await mineN(1);
    assert.equal((await alice.resolveName('bakery')).target, alice.tAddress);

    // transfer to Bob's QUANTUM-SAFE address; Bob renews signing with Schnorr + ML-DSA
    await nameTransfer(alice, 'bakery', bob.qAddress);
    await mineN(1);
    info = await bob.resolveName('bakery');
    assert.equal(info.owner, bob.qAddress);
    const before = info.expiry;
    const rn = await nameRenew(bob, 'bakery');
    assert.equal(rn.nameFee, COIN);
    await mineN(1);
    assert.ok((await bob.resolveName('bakery')).expiry > before, 'renewed');
    assert.deepEqual((await myNames(bob)).map((x) => x.name), ['bakery']);
    assert.equal((await myNames(alice)).length, 0);
    const gi = await rpc(url, 'getinfo');
    assert.equal(gi.names, 1);

    // Bob releases the name: the deposit comes back and the name is free
    await nameRelease(bob, 'bakery');
    await mineN(1);
    assert.equal((await bob.resolveName('bakery')).status, 'free');
    await assert.rejects(() => alice.send({ to: '@bakery', amount: COIN }), /is not registered/);
  } finally {
    await node.stop();
  }
});
