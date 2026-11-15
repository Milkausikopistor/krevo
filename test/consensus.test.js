import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getParams, COIN, MAX_SUPPLY } from '../src/params.js';
import { Consensus } from '../src/consensus/consensus.js';
import { Block } from '../src/consensus/block.js';
import { Keys } from '../src/wallet/keys.js';
import { buildTransaction } from '../src/wallet/builder.js';
import { scheduledSubsidy } from '../src/consensus/emission.js';
import { toHex } from '../src/util/bytes.js';
import { Clock, mine, tUtxos, matureTUtxos, scanShielded, makeRing } from './helpers.js';
import { solve } from '../src/node/solver.js';

const params = getParams('simnet');

function sumT(c, keys) { return tUtxos(c, keys).reduce((a, u) => a + u.amount, 0n); }
function sumS(c, keys) { return scanShielded(c, keys).reduce((a, u) => a + u.amount, 0n); }

test('consensus: mining, rewards, transparent and private transactions, double spending and the supply invariant', () => {
  const c = new Consensus(params);
  const clock = new Clock();
  const alice = Keys.random(), bob = Keys.random(), carol = Keys.random(), miner2 = Keys.random();
  const A = alice.tKey(0).lock;

  // 1) Sequential mining: the genesis pays nothing (zero premine).
  for (let i = 0; i < 15; i++) mine(c, A, [], clock);
  assert.equal(c.virtual.gd.blueScore, 16);
  const sub = scheduledSubsidy(1, params);
  // 15 blocks mined; the virtual has already accepted the coinbase of the last selected parent,
  // which pays blocks 1..14 (block 15 will be paid by the next chain block).
  assert.equal(sumT(c, alice), sub * 14n);

  // 2) Parallel blocks (DAG): two miners on the same parents, both rewarded.
  const parents = c.virtual.parents.map(toHex);
  const b1 = mine(c, A, [], clock, parents);
  const b2 = mine(c, miner2.tKey(0).lock, [], clock, parents);
  assert.equal(c.tips.size, 2, 'duas pontas paralelas');
  mine(c, A, [], clock); // funde as duas pontas
  const gd = c.gd(c.virtual.gd.selectedParent);
  assert.equal(gd.mergesetBlues.length, 2, 'both parallel blocks are blue');
  mine(c, A, [], clock);
  assert.equal(sumT(c, miner2), sub, 'the parallel block\'s miner was paid');
  assert.ok(b1 && b2);

  // 3) Transparent transaction Alice → Bob.
  const inputs = matureTUtxos(c, alice).slice(0, 2);
  assert.ok(inputs.length === 2);
  const pay = buildTransaction({ params, tInputs: inputs, outputs: [{ type: 't', lock: bob.tKey(0).lock, amount: 3n * COIN / 10n }], change: { type: 't', lock: A } });
  mine(c, A, [pay.tx], clock);
  assert.equal(c.txStatus(pay.tx.idHex).status, 'accepted');
  assert.equal(sumT(c, bob), 3n * COIN / 10n);
  assert.ok(pay.fee > 0n && pay.fee < 10_000n, `negligible fee: ${pay.fee} grains`);

  // double spend of the same input: the block is valid, but the transaction is ignored.
  const dbl = buildTransaction({ params, tInputs: inputs, outputs: [{ type: 't', lock: carol.tKey(0).lock, amount: COIN / 10n }], change: { type: 't', lock: A } });
  mine(c, A, [dbl.tx], clock);
  assert.equal(c.txStatus(dbl.tx.idHex).status, 'unknown');
  assert.equal(sumT(c, carol), 0n);

  // 4) Shielding: transparent → private (several outputs to form the anonymity set),
  //    and mining straight to a private address (private coinbase).
  const shieldIn = matureTUtxos(c, alice).filter((u) => !inputs.some((i) => toHex(i.outpoint.txid) === toHex(u.outpoint.txid)));
  const sh = buildTransaction({
    params, tInputs: shieldIn.slice(0, 3),
    outputs: [
      { type: 's', A: bob.A, B: bob.B, amount: COIN / 2n },
      { type: 's', A: bob.A, B: bob.B, amount: COIN / 4n },
      { type: 's', A: carol.A, B: carol.B, amount: COIN / 8n },
    ],
    change: { type: 't', lock: A },
  });
  mine(c, A, [sh.tx], clock);
  assert.equal(c.txStatus(sh.tx.idHex).status, 'accepted');
  for (let i = 0; i < 12; i++) mine(c, miner2.shieldedData, [], clock);
  assert.equal(sumS(c, bob), COIN / 2n + COIN / 4n);
  assert.ok(sumS(c, miner2) > 0n, 'private coinbase received');

  // 5) Private → private with a ring.
  const bobOut = scanShielded(c, bob).find((o) => o.amount === COIN / 2n);
  const priv = buildTransaction({
    params, sInputs: [{ ...bobOut, ring: makeRing(c, bobOut) }],
    outputs: [{ type: 's', A: carol.A, B: carol.B, amount: COIN / 5n }],
    change: { type: 's', A: bob.A, B: bob.B },
  });
  assert.equal(priv.tx.tOut.length, 0);
  mine(c, A, [priv.tx], clock);
  assert.equal(c.txStatus(priv.tx.idHex).status, 'accepted');
  assert.equal(sumS(c, carol), COIN / 8n + COIN / 5n);
  assert.equal(sumS(c, bob), COIN / 4n + COIN / 2n - COIN / 5n - priv.fee);

  // private double spend (same output, another ring): same key image → rejected.
  const priv2 = buildTransaction({
    params, sInputs: [{ ...bobOut, ring: makeRing(c, bobOut) }],
    outputs: [{ type: 's', A: carol.A, B: carol.B, amount: COIN / 5n }],
    change: { type: 's', A: bob.A, B: bob.B },
  });
  mine(c, A, [priv2.tx], clock);
  assert.equal(c.txStatus(priv2.tx.idHex).status, 'unknown');

  // 6) Unshielding: private → transparent.
  for (let i = 0; i < 3; i++) mine(c, A, [], clock);
  const carolOuts = scanShielded(c, carol);
  const un = buildTransaction({
    params, sInputs: carolOuts.map((o) => ({ ...o, ring: makeRing(c, o) })),
    outputs: [{ type: 't', lock: carol.tKey(0).lock, amount: COIN / 4n }],
    change: { type: 's', A: carol.A, B: carol.B },
  });
  mine(c, A, [un.tx], clock);
  assert.equal(c.txStatus(un.tx.idHex).status, 'accepted');
  assert.equal(sumT(c, carol), COIN / 4n);

  // 7) Invariant: everything that exists = everything that was minted (nothing created from nothing).
  mine(c, A, [], clock);
  const sp = c.virtual.gd.selectedParent;
  const spAcc = c.acc.get(sp);
  const everyone = [alice, bob, carol, miner2];
  const total = everyone.reduce((a, k) => a + sumT(c, k) + sumS(c, k), 0n);
  assert.equal(total + spAcc.pool + c.virtual.acceptance.feeTotal, spAcc.minted);
  assert.ok(spAcc.minted <= MAX_SUPPLY);
});

test('consensus: reorganization — the heavier branch wins and the conflicting transaction is reverted', () => {
  const c = new Consensus(params);
  const clock = new Clock();
  const alice = Keys.random(), bob = Keys.random(), carol = Keys.random();
  const A = alice.tKey(0).lock;
  for (let i = 0; i < 14; i++) mine(c, A, [], clock);
  const coin = matureTUtxos(c, alice)[0];
  const toBob = buildTransaction({ params, tInputs: [coin], outputs: [{ type: 't', lock: bob.tKey(0).lock, amount: COIN / 10n }], change: { type: 't', lock: A } });
  const toCarol = buildTransaction({ params, tInputs: [coin], outputs: [{ type: 't', lock: carol.tKey(0).lock, amount: COIN / 10n }], change: { type: 't', lock: A } });

  // An "attacker" copies the current state and mines in secret.
  const attacker = new Consensus(params);
  const history = [...c.blocks.values()].filter((b) => b.header.parents.length).sort((x, y) => x.header.daaScore - y.header.daaScore);
  for (const b of history) assert.equal(attacker.addBlock(b, { now: clock.t + 1000 }).status, 'accepted');

  // branch A (public): 1 block with the payment to Bob
  const a1 = mine(c, A, [toBob.tx], clock);
  assert.equal(c.txStatus(toBob.tx.idHex).status, 'accepted');
  // branch B (secret, without merging A): 3 blocks, the first one pays Carol
  const bBlocks = [];
  for (let i = 0; i < 3; i++) bBlocks.push(mine(attacker, A, i === 0 ? [toCarol.tx] : [], clock));
  // Publishes branch B: it has more work; A is still a tip and gets merged as red/blue,
  // but in consensus order B's transaction comes first → Carol gets paid, Bob does not.
  for (const b of bBlocks) assert.equal(c.addBlock(b, { now: clock.t + 1000 }).status, 'accepted');
  assert.equal(c.virtual.gd.selectedParent, bBlocks[2].hashHex);
  assert.equal(c.txStatus(toCarol.tx.idHex).status, 'accepted');
  assert.equal(c.txStatus(toBob.tx.idHex).status, 'unknown');
  assert.equal(sumT(c, bob), 0n);
  assert.equal(sumT(c, carol), COIN / 10n);
  // every node reaches the same state regardless of the arrival order
  const c2 = new Consensus(params);
  const all = [...c.blocks.values()].filter((b) => b.header.parents.length).sort((x, y) => x.header.daaScore - y.header.daaScore);
  for (const b of all.reverse()) c2.addBlock(b, { now: clock.t + 1000 }); // reversed order: several orphans
  let pending = all.filter((b) => !c2.has(b.hashHex));
  while (pending.length) {
    for (const b of pending) c2.addBlock(b, { now: clock.t + 1000 });
    pending = pending.filter((b) => !c2.has(b.hashHex));
  }
  assert.equal(c2.virtual.gd.selectedParent, c.virtual.gd.selectedParent);
  assert.deepEqual(c2.virtual.acceptance.muhash.digest(), c.virtual.acceptance.muhash.digest());
  assert.ok(a1);
});

test('consensus: invalid blocks are rejected', () => {
  const c = new Consensus(params);
  const clock = new Clock();
  const alice = Keys.random();
  const A = alice.tKey(0).lock;
  for (let i = 0; i < 3; i++) mine(c, A, [], clock);

  // a coinbase paying more than it should → disqualified from the chain
  const t = clock.next();
  const greedy = c.buildTemplate(A, [], Buffer.alloc(0), t);
  greedy.txs[0].tOut[0].amount += 1n;
  greedy.txs[0].invalidate();
  greedy.header.hashMerkleRoot = (() => { const b = c.buildTemplate(A, [], Buffer.alloc(0), t); return b.header.hashMerkleRoot; })();
  // recomputes the correct Merkle root for the tampered coinbase
  const { merkleRoot } = awaitImport;
  greedy.header.hashMerkleRoot = merkleRoot(greedy.txs.map((x) => x.hash));
  assert.ok(solve(greedy));
  const r = c.addBlock(greedy, { now: t + 1000 });
  assert.equal(r.status, 'accepted');
  assert.equal(r.chainValid, false, 'a greedy coinbase is disqualified');
  assert.notEqual(c.virtual.gd.selectedParent, greedy.hashHex);

  // invalid PoW
  const t2 = clock.next();
  const bad = c.buildTemplate(A, [], Buffer.alloc(0), t2);
  bad.header.bits = 0x1d00ffff; // hard target, the nonce does not solve it
  const r2 = c.addBlock(new Block(bad.header, bad.txs), { now: t2 + 1000 });
  assert.equal(r2.status, 'invalid');

  // timestamp far in the future (policy): waits
  const t3 = clock.next();
  const fut = c.buildTemplate(A, [], Buffer.alloc(0), t3 + 10 * 60_000);
  assert.ok(solve(fut));
  assert.equal(c.addBlock(fut, { now: t3 }).status, 'future');
});

const awaitImport = await import('../src/consensus/block.js');
