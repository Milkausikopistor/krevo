// Quantum protection: hybrid krq address (Schnorr + ML-DSA-44) and the private pool turnstile.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getParams, COIN } from '../src/params.js';
import { Consensus } from '../src/consensus/consensus.js';
import { Mempool } from '../src/node/mempool.js';
import { Node } from '../src/node/node.js';
import { Wallet } from '../src/wallet/wallet.js';
import { rpc } from '../src/node/rpcclient.js';
import { Block } from '../src/consensus/block.js';
import { solve } from '../src/node/solver.js';
import { Keys } from '../src/wallet/keys.js';
import { buildTransaction } from '../src/wallet/builder.js';
import { schnorrSign } from '../src/crypto/schnorr.js';
import { mldsaKeyFromSeed, mldsaSign, mldsaVerify, MLDSA_PUB_SIZE, MLDSA_SIG_SIZE } from '../src/crypto/pq.js';
import { verifyPqWitness, encodePqWitness, isPqWitness, PQ_WITNESS_SIZE } from '../src/consensus/pqlock.js';
import { shieldedDelta } from '../src/consensus/txvalidation.js';
import { computeMass } from '../src/consensus/mass.js';
import { decodeAddress } from '../src/address.js';
import { parseOutpointKey, Transaction } from '../src/consensus/tx.js';
import { toHex, fromHex } from '../src/util/bytes.js';
import { Clock, mine, matureTUtxos, tUtxos, scanShielded, makeRing, freePorts } from './helpers.js';

const params = getParams('simnet');

async function mineVia(url, address, n) {
  for (let i = 0; i < n; i++) {
    const t = await rpc(url, 'getblocktemplate', { address });
    const b = Block.deserialize(fromHex(t.block));
    assert.ok(solve(b));
    const r = await rpc(url, 'submitblock', { block: toHex(b.serialize()) });
    assert.equal(r.status, 'accepted', r.reason);
  }
}

/** Mature coins of a quantum-safe address, ready for the builder. */
function qUtxos(c, keys) {
  const k = keys.qKey(0), daa = c.virtual.gd.daaScore;
  return c.utxosByLock(toHex(k.lock))
    .filter((u) => !u.coinbase || daa - u.daa >= c.params.coinbaseMaturity)
    .map((u) => ({ outpoint: parseOutpointKey(u.key), amount: u.amount, signer: k.signer, pq: k }));
}

test('ML-DSA-44: deterministic keys from the seed, signature and tampering', () => {
  const seed = randomBytes(32);
  const a = mldsaKeyFromSeed(seed), b = mldsaKeyFromSeed(Buffer.from(seed));
  assert.equal(a.pub.length, MLDSA_PUB_SIZE);
  assert.ok(a.pub.equals(b.pub), 'same seed → same key (recoverable from the phrase)');
  assert.ok(!mldsaKeyFromSeed(randomBytes(32)).pub.equals(a.pub));
  const msg = Buffer.from('transaction');
  const sig = mldsaSign(a.priv, msg);
  assert.equal(sig.length, MLDSA_SIG_SIZE);
  assert.ok(mldsaVerify(a.pub, msg, sig));
  assert.equal(mldsaVerify(a.pub, Buffer.from('other'), sig), false, 'another message');
  const bad = Buffer.from(sig); bad[100] ^= 1;
  assert.equal(mldsaVerify(a.pub, msg, bad), false, 'tampered signature');
  assert.equal(mldsaVerify(mldsaKeyFromSeed(randomBytes(32)).pub, msg, sig), false, 'someone else\'s key');
  assert.equal(mldsaVerify(a.pub, msg, sig.subarray(1)), false, 'wrong size');

  // the wallet derives the krq address from the seed: restoring gives the same address
  const s = randomBytes(32);
  const k1 = new Keys(s), k2 = new Keys(Buffer.from(s));
  assert.match(k1.qAddress(params), /^krqsim1/);
  assert.equal(k1.qAddress(params), k2.qAddress(params));
  assert.equal(decodeAddress(params, k1.qAddress(params)).type, 'q');
  assert.throws(() => decodeAddress(getParams('devnet'), k1.qAddress(params)), /another network/);
  assert.notEqual(k1.qAddress(params), Keys.random().qAddress(params));
});

test('hybrid witness: it needs BOTH signatures and the right keys', () => {
  const me = new Keys(randomBytes(32)).qKey(0), other = Keys.random().qKey(0);
  const msg = Buffer.from('transaction body');
  const w = (k, sSig, qSig) => encodePqWitness(k.sPub, k.mldsa.pub, sSig, qSig);
  const good = w(me, me.signer.sign(msg), me.mldsa.sign(msg));
  assert.equal(good.length, PQ_WITNESS_SIZE);
  assert.ok(isPqWitness(good));
  assert.ok(verifyPqWitness(me.lock, good, msg), 'valid');
  assert.equal(verifyPqWitness(me.lock, good, Buffer.from('another transaction')), false, 'replay in another transaction');

  // "broke the elliptic curve": has the Schnorr key, but not the ML-DSA one
  const forgedQ = w(me, me.signer.sign(msg), other.mldsa.sign(msg));
  assert.equal(verifyPqWitness(me.lock, forgedQ, msg), false, 'wrong ML-DSA');
  // "broke the lattice": has the ML-DSA key, but not the Schnorr one
  const forgedS = w(me, other.signer.sign(msg), me.mldsa.sign(msg));
  assert.equal(verifyPqWitness(me.lock, forgedS, msg), false, 'wrong Schnorr');
  // swapping the ML-DSA key for one of your own does not match the address hash
  const swapped = encodePqWitness(me.sPub, other.mldsa.pub, me.signer.sign(msg), other.mldsa.sign(msg));
  assert.equal(verifyPqWitness(me.lock, swapped, msg), false, 'swapped key');
  // valid witness from someone else
  const theirs = w(other, other.signer.sign(msg), other.mldsa.sign(msg));
  assert.equal(verifyPqWitness(me.lock, theirs, msg), false, 'someone else\'s address');
  assert.equal(verifyPqWitness(me.lock, good.subarray(0, -1), msg), false, 'truncated');
  assert.equal(verifyPqWitness(me.lock, me.signer.sign(msg), msg), false, 'Schnorr alone is not enough');
});

test('krq on the network: mine, receive, spend; an attack with only one of the keys fails', () => {
  const c = new Consensus(params);
  const clock = new Clock();
  const alice = Keys.random(), bob = Keys.random(), carol = Keys.random(), eve = Keys.random();
  // mining reward straight to the quantum-safe address
  for (let i = 0; i < 14; i++) mine(c, bob.qKey(0).lock, [], clock);
  for (let i = 0; i < 16; i++) mine(c, alice.tKey(0).lock, [], clock);
  const bobCoins = qUtxos(c, bob);
  assert.ok(bobCoins.length >= 3, 'recompensas maduras no krq');

  // Alice (classic) pays Bob's krq
  const fund = buildTransaction({ params, tInputs: matureTUtxos(c, alice).slice(0, 4), outputs: [{ type: 't', lock: bob.qKey(0).lock, amount: 2n * COIN }], change: { type: 't', lock: alice.tKey(0).lock } });
  mine(c, alice.tKey(0).lock, [fund.tx], clock);
  assert.equal(c.txStatus(fund.tx.idHex).status, 'accepted');

  // Bob spends from the krq (hybrid signature), the change goes back to the krq
  const spend = buildTransaction({ params, tInputs: bobCoins.slice(0, 2), outputs: [{ type: 't', lock: carol.tKey(0).lock, amount: COIN }], change: { type: 't', lock: bob.qKey(0).lock } });
  assert.ok(spend.tx.tIn.every((i) => i.sig.length === PQ_WITNESS_SIZE));
  assert.equal(spend.tx.mass, Math.max(computeMass(spend.tx, params), spend.tx.mass), 'declared mass covers the computation');
  assert.ok(spend.fee < 50_000n, `fee still negligible: ${spend.fee} grains`);
  mine(c, alice.tKey(0).lock, [spend.tx], clock);
  assert.equal(c.txStatus(spend.tx.idHex).status, 'accepted');
  assert.equal(tUtxos(c, carol)[0].amount, COIN);

  // Eve "broke" the elliptic curve: she knows Bob's Schnorr key, but not the ML-DSA one.
  const coin = qUtxos(c, bob).find((u) => u.amount === 2n * COIN);
  const k = bob.qKey(0);
  const evePq = { ...k, mldsa: { pub: k.mldsa.pub, sign: eve.qKey(0).mldsa.sign } };
  const theft = buildTransaction({ params, tInputs: [{ ...coin, pq: evePq }], outputs: [{ type: 't', lock: eve.tKey(0).lock, amount: COIN }], change: { type: 't', lock: eve.tKey(0).lock } });
  mine(c, alice.tKey(0).lock, [theft.tx], clock);
  assert.equal(c.txStatus(theft.tx.idHex).status, 'unknown', 'theft with Schnorr alone is ignored');
  // …and using her own ML-DSA key does not match the address hash
  const theft2 = buildTransaction({ params, tInputs: [{ ...coin, pq: { ...k, mldsa: eve.qKey(0).mldsa } }], outputs: [{ type: 't', lock: eve.tKey(0).lock, amount: COIN }] });
  mine(c, alice.tKey(0).lock, [theft2.tx], clock);
  assert.equal(c.txStatus(theft2.tx.idHex).status, 'unknown');
  // plain Schnorr does not open a krq either
  const plain = buildTransaction({ params, tInputs: [{ outpoint: coin.outpoint, amount: coin.amount, signer: k.signer }], outputs: [{ type: 't', lock: eve.tKey(0).lock, amount: COIN }] });
  mine(c, alice.tKey(0).lock, [plain.tx], clock);
  assert.equal(c.txStatus(plain.tx.idHex).status, 'unknown');
  assert.equal(tUtxos(c, eve).length, 0);
  assert.ok(qUtxos(c, bob).some((u) => u.amount === 2n * COIN), 'Bob\'s coin intact');
});

test('private pool turnstile: public accounting and blocking forged coins from leaving', () => {
  // delta = transparent inputs − transparent outputs − fee (only in transactions with a private part)
  const plainTx = { sIn: [], sOut: [], tOut: [{ amount: 5n }], fee: 1n };
  assert.equal(shieldedDelta(plainTx, 6n), 0n);
  assert.equal(shieldedDelta({ sIn: [], sOut: [{}], tOut: [], fee: 2n }, 100n), 98n, 'blindar');
  assert.equal(shieldedDelta({ sIn: [{}], sOut: [{}], tOut: [{ amount: 40n }], fee: 2n }, 0n), -42n, 'desblindar');

  const c = new Consensus(params);
  const clock = new Clock();
  const alice = Keys.random(), bob = Keys.random(), carol = Keys.random();
  const Q = COIN / 4n;
  const sumS = () => scanShielded(c, bob).reduce((a, u) => a + u.amount, 0n);
  assert.equal(c.supplyInfo().shieldedSupply, 0n);
  for (let i = 0; i < 14; i++) mine(c, bob.shieldedData, [], clock);
  for (let i = 0; i < 4; i++) mine(c, alice.tKey(0).lock, [], clock);
  // all existing private KRV is Bob's: the (public) turnstile must match his balance
  assert.ok(sumS() > 0n);
  assert.equal(c.supplyInfo().shieldedSupply, sumS(), 'private rewards enter the turnstile');

  // Bob takes 0.25 KRV out of the pool to a transparent address (the change stays private)
  const coin = scanShielded(c, bob).find((o) => c.virtual.gd.daaScore - o.daa >= params.coinbaseMaturity);
  const unshield = () => buildTransaction({ params, sInputs: [{ ...coin, ring: makeRing(c, coin) }], outputs: [{ type: 't', lock: carol.tKey(0).lock, amount: Q }], change: { type: 's', A: bob.A, B: bob.B } }).tx;
  const ok = unshield();
  const before = c.supplyInfo().shieldedSupply;
  mine(c, alice.tKey(0).lock, [ok], clock);
  assert.equal(c.txStatus(ok.idHex).status, 'accepted');
  assert.equal(c.supplyInfo().shieldedSupply, before - Q - ok.fee, 'desblindar reduz a catraca');
  assert.equal(c.supplyInfo().shieldedSupply, sumS());
  // (in a DAG, a block's transactions are accepted by its child: one more block settles the unshielding)
  mine(c, alice.tKey(0).lock, [], clock);

  // Simulation: someone forged coins INSIDE the pool (a bug or a quantum computer). To the
  // network, that shows up as trying to take more out of the pool than went in. We pretend the
  // public record says the pool is almost empty and try to unshield 1 KRV.
  const tip = c.virtual.gd.selectedParent;
  const acc = c.acc.get(tip);
  acc.shielded = Q / 2n; acc.cbShielded = 0n;
  c.virtual.acceptance.shielded = Q / 2n; // the node reuses the virtual's acceptance (cache)
  const coin2 = scanShielded(c, bob).find((o) => o !== coin && c.virtual.gd.daaScore - o.daa >= params.coinbaseMaturity && o.amount > Q);
  const forged = buildTransaction({ params, sInputs: [{ ...coin2, ring: makeRing(c, coin2) }], outputs: [{ type: 't', lock: carol.tKey(0).lock, amount: Q }], change: { type: 's', A: bob.A, B: bob.B } }).tx;
  mine(c, alice.tKey(0).lock, [forged], clock, [tip]);
  assert.equal(c.txStatus(forged.idHex).status, 'unknown', 'the turnstile blocks the exit: the forged coins stay stuck in the pool');
  assert.equal(tUtxos(c, carol).reduce((a, u) => a + u.amount, 0n), Q, 'Carol only has the legitimate 0.25 KRV');
  assert.ok(c.supplyInfo().shieldedSupply >= 0n);
  // the mempool rejects it right at the door
  const mp = new Mempool(c);
  const r = mp.add(forged);
  assert.equal(r.ok, false);
  assert.match(r.reason, /turnstile/);
  // movements INSIDE the pool keep working (private → private does not touch the turnstile)
  const inside = buildTransaction({ params, sInputs: [{ ...coin2, ring: makeRing(c, coin2) }], outputs: [{ type: 's', A: carol.A, B: carol.B, amount: Q / 10n }], change: { type: 's', A: bob.A, B: bob.B } });
  assert.ok(shieldedDelta(inside.tx, 0n) < 0n && -shieldedDelta(inside.tx, 0n) === inside.fee, 'only the fee leaves the pool');
});

test('wallet on the network: status, migration krv → krq, sending from the krq and restoring from the phrase', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krv-quantum-test-'));
  const port = await freePorts(4);
  const node = new Node({ params, datadir: dir, p2pPort: port, rpcPort: port + 1, log: () => {}, persist: false });
  await node.start();
  const url = `http://127.0.0.1:${port + 1}`;
  try {
    const alice = Wallet.create(path.join(dir, 'a.json'), params, url);
    const bob = Wallet.create(path.join(dir, 'b.json'), params, url);
    assert.match(alice.qAddress, /^krqsim1/);
    await mineVia(url, alice.tAddress, 6);
    await mineVia(url, bob.sAddress, 6);
    await mineVia(url, bob.tAddress, 12);

    let st = await alice.quantumStatus();
    assert.equal(st.enabled, false);
    assert.ok(st.classic > 0n);
    assert.equal(st.quantum, 0n);

    // migration: turns quantum mode on and moves everything classic and mature to krq
    const before = st.classic;
    const m = await alice.migrateQuantum();
    assert.ok(m.txs.length >= 1);
    await mineVia(url, bob.tAddress, 1);
    st = await alice.quantumStatus();
    assert.equal(st.enabled, true);
    assert.equal(st.classic, 0n, 'nothing left at the classic address');
    assert.equal(st.quantum, before - m.txs.reduce((a, t) => a + t.fee, 0n), 'only the fee was spent');
    assert.ok(m.txs.every((t) => t.fee < 100_000n), 'migration costs fractions of a cent');

    // spending from the krq: the wallet signs with Schnorr + ML-DSA, the change goes back to the krq
    const r = await alice.send({ to: bob.tAddress, amount: COIN / 10n });
    assert.equal(r.from, 'transparent');
    await mineVia(url, bob.tAddress, 1);
    assert.equal((await rpc(url, 'gettransactionstatus', { txid: r.txid })).status, 'accepted');
    const tx = Transaction.deserialize(fromHex((await rpc(url, 'gettransaction', { txid: r.txid })).tx));
    assert.ok(tx.tIn.every((i) => i.sig.length === PQ_WITNESS_SIZE), 'hybrid witness on the network');
    st = await alice.quantumStatus();
    assert.equal(st.classic, 0n, 'the change went to the krq');
    assert.ok(st.quantum > 0n);

    // the explorer / getinfo show the private pool turnstile
    const info = await rpc(url, 'getinfo');
    assert.ok(BigInt(info.shieldedSupply) > 0n);

    // same phrase → same quantum-safe address and same balance (the ML-DSA keys come from the seed)
    const restored = Wallet.restore(path.join(dir, 'r.json'), params, url, { mnemonic: alice.mnemonic });
    assert.equal(restored.qAddress, alice.qAddress);
    assert.equal((await restored.quantumStatus()).quantum, st.quantum);
  } finally {
    await node.stop();
  }
});
