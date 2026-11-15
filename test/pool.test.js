import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import path from 'node:path';
import { getParams, COIN } from '../src/params.js';
import { Node } from '../src/node/node.js';
import { Wallet } from '../src/wallet/wallet.js';
import { PowState, hashMeetsTarget } from '../src/consensus/pow.js';
import { fromHex } from '../src/util/bytes.js';
import { startPool, splitReward, nextWeight, targetForWeight, weightOfTarget, parseDuration, MIN_WEIGHT } from '../src/pool/pool.js';
import { freePorts } from './helpers.js';

const params = getParams('simnet');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

test('pool: reward split, vardiff, targets and durations', () => {
  const parts = splitReward(1_000_000_007n, { a: 3, b: 1, c: 0 });
  assert.equal(parts.get('c'), undefined);
  const sum = [...parts.values()].reduce((x, y) => x + y, 0n);
  assert.ok(sum <= 1_000_000_007n && sum > 1_000_000_007n - 10n, 'never distributes more than the reward');
  assert.ok(parts.get('a') > 2n * parts.get('b'));
  assert.equal(splitReward(100n, {}).size, 0);
  assert.equal(nextWeight(1000, 2), 4000, 'too many shares → the difficulty goes up (max 4×)');
  assert.equal(nextWeight(1000, 0.25), 500);
  assert.equal(nextWeight(300, 0), MIN_WEIGHT, 'never below the minimum');
  const blockTarget = 1n << 200n;
  assert.equal(targetForWeight(2 ** 70, blockTarget), blockTarget, 'a share is never harder than the block');
  const t = targetForWeight(1 << 20, blockTarget);
  assert.ok(Math.abs(weightOfTarget(t) - (1 << 20)) <= 1);
  assert.equal(parseDuration('90s'), 90_000);
  assert.equal(parseDuration('2min'), 120_000);
  assert.throws(() => parseDuration('in a little while'));
});

function client(port) {
  const sock = net.connect(port, '127.0.0.1');
  let buf = '', job = null, id = 0;
  const pending = new Map();
  sock.on('data', (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf('\n')) >= 0) {
      const m = JSON.parse(buf.slice(0, i)); buf = buf.slice(i + 1);
      if (m.method === 'job') job = m.params;
      else if (pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
    }
  });
  const req = (method, params) => new Promise((res) => { const n = ++id; pending.set(n, res); sock.write(JSON.stringify({ id: n, method, params }) + '\n'); });
  const ready = new Promise((r) => sock.on('connect', r));
  return {
    req, ready, get job() { return job; }, close: () => sock.destroy(),
    /** Finds a valid nonce for the current job and submits it. */
    async share() {
      for (let k = 0; k < 100 && !job; k++) await sleep(10);
      const j = job, pow = new PowState(fromHex(j.prePowHash)), tgt = fromHex(j.target);
      const ts = Math.max(j.timestamp, Date.now());
      for (let n = BigInt(Math.floor(Math.random() * 1e12)); ; n++) {
        if (hashMeetsTarget(pow.hash(ts, n), tgt)) return req('submit', { jobId: j.jobId, nonce: n.toString(), timestamp: ts });
      }
    },
  };
}

test('pool on the network: shares, blocks, proportional split and payout (transparent and private)', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krv-pool-'));
  const port = await freePorts(4);
  const node = new Node({ params, datadir: dir, p2pPort: port, rpcPort: port + 1, log: () => {}, persist: false });
  await node.start();
  const url = `http://127.0.0.1:${port + 1}`;
  const poolWallet = Wallet.create(path.join(dir, 'pool.json'), params, url);
  const alice = Wallet.create(path.join(dir, 'a.json'), params, url); // receives as transparent
  const bob = Wallet.create(path.join(dir, 'b.json'), params, url);   // receives as private
  const pool = await startPool({ params, rpcUrl: url, wallet: poolWallet, port: port + 2, webPort: port + 3, feePct: 2, minPayout: COIN / 100n, payoutEveryMs: 3_600_000, stateFile: path.join(dir, 'pool-state.json') });
  const A = client(port + 2), B = client(port + 2);
  try {
    await Promise.all([A.ready, B.ready]);
    // protocol rules
    assert.match((await A.req('submit', { jobId: '1', nonce: '1', timestamp: Date.now() })).error, /log in/);
    assert.match((await B.req('login', { address: 'krv1invalid' })).error, /invalid address/);
    assert.ok((await A.req('login', { address: alice.tAddress, worker: 'rig-a' })).result.login);
    assert.ok((await B.req('login', { address: bob.sAddress, worker: 'rig-b' })).result.login);
    assert.match((await A.req('submit', { jobId: '999999', nonce: '1', timestamp: Date.now() })).error, /expired/);

    // Alice mines 3× more than Bob
    let blocks = 0;
    for (let round = 0; round < 30; round++) {
      for (let k = 0; k < 3; k++) { const r = await A.share(); assert.ok(r.result?.accepted, JSON.stringify(r)); if (r.result.block) blocks++; }
      const r = await B.share(); assert.ok(r.result?.accepted); if (r.result.block) blocks++;
    }
    assert.ok(blocks > 20, `the pool found ${blocks} blocks`);
    // repeated share
    const j = A.job, pow = new PowState(fromHex(j.prePowHash)), ts = Math.max(j.timestamp, Date.now());
    let n = 0n; while (!hashMeetsTarget(pow.hash(ts, n), fromHex(j.target))) n++;
    await A.req('submit', { jobId: j.jobId, nonce: n.toString(), timestamp: ts });
    assert.match((await A.req('submit', { jobId: j.jobId, nonce: n.toString(), timestamp: ts })).error, /repeated/);

    // maturing: more blocks on top and the crediting loop runs
    for (let k = 0; k < 20; k++) await A.share();
    await sleep(2500);
    const st = pool.stats();
    const ma = st.miners.find((m) => m.address === alice.tAddress), mb = st.miners.find((m) => m.address === bob.sAddress);
    assert.ok(ma.balance > 0n && mb.balance > 0n, 'both received credit');
    const ratio = Number(ma.balance) / Number(mb.balance);
    assert.ok(ratio > 2 && ratio < 6, `ratio ${ratio.toFixed(2)} (Alice mined 3× more and also made the last shares)`);
    assert.ok(st.blocks.some((b) => b.status === 'credited'));
    assert.ok(st.pool.earned > 0n, 'the pool kept the fee');

    // payout: Alice to a transparent address, Bob to a private address
    const pay = await pool.payoutNow();
    assert.ok(pay?.txid, 'payout sent');
    for (let k = 0; k < 15; k++) await A.share(); // confirms the payout and matures the private outputs
    await alice.sync(); await bob.sync();
    const paidA = pool.stats().miners.find((m) => m.address === alice.tAddress).paid;
    const paidB = pool.stats().miners.find((m) => m.address === bob.sAddress).paid;
    assert.equal(alice.balance().transparent + alice.balance().transparentImmature, paidA);
    const bb = bob.balance();
    assert.equal(bb.shielded + bb.shieldedImmature, paidB, 'Bob was paid privately');
    // web page and API
    const html = await (await fetch(`http://127.0.0.1:${port + 3}/`)).text();
    assert.match(html, /Krevo mining pool/);
    assert.match(html, /private/);
    const api = await (await fetch(`http://127.0.0.1:${port + 3}/api/miner/${alice.tAddress}`)).json();
    assert.equal(api.address, alice.tAddress);
    // the state survives restarts
    await sleep(700);
    const saved = JSON.parse(fs.readFileSync(path.join(dir, 'pool-state.json'), 'utf8'));
    assert.equal(BigInt(saved.paid[alice.tAddress]), paidA);
  } finally {
    A.close(); B.close();
    await pool.stop();
    await node.stop();
  }
});
