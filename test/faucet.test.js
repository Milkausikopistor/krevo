// Testnet faucet (src/faucet/faucet.js) and seed nodes (seeds/*.txt).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getParams, COIN } from '../src/params.js';
import { startFaucet, FaucetLimits } from '../src/faucet/faucet.js';
import { parseSeeds, seedsFor } from '../src/node/seeds.js';
import { Keys } from '../src/wallet/keys.js';

const params = getParams('simnet');

test('faucet: limits per address, per IP and global; quota returned if sending fails', () => {
  let t = 0;
  const L = new FaucetLimits({ perIpPerHour: 2, perHour: 3, now: () => t });
  L.take('ip1', 'a');
  assert.throws(() => L.take('ip2', 'a'), /already received/, 'same address within 24 h');
  L.take('ip1', 'b');
  assert.throws(() => L.take('ip1', 'c'), /IP/, 'third request from the same IP in the hour');
  L.take('ip2', 'c');
  assert.throws(() => L.take('ip3', 'd'), /busy/, 'global hourly cap');
  L.undo('ip2', 'c');
  L.take('ip3', 'd');
  t += 3_600_001;
  L.take('ip1', 'e');
  t += 24 * 3_600_000;
  L.take('ip9', 'a');
});

test('faucet: HTTP API, addresses of other networks rejected, never on mainnet', async () => {
  const sent = [];
  const wallet = {
    async sync() {},
    balance: () => ({ transparent: 1000n * COIN }),
    async send({ to, amount }) { sent.push({ to, amount }); return { txid: 'ab'.repeat(32), fee: 1000n }; },
  };
  await assert.rejects(startFaucet({ wallet, params: getParams('mainnet') }), /test networks/);
  const f = await startFaucet({ wallet, params, port: 0, amount: 5n * COIN });
  try {
    const base = `http://127.0.0.1:${f.port}`;
    const to = Keys.random().sAddress(params);
    const page = await (await fetch(base)).text();
    assert.match(page, /Krevo simnet faucet/);
    const r1 = await (await fetch(`${base}/?to=${to}`)).json();
    assert.equal(r1.ok, true);
    assert.deepEqual(sent, [{ to, amount: 5n * COIN }]);
    const r2 = await fetch(base, { method: 'POST', body: JSON.stringify({ to }) });
    assert.equal(r2.status, 429, 'same address again');
    const other = Keys.random().sAddress(getParams('devnet'));
    const r3 = await (await fetch(`${base}/?to=${other}`)).json();
    assert.match(r3.error, /invalid/, 'devnet address on a simnet faucet');
    const r4 = await (await fetch(`${base}/?to=garbage`)).json();
    assert.equal(r4.ok, false);
    assert.equal(sent.length, 1);
  } finally { await f.close(); }
});

test('seed nodes: file format; mainnet has no seeds (not launched)', () => {
  assert.deepEqual(parseSeeds('# comment\n1.2.3.4:16210\nseed.example.org:16210  # with a note\nno-port\n\n[::1]:16210\n'),
    ['1.2.3.4:16210', 'seed.example.org:16210', '[::1]:16210']);
  assert.deepEqual(seedsFor('mainnet'), []);
  assert.ok(Array.isArray(seedsFor('testnet')));
  assert.deepEqual(seedsFor('network-that-does-not-exist'), []);
});
