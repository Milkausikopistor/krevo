// Torneira de testnet (src/faucet/faucet.js) e nós-semente (seeds/*.txt).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getParams, COIN } from '../src/params.js';
import { startFaucet, FaucetLimits } from '../src/faucet/faucet.js';
import { parseSeeds, seedsFor } from '../src/node/seeds.js';
import { Keys } from '../src/wallet/keys.js';

const params = getParams('simnet');

test('torneira: limites por endereço, por IP e global; cota devolvida se o envio falhar', () => {
  let t = 0;
  const L = new FaucetLimits({ perIpPerHour: 2, perHour: 3, now: () => t });
  L.take('ip1', 'a');
  assert.throws(() => L.take('ip2', 'a'), /já recebeu/, 'mesmo endereço em 24 h');
  L.take('ip1', 'b');
  assert.throws(() => L.take('ip1', 'c'), /IP/, 'terceiro pedido do mesmo IP na hora');
  L.take('ip2', 'c');
  assert.throws(() => L.take('ip3', 'd'), /procurada/, 'teto global por hora');
  L.undo('ip2', 'c');
  L.take('ip3', 'd');
  t += 3_600_001;
  L.take('ip1', 'e');
  t += 24 * 3_600_000;
  L.take('ip9', 'a');
});

test('torneira: API HTTP, endereços de outra rede recusados, nunca na mainnet', async () => {
  const sent = [];
  const wallet = {
    async sync() {},
    balance: () => ({ transparent: 1000n * COIN }),
    async send({ to, amount }) { sent.push({ to, amount }); return { txid: 'ab'.repeat(32), fee: 1000n }; },
  };
  await assert.rejects(startFaucet({ wallet, params: getParams('mainnet') }), /redes de teste/);
  const f = await startFaucet({ wallet, params, port: 0, amount: 5n * COIN });
  try {
    const base = `http://127.0.0.1:${f.port}`;
    const to = Keys.random().sAddress(params);
    const page = await (await fetch(base)).text();
    assert.match(page, /Torneira — Krevo simnet/);
    const r1 = await (await fetch(`${base}/?para=${to}`)).json();
    assert.equal(r1.ok, true);
    assert.deepEqual(sent, [{ to, amount: 5n * COIN }]);
    const r2 = await fetch(base, { method: 'POST', body: JSON.stringify({ para: to }) });
    assert.equal(r2.status, 429, 'mesmo endereço de novo');
    const other = Keys.random().sAddress(getParams('devnet'));
    const r3 = await (await fetch(`${base}/?para=${other}`)).json();
    assert.match(r3.error, /inválido/, 'endereço da devnet numa torneira da simnet');
    const r4 = await (await fetch(`${base}/?para=lixo`)).json();
    assert.equal(r4.ok, false);
    assert.equal(sent.length, 1);
  } finally { await f.close(); }
});

test('nós-semente: formato do arquivo; mainnet sem sementes (não lançada)', () => {
  assert.deepEqual(parseSeeds('# comentário\n1.2.3.4:16210\nno.exemplo.org:16210  # com nota\nsem-porta\n\n[::1]:16210\n'),
    ['1.2.3.4:16210', 'no.exemplo.org:16210', '[::1]:16210']);
  assert.deepEqual(seedsFor('mainnet'), []);
  assert.ok(Array.isArray(seedsFor('testnet')));
  assert.deepEqual(seedsFor('rede-que-nao-existe'), []);
});
