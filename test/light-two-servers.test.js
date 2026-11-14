// Carteira leve com DOIS servidores: um honesto e um mentiroso que (a) esconde um pagamento
// privado (remove a saída e desloca os índices), (b) esconde uma moeda transparente e
// (c) mostra como disponível uma moeda que já foi gasta. Sozinho, o mentiroso engana a
// carteira; com o servidor honesto ao lado, a carteira acerta o saldo e aponta as divergências.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { getParams, COIN } from '../src/params.js';
import { Node } from '../src/node/node.js';
import { Wallet } from '../src/wallet/wallet.js';
import { rpc } from '../src/node/rpcclient.js';
import { Block } from '../src/consensus/block.js';
import { solve } from '../src/node/solver.js';
import { fromHex, toHex } from '../src/util/bytes.js';
import { Keys } from '../src/wallet/keys.js';
import { startLightServer } from '../src/light/server.js';
import { LightWallet } from '../src/light/wallet.js';

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

/** Servidor mentiroso na frente de um honesto. */
function liarProxy(upstream, plan) {
  const server = http.createServer(async (req, res) => {
    const u = new URL(req.url, 'http://x');
    let body = '';
    for await (const c of req) body += c;
    const send = (code, type, data) => { res.writeHead(code, { 'content-type': type, 'access-control-allow-origin': '*' }); res.end(data); };
    const fwd = (p, opts = {}) => fetch(upstream + p, opts);
    const K = plan.hideIndex; // saída privada escondida (índice global real)
    if (u.pathname === '/v1/info') { const i = await (await fwd('/v1/info')).json(); i.outputs -= K === null ? 0 : 1; return send(200, 'application/json', JSON.stringify(i)); }
    if (u.pathname === '/v1/compact' && K !== null) {
      // monta a lista "mentirosa" (sem a saída K, índices deslocados) e devolve o pedaço pedido
      const info = await (await fwd('/v1/info')).json();
      const all = Buffer.from(await (await fwd(`/v1/compact?start=0&count=${info.outputs}`)).arrayBuffer());
      const entries = [];
      for (let k = 0; k < all.readUInt32LE(8); k++) if (k !== K) entries.push(all.subarray(20 + 35 * k, 55 + 35 * k));
      const s = Number(u.searchParams.get('start')), n = Math.min(Number(u.searchParams.get('count')), entries.length - s);
      const head = Buffer.alloc(20);
      head.writeUInt32LE(entries.length, 0); head.writeUInt32LE(s, 4); head.writeUInt32LE(Math.max(0, n), 8); head.writeBigUInt64LE(all.readBigUInt64LE(12), 12);
      return send(200, 'application/octet-stream', Buffer.concat([head, ...entries.slice(s, s + Math.max(0, n))]));
    }
    if (u.pathname === '/v1/outputs' && K !== null) {
      const want = JSON.parse(body).indices.map((i) => (i < K ? i : i + 1));
      const r = await (await fwd('/v1/outputs', { method: 'POST', body: JSON.stringify({ indices: want }), headers: { 'content-type': 'application/json' } })).json();
      r.outputs = r.outputs.filter((o) => o.index !== K).map((o) => ({ ...o, index: o.index < K ? o.index : o.index - 1 }));
      r.total -= 1;
      return send(200, 'application/json', JSON.stringify(r));
    }
    if (u.pathname === '/v1/utxos') {
      const r = await (await fwd('/v1/utxos', { method: 'POST', body, headers: { 'content-type': 'application/json' } })).json();
      r.utxos = r.utxos.filter((x) => x.outpoint !== plan.hideOutpoint);
      if (plan.phantom) r.utxos.push(plan.phantom);
      return send(200, 'application/json', JSON.stringify(r));
    }
    const r = await fwd(req.url, req.method === 'POST' ? { method: 'POST', body, headers: { 'content-type': 'application/json' } } : {});
    return send(r.status, r.headers.get('content-type') ?? 'application/json', Buffer.from(await r.arrayBuffer()));
  });
  return new Promise((ok) => server.listen(0, '127.0.0.1', () => ok({ url: `http://127.0.0.1:${server.address().port}`, close: () => { server.closeAllConnections?.(); server.close(); } })));
}

test('dois servidores: o honesto desmascara o que o mentiroso esconde ou inventa', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krv-2srv-'));
  const port = 19000 + Math.floor(Math.random() * 900);
  const node = new Node({ params, datadir: dir, p2pPort: port, rpcPort: port + 1, log: () => {}, persist: false });
  await node.start();
  const url = `http://127.0.0.1:${port + 1}`;
  const a = await startLightServer({ params, rpcUrl: url, port: 0 });
  const b = await startLightServer({ params, rpcUrl: url, port: 0 });
  const plan = { hideIndex: null, hideOutpoint: null, phantom: null };
  const liar = await liarProxy(a.url, plan);
  try {
    const alice = Wallet.create(path.join(dir, 'alice.json'), params, url);
    const truth = LightWallet.create(path.join(dir, 'bob.json'), params, b.url); // Bob com um servidor honesto
    const miner = Keys.random();
    const mine = (n) => mineVia(url, miner.tAddress(params), n);
    await mineVia(url, alice.tAddress, 30);
    await mineVia(url, miner.sAddress(params), 40);

    // Bob recebe T1 e GASTA (para o mentiroso depois "ressuscitar" essa moeda)
    await alice.send({ to: truth.tAddress, amount: 2n * COIN, from: 'transparente' });
    await mine(params.lightProofDepth + 3);
    await truth.sync();
    const t1 = { ...truth.tUtxos[0] };
    await truth.send({ to: alice.tAddress, amount: COIN / 2n, from: 'transparente' });
    await mine(1);
    // Alice paga Bob: privado P (escondido pelo mentiroso) e transparente T2 (idem)
    const pay = await alice.send({ to: truth.sAddress, amount: 3n * COIN, from: 'transparente', memo: 'escondido?' });
    await mine(1);
    await alice.send({ to: miner.sAddress(params), amount: COIN, from: 'transparente' }); // outra saída privada DEPOIS de P: P fica no meio
    await mine(1);
    const t2 = await alice.send({ to: truth.tAddress, amount: COIN, from: 'transparente' });
    await mine(params.lightProofDepth + 60); // longe o bastante para não parecer "atraso"
    const outs = await rpc(url, 'getshieldedoutputs', { start: 0, count: 5000 });
    plan.hideIndex = outs.outputs.find((o) => o.outpoint.startsWith(pay.txid)).index;
    plan.hideOutpoint = `${t2.txid}:0`;
    plan.phantom = { outpoint: t1.outpoint, amount: t1.amount, lock: t1.lock, daa: t1.daa, coinbase: false, mature: true, inMempool: false };
    assert.ok((await rpc(url, 'getutxos', { locks: [t1.lock] })).utxos.every((u) => u.outpoint !== t1.outpoint), 'T1 está mesmo gasta');

    await truth.sync();
    const real = truth.balance();
    assert.equal(real.shielded, 3n * COIN);

    // 1) só o mentiroso: a carteira é enganada (sem o pagamento privado, sem T2, com a moeda gasta)
    const fooled = LightWallet.restore(path.join(dir, 'bob-1.json'), params, liar.url, { mnemonic: truth.mnemonic });
    await fooled.sync();
    const f = fooled.balance();
    assert.equal(f.shielded, 0n, 'pagamento privado escondido');
    assert.notEqual(f.transparent, real.transparent, 'saldo transparente errado');

    // 2) mentiroso + honesto: saldo certo e divergências apontadas
    const both = LightWallet.restore(path.join(dir, 'bob-2.json'), params, `${liar.url},${b.url}`, { mnemonic: truth.mnemonic });
    const st = await both.sync();
    const g = both.balance();
    assert.equal(st.servers, 2);
    assert.equal(g.shielded, real.shielded, 'o pagamento privado foi encontrado pelo honesto');
    assert.equal(g.transparent, real.transparent, 'transparente certo: T2 conta, a moeda gasta não');
    assert.deepEqual(both.history().received.map((r) => r.memo).filter(Boolean), ['escondido?']);
    const d = both.discrepancies.join(' | ');
    assert.match(d, /saídas privadas DIFERENTES/);
    assert.match(d, /escondeu uma moeda transparente/);
    assert.match(d, /já foi gasta \(a carteira tem a PROVA do gasto\)/);
    assert.match(d, new RegExp(`a partir da posição ${plan.hideIndex}\\b`), 'aponta exatamente onde começou a divergência');

    // 3) dois honestos: concordam
    const calm = LightWallet.restore(path.join(dir, 'bob-3.json'), params, `${a.url},${b.url}`, { mnemonic: truth.mnemonic });
    await calm.sync();
    assert.deepEqual(calm.discrepancies, []);
    assert.equal(calm.balance().shielded, real.shielded);
    assert.equal(calm.balance().transparent, real.transparent);
    console.log(`    divergências detectadas: ${both.discrepancies.length} — ${d.slice(0, 160)}…`);
  } finally {
    liar.close();
    await a.close();
    await b.close();
    await node.stop();
  }
});
