// Explorador de blocos: páginas, API JSON, busca e escape de HTML.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getParams, COIN } from '../src/params.js';
import { Node } from '../src/node/node.js';
import { Wallet } from '../src/wallet/wallet.js';
import { rpc } from '../src/node/rpcclient.js';
import { Block } from '../src/consensus/block.js';
import { solve } from '../src/node/solver.js';
import { fromHex, toHex } from '../src/util/bytes.js';
import { startExplorer, dagSvg } from '../src/explorer/server.js';
import { freePorts } from './helpers.js';

const params = getParams('simnet');

async function mineVia(url, address, n) {
  for (let i = 0; i < n; i++) {
    const t = await rpc(url, 'getblocktemplate', { address });
    const b = Block.deserialize(fromHex(t.block));
    assert.ok(solve(b));
    assert.equal((await rpc(url, 'submitblock', { block: toHex(b.serialize()) })).status, 'accepted');
  }
}

test('explorador: painel, bloco, transação, endereço, busca e API', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krv-explorer-'));
  const port = await freePorts(4);
  const node = new Node({ params, datadir: dir, p2pPort: port, rpcPort: port + 1, log: () => {}, persist: false });
  await node.start();
  const url = `http://127.0.0.1:${port + 1}`;
  const ex = await startExplorer({ params, rpcUrl: url, port: port + 2 });
  const get = async (p, opts) => { const r = await fetch(ex.url + p, { redirect: 'manual', ...opts }); return { status: r.status, text: await r.text(), loc: r.headers.get('location') }; };
  try {
    const alice = Wallet.create(path.join(dir, 'a.json'), params, url);
    const bob = Wallet.create(path.join(dir, 'b.json'), params, url);
    await mineVia(url, alice.tAddress, 20);
    await mineVia(url, bob.sAddress, 6);
    const pay = await alice.send({ to: bob.tAddress, amount: COIN / 2n, from: 'transparente' });
    const shield = await alice.send({ to: bob.sAddress, amount: COIN / 4n, from: 'transparente', memo: 'segredo' });
    await mineVia(url, alice.tAddress, 2);

    // painel
    const home = await get('/');
    assert.equal(home.status, 200);
    assert.match(home.text, /Explorador Krevo/);
    assert.match(home.text, /DAG ao vivo/);
    assert.match(home.text, /<svg class="dag"/);
    assert.match(home.text, /blocos por segundo/);
    const panel = JSON.parse((await get('/api/painel')).text);
    assert.ok(panel.dag.includes('<rect') && panel.blocks.includes('/bloco/') && panel.txs.includes(pay.txid.slice(0, 10)));

    // transação transparente: valores visíveis; blindagem: partes ocultas, memo cifrado
    const t1 = await get(`/tx/${pay.txid}`);
    assert.equal(t1.status, 200);
    assert.match(t1.text, /Transparente/);
    assert.match(t1.text, /0,5 KRV/);
    assert.match(t1.text, /aceita/);
    const t2 = await get(`/tx/${shield.txid}`);
    assert.match(t2.text, /Blindagem/);
    assert.match(t2.text, /saída privada/);
    assert.match(t2.text, /Memo/);
    assert.ok(!t2.text.includes('segredo'), 'o memo nunca aparece');
    const api = JSON.parse((await get(`/api/tx/${shield.txid}`)).text);
    assert.equal(api.memo, 'cifrado');
    assert.equal(api.outputs.find((o) => o.type === 'shielded').amount, undefined);

    // bloco
    const info = await rpc(url, 'getinfo');
    const blk = await get(`/bloco/${info.virtual.selectedParent}`);
    assert.equal(blk.status, 200);
    assert.match(blk.text, /Pai selecionado/);
    assert.match(blk.text, /Recompensas pagas/);

    // endereços
    const ta = await get(`/endereco/${bob.tAddress}`);
    assert.match(ta.text, /Endereço transparente/);
    assert.match(ta.text, /0,5 KRV/);
    assert.match(ta.text, /\+0,5 KRV/);
    const sa = await get(`/endereco/${bob.sAddress}`);
    assert.match(sa.text, /privacidade funcionando/);
    assert.ok(!/0,25 KRV/.test(sa.text));

    // busca
    assert.equal((await get(`/busca?q=${pay.txid}`)).loc, `/tx/${pay.txid}`);
    assert.equal((await get(`/busca?q=${info.virtual.selectedParent}`)).loc, `/bloco/${info.virtual.selectedParent}`);
    assert.equal((await get(`/busca?q=${bob.tAddress}`)).loc, `/endereco/${bob.tAddress}`);
    const xss = await get('/busca?q=' + encodeURIComponent('<script>alert(1)</script>'));
    assert.equal(xss.status, 404);
    assert.ok(!xss.text.includes('<script>alert(1)'), 'entrada do usuário é escapada');
    assert.ok(xss.text.includes('&lt;script&gt;'));
    assert.equal((await get('/bloco/' + 'ab'.repeat(32))).status, 404);
    assert.equal((await get('/nada')).status, 404);
    assert.equal((await get('/', { method: 'POST' })).status, 405);
  } finally {
    await ex.close();
    await node.stop();
  }
});

test('explorador: desenho do DAG coloca paralelos lado a lado e liga aos pais', () => {
  const blocks = [
    { hash: 'a'.repeat(64), parents: [], blueScore: 1, chain: true, color: 'blue', txs: 0 },
    { hash: 'b'.repeat(64), parents: ['a'.repeat(64)], blueScore: 2, chain: true, color: 'blue', txs: 1 },
    { hash: 'c'.repeat(64), parents: ['a'.repeat(64)], blueScore: 2, chain: false, color: 'red', txs: 0 },
    { hash: 'd'.repeat(64), parents: ['b'.repeat(64), 'c'.repeat(64)], blueScore: 4, chain: true, color: 'blue', txs: 0, tip: true },
  ];
  const svg = dagSvg(blocks);
  assert.equal((svg.match(/<rect/g) ?? []).length, 4);
  assert.equal((svg.match(/<line/g) ?? []).length, 4);
  assert.equal((svg.match(/class="e sp"/g) ?? []).length, 2, 'arestas da cadeia selecionada em destaque');
  assert.match(svg, /class="n red"/);
  assert.match(svg, /class="n chain tip"/);
});
