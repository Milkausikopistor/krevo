// Block explorer: pages, JSON API, search and HTML escaping.
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

test('explorer: dashboard, block, transaction, address, search and API', async () => {
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
    const pay = await alice.send({ to: bob.tAddress, amount: COIN / 2n, from: 'transparent' });
    const shield = await alice.send({ to: bob.sAddress, amount: COIN / 4n, from: 'transparent', memo: 'secret' });
    await mineVia(url, alice.tAddress, 2);

    // dashboard
    const home = await get('/');
    assert.equal(home.status, 200);
    assert.match(home.text, /Krevo Explorer/);
    assert.match(home.text, /Live DAG/);
    assert.match(home.text, /<svg class="dag"/);
    assert.match(home.text, /blocks per second/);
    const panel = JSON.parse((await get('/api/panel')).text);
    assert.ok(panel.dag.includes('<rect') && panel.blocks.includes('/block/') && panel.txs.includes(pay.txid.slice(0, 10)));

    // transparent transaction: visible amounts; shielding: hidden parts, encrypted memo
    const t1 = await get(`/tx/${pay.txid}`);
    assert.equal(t1.status, 200);
    assert.match(t1.text, /Transparent/);
    assert.match(t1.text, /0\.5 KRV/);
    assert.match(t1.text, /accepted/);
    const t2 = await get(`/tx/${shield.txid}`);
    assert.match(t2.text, /Shielding/);
    assert.match(t2.text, /private output/);
    assert.match(t2.text, /Memo/);
    assert.ok(!t2.text.includes('secret'), 'the memo never shows up');
    const api = JSON.parse((await get(`/api/tx/${shield.txid}`)).text);
    assert.equal(api.memo, 'encrypted');
    assert.equal(api.outputs.find((o) => o.type === 'shielded').amount, undefined);

    // block
    const info = await rpc(url, 'getinfo');
    const blk = await get(`/block/${info.virtual.selectedParent}`);
    assert.equal(blk.status, 200);
    assert.match(blk.text, /Selected parent/);
    assert.match(blk.text, /Rewards paid/);

    // addresses
    const ta = await get(`/address/${bob.tAddress}`);
    assert.match(ta.text, /Transparent address/);
    assert.match(ta.text, /0\.5 KRV/);
    assert.match(ta.text, /\+0\.5 KRV/);
    const sa = await get(`/address/${bob.sAddress}`);
    assert.match(sa.text, /privacy working/);
    assert.ok(!/0\.25 KRV/.test(sa.text));

    // search
    assert.equal((await get(`/search?q=${pay.txid}`)).loc, `/tx/${pay.txid}`);
    assert.equal((await get(`/search?q=${info.virtual.selectedParent}`)).loc, `/block/${info.virtual.selectedParent}`);
    assert.equal((await get(`/search?q=${bob.tAddress}`)).loc, `/address/${bob.tAddress}`);
    const xss = await get('/search?q=' + encodeURIComponent('<script>alert(1)</script>'));
    assert.equal(xss.status, 404);
    assert.ok(!xss.text.includes('<script>alert(1)'), 'user input is escaped');
    assert.ok(xss.text.includes('&lt;script&gt;'));
    assert.equal((await get('/block/' + 'ab'.repeat(32))).status, 404); assert.equal((await get(`/bloco/${info.virtual.selectedParent}`)).status, 200, 'links from older versions still work');
    assert.equal((await get('/nothing')).status, 404);
    assert.equal((await get('/', { method: 'POST' })).status, 405);
  } finally {
    await ex.close();
    await node.stop();
  }
});

test('explorer: the DAG drawing puts parallel blocks side by side and links them to their parents', () => {
  const blocks = [
    { hash: 'a'.repeat(64), parents: [], blueScore: 1, chain: true, color: 'blue', txs: 0 },
    { hash: 'b'.repeat(64), parents: ['a'.repeat(64)], blueScore: 2, chain: true, color: 'blue', txs: 1 },
    { hash: 'c'.repeat(64), parents: ['a'.repeat(64)], blueScore: 2, chain: false, color: 'red', txs: 0 },
    { hash: 'd'.repeat(64), parents: ['b'.repeat(64), 'c'.repeat(64)], blueScore: 4, chain: true, color: 'blue', txs: 0, tip: true },
  ];
  const svg = dagSvg(blocks);
  assert.equal((svg.match(/<rect/g) ?? []).length, 4);
  assert.equal((svg.match(/<line/g) ?? []).length, 4);
  assert.equal((svg.match(/class="e sp"/g) ?? []).length, 2, 'selected chain edges highlighted');
  assert.match(svg, /class="n red"/);
  assert.match(svg, /class="n chain tip"/);
});
