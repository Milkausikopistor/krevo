// Regressão: duas transações seguidas da mesma carteira, com Dandelion++ ativo
// (a primeira ainda está na "haste", fora do mempool) não podem gastar as mesmas moedas.
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
import { Transaction } from '../src/consensus/tx.js';
import { solve } from '../src/node/solver.js';
import { fromHex, toHex } from '../src/util/bytes.js';
import { freePorts } from './helpers.js';

const params = getParams('simnet');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function mineVia(url, address, n) {
  for (let i = 0; i < n; i++) {
    const t = await rpc(url, 'getblocktemplate', { address });
    const b = Block.deserialize(fromHex(t.block));
    assert.ok(solve(b));
    await rpc(url, 'submitblock', { block: toHex(b.serialize()) });
  }
}

test('dandelion: envios seguidos não reutilizam moedas que estão na haste', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krv-dand-'));
  const port = await freePorts(4);
  const n0 = new Node({ params, datadir: dir, p2pPort: port, rpcPort: port + 1, log: () => {}, persist: false });
  const n1 = new Node({ params, datadir: dir, p2pPort: port + 2, rpcPort: port + 3, peers: [`127.0.0.1:${port}`], log: () => {}, persist: false });
  await n0.start(); await n1.start();
  const url = `http://127.0.0.1:${port + 1}`;
  try {
    for (let i = 0; i < 50 && ![...n0.p2p.peers].some((p) => p.ready); i++) await sleep(50);
    const alice = Wallet.create(path.join(dir, 'a.json'), params, url);
    const bob = Wallet.create(path.join(dir, 'b.json'), params, url);
    await mineVia(url, alice.tAddress, 25);
    const ins = async (txid) => Transaction.deserialize(fromHex((await rpc(url, 'gettransaction', { txid })).tx))
      .tIn.map((i) => `${toHex(i.outpoint.txid)}:${i.outpoint.index}`);
    for (let round = 0; round < 3; round++) {
      const t1 = await alice.send({ to: bob.tAddress, amount: COIN / 4n, from: 'transparente' });
      const t2 = await alice.send({ to: bob.tAddress, amount: COIN / 4n, from: 'transparente' }); // imediatamente
      const a = await ins(t1.txid), b = await ins(t2.txid);
      assert.ok(!a.some((k) => b.includes(k)), 'a segunda transação escolheu moedas diferentes');
      await sleep(4500); // embargo do Dandelion++ termina; transações chegam ao mempool
      await mineVia(url, alice.tAddress, 2);
      for (const t of [t1, t2]) assert.equal((await rpc(url, 'gettransactionstatus', { txid: t.txid })).status, 'accepted');
    }
  } finally {
    await n1.stop(); await n0.stop();
  }
});
