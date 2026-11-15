// The web app's wallet, running with the SAME pieces as the browser (Buffer and pure-JS
// cryptography, without node:crypto) against a real node + light server: restores from the phrase, scans, verifies
// proofs with PoW, reads the encrypted memo and spends as private.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { getParams, COIN } from '../src/params.js';
import { Node } from '../src/node/node.js';
import { Wallet } from '../src/wallet/wallet.js';
import { rpc } from '../src/node/rpcclient.js';
import { Block } from '../src/consensus/block.js';
import { solve } from '../src/node/solver.js';
import { fromHex, toHex } from '../src/util/bytes.js';
import { Keys } from '../src/wallet/keys.js';
import { Transaction } from '../src/consensus/tx.js';
import { PQ_WITNESS_SIZE } from '../src/consensus/pqlock.js';
import { generateMnemonic } from '../src/wallet/bip39.js';
import { startLightServer } from '../src/light/server.js';
import { freePorts } from './helpers.js';

const params = getParams('simnet');
const run = promisify(execFile);
const here = path.dirname(fileURLToPath(import.meta.url));

async function mineVia(url, address, n) {
  for (let i = 0; i < n; i++) {
    const t = await rpc(url, 'getblocktemplate', { address });
    const b = Block.deserialize(fromHex(t.block));
    assert.ok(solve(b));
    const r = await rpc(url, 'submitblock', { block: toHex(b.serialize()) });
    assert.equal(r.status, 'accepted', r.reason);
  }
}

test('web wallet (browser pieces): restores, scans, proves, reads the memo and spends', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krv-web-'));
  const port = await freePorts(4);
  const node = new Node({ params, datadir: dir, p2pPort: port, rpcPort: port + 1, log: () => {}, persist: false });
  await node.start();
  const url = `http://127.0.0.1:${port + 1}`;
  const ls = await startLightServer({ params, rpcUrl: url, port: 0 });
  try {
    const alice = Wallet.create(path.join(dir, 'alice.json'), params, url);
    const phrase = generateMnemonic(24);
    const web = Wallet.create(path.join(dir, 'web.json'), params, url, { mnemonic: phrase }); // only to learn the address
    const miner = Keys.random();
    await mineVia(url, alice.tAddress, 30);
    await mineVia(url, miner.sAddress(params), 40);
    const p = await alice.send({ to: web.sAddress, amount: 3n * COIN, from: 'transparent', memo: 'café ☕' });
    await alice.send({ to: web.tAddress, amount: 2n * COIN, from: 'transparent' }); // classic coins, migrated to krq at the end
    await mineVia(url, miner.tAddress(params), params.lightProofDepth + 6);
    assert.equal((await rpc(url, 'gettransactionstatus', { txid: p.txid })).status, 'accepted');

    const client = (...extra) => run(process.execPath, ['--import', pathToFileURL(path.join(here, 'browser', 'register.mjs')).href, path.join(here, 'browser', 'client.mjs'), ls.url, 'simnet', phrase, ...extra], { timeout: 300_000 });
    const r1 = JSON.parse((await client()).stdout);
    assert.ok(r1.env.webBuffer, 'ran with the web app\'s Buffer');
    assert.equal(r1.address, web.sAddress, 'the phrase produces the same address with the browser\'s cryptography');
    assert.equal(r1.balance.shielded, (3n * COIN).toString(), 'private balance proven');
    assert.deepEqual(r1.memos, ['café ☕'], 'memo decrypted with the pure-JS AES-GCM');

    const r2 = JSON.parse((await client(alice.tAddress, String(COIN), 'private')).stdout);
    assert.ok(r2.sent?.txid, 'transaction built in the "browser"');
    await mineVia(url, miner.tAddress(params), 1);
    assert.equal((await rpc(url, 'gettransactionstatus', { txid: r2.sent.txid })).status, 'accepted', 'the network accepted it (CLSAG ring + Bulletproofs made in pure JS)');
    // private spend with a proof against the whole tree, also with just the browser pieces
    await mineVia(url, miner.tAddress(params), params.fcmpMaturity + params.lightProofDepth + 3);
    const r3 = JSON.parse((await client(alice.tAddress, String(COIN / 2n), 'private', 'fcmp')).stdout);
    await mineVia(url, miner.tAddress(params), 1);
    assert.equal((await rpc(url, 'gettransactionstatus', { txid: r3.sent.txid })).status, 'accepted', 'the network accepted the membership proof made in pure JS');
    const raw3 = Transaction.deserialize(fromHex((await rpc(url, 'gettransaction', { txid: r3.sent.txid })).tx));
    assert.ok(raw3.sIn.length && raw3.sIn.every((i) => i.ring.length === 0), 'no ring');
    console.log(`    sync in the "browser": ${r1.syncMs} ms, ${r1.sync.bytes} B; FCMP spend without threads: proof in ${(r3.sent.proveMs / 1000).toFixed(1)} s, ${r3.sent.anonymitySet} outputs`);

    // quantum-safe address (krq) with just the browser pieces: ML-DSA comes from the WebAssembly core
    if (!r1.pq) return; // KREVO_NO_WASM: the browser has no other ML-DSA (the app hides krq in that case)
    assert.equal(r1.qAddress, web.qAddress, 'the phrase produces the same krq address in the browser');
    const r4 = JSON.parse((await client('', '', '', 'migrate')).stdout);
    assert.equal(r4.migrated.txids.length, 1, 'the classic coins moved to krq');
    assert.ok(BigInt(r4.migrated.moved) > 2n * COIN - 100_000n, `moved ${r4.migrated.moved} grains`);
    await mineVia(url, miner.tAddress(params), params.lightProofDepth + 3);
    assert.equal((await rpc(url, 'gettransactionstatus', { txid: r4.migrated.txids[0] })).status, 'accepted');
    // spending from krq: the browser signs with Schnorr + ML-DSA
    const r5 = JSON.parse((await client(alice.tAddress, String(COIN / 2n), 'transparent')).stdout);
    await mineVia(url, miner.tAddress(params), 1);
    assert.equal((await rpc(url, 'gettransactionstatus', { txid: r5.sent.txid })).status, 'accepted', 'the network accepted the hybrid signature made in the browser');
    const raw5 = Transaction.deserialize(fromHex((await rpc(url, 'gettransaction', { txid: r5.sent.txid })).tx));
    assert.ok(raw5.tIn.length && raw5.tIn.every((i) => i.sig.length === PQ_WITNESS_SIZE), 'hybrid Schnorr + ML-DSA witness');
    console.log(`    krq in the "browser": ${r4.migrated.moved} grains migrated, then spent with a ${PQ_WITNESS_SIZE}-byte hybrid witness`);
  } finally {
    await ls.close();
    await node.stop();
  }
});
