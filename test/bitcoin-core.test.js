// Validation against the REAL BITCOIN CORE (regtest). Optional: it only runs with
//   BITCOIND=/path/to/bitcoind node --test test/bitcoin-core.test.js
// Starts an isolated bitcoind (127.0.0.1 only, no P2P network, temporary folder) and checks that
// Bitcoin Core itself accepts — and rejects — exactly what it should in atomic swaps.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { getParams, COIN } from '../src/params.js';
import { Node } from '../src/node/node.js';
import { Wallet } from '../src/wallet/wallet.js';
import { rpc } from '../src/node/rpcclient.js';
import { Block } from '../src/consensus/block.js';
import { solve } from '../src/node/solver.js';
import { fromHex, toHex } from '../src/util/bytes.js';
import { Keys } from '../src/wallet/keys.js';
import { BTC_NETWORKS, p2wpkhAddress, decodeBtcAddress, sha256 } from '../src/btc/address.js';
import { pubFromPriv } from '../src/btc/ecdsa.js';
import { btcHtlc, spendBtcHtlc } from '../src/btc/htlc.js';
import { BitcoinCore } from '../src/btc/core.js';
import { createOffer, acceptOffer, importAcceptance, swapStep } from '../src/wallet/swap.js';
import { freePorts } from './helpers.js';

const BITCOIND = process.env.BITCOIND;
const skip = BITCOIND ? false : 'set BITCOIND=path/to/bitcoind to validate against the real Bitcoin Core';
const net = BTC_NETWORKS.regtest;
const sats = (btc) => Math.round(Number(btc) * 1e8);

async function startCore() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krv-core-'));
  const port = await freePorts(4);
  const pass = randomBytes(12).toString('hex');
  const proc = spawn(BITCOIND, ['-regtest', `-datadir=${dir}`, '-listen=0', '-dnsseed=0', '-connect=0', '-server=1',
    '-rpcbind=127.0.0.1', '-rpcallowip=127.0.0.1', `-rpcport=${port}`, '-rpcuser=krevo', `-rpcpassword=${pass}`,
    '-fallbackfee=0.0002', '-txindex=1', '-printtoconsole=0'], { stdio: 'ignore' });
  const url = `http://krevo:${pass}@127.0.0.1:${port}`;
  const core = new BitcoinCore(url);
  for (let i = 0; ; i++) {
    try { await core.rpc('getblockchaininfo'); break; } catch (e) {
      if (i > 120) throw new Error('bitcoind did not respond: ' + e.message);
      await new Promise((r) => setTimeout(r, 250));
    }
  }
  const funder = new BitcoinCore(url, { wallet: 'funder' });
  await core.rpc('createwallet', ['funder']);
  const minerAddr = await funder.rpc('getnewaddress', ['', 'bech32'], true);
  await core.rpc('generatetoaddress', [101, minerAddr]);
  return {
    url, core, version: (await core.rpc('getnetworkinfo')).subversion,
    mine: (n = 1) => core.rpc('generatetoaddress', [n, minerAddr]),
    pay: (address, value) => funder.rpc('sendtoaddress', [address, (Number(value) / 1e8).toFixed(8)], true),
    received: async (address) => sats((await core.rpc('scantxoutset', ['start', [`addr(${address})`]])).total_amount),
    stop: async () => {
      try { await core.rpc('stop'); } catch { /* already stopping */ }
      await Promise.race([new Promise((r) => proc.once('exit', r)), new Promise((r) => setTimeout(r, 15_000))]);
      proc.kill();
    },
  };
}

test('real Bitcoin Core: addresses, HTLC script, claim, refund and attacks', { skip, timeout: 120_000 }, async () => {
  const c = await startCore();
  try {
    console.log(`    validating against ${c.version}`);
    const claimKey = 0x1111n, refundKey = 0x2222n;
    const dest = p2wpkhAddress(net, pubFromPriv(0x4444n));
    const va = await c.core.rpc('validateaddress', [dest]);
    assert.equal(va.isvalid, true);
    assert.equal(va.scriptPubKey, decodeBtcAddress(net, dest).script.toString('hex'), 'same scriptPubKey');

    const secret = randomBytes(32), hash = sha256(secret);
    const deadline = (await c.core.tip()).time + 3600;
    const h = btcHtlc(net, { hash, claimPub: pubFromPriv(claimKey), refundPub: pubFromPriv(refundKey), locktime: deadline });
    const ds = await c.core.rpc('decodescript', [h.script.toString('hex')]);
    assert.equal(ds.segwit.address, h.address, 'Bitcoin Core reaches the same P2WSH address');
    assert.match(ds.asm, /^OP_IF OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 [0-9a-f]{64} OP_EQUALVERIFY [0-9a-f]{66} OP_ELSE \d+ OP_CHECKLOCKTIMEVERIFY OP_DROP [0-9a-f]{66} OP_ENDIF OP_CHECKSIG$/);

    const fund = async (htlc, value) => {
      const txid = await c.pay(htlc.address, value);
      await c.mine(1);
      const tx = await c.core.rpc('getrawtransaction', [txid, true]);
      return [{ txid, vout: tx.vout.findIndex((o) => o.scriptPubKey.address === htlc.address), value: Number(value) }];
    };
    const check = async (hex) => (await c.core.rpc('testmempoolaccept', [[hex]]))[0];
    const spend = (o) => spendBtcHtlc({ net, htlc: h, to: dest, feeRate: 2, ...o });

    const u = await fund(h, 100_000n);
    let r = await check(spend({ utxos: u, key: claimKey, secret: Buffer.alloc(32, 1) }).hex);
    assert.equal(r.allowed, false, 'wrong secret');
    assert.match(r['reject-reason'], /script-verify/);
    r = await check(spend({ utxos: u, key: 0x3333n, secret }).hex);
    assert.equal(r.allowed, false, 'wrong key');
    r = await check(spend({ utxos: u, key: refundKey }).hex);
    assert.equal(r.allowed, false, 'refund before the deadline');
    assert.match(r['reject-reason'], /non-final/);

    // the right claim: accepted, and Bitcoin Core computes the same txid, weight and size as we do
    const ok = spend({ utxos: u, key: claimKey, secret });
    r = await check(ok.hex);
    assert.equal(r.allowed, true, r['reject-reason']);
    const dec = await c.core.rpc('decoderawtransaction', [ok.hex]);
    assert.equal(dec.txid, ok.txid);
    assert.equal(dec.weight, ok.tx.weight);
    assert.equal(dec.vsize, ok.tx.vsize);
    assert.equal(await c.core.broadcast(ok.hex), ok.txid);
    await c.mine(1);
    const conf = await c.core.rpc('getrawtransaction', [ok.txid, true]);
    assert.ok(conf.confirmations >= 1, 'confirmed in a block');
    assert.equal(conf.vin[0].txinwitness[1], secret.toString('hex'), 'the secret becomes public in the witness');
    assert.equal(await c.received(dest), Number(ok.value));

    // 31-byte secret with the right hash: OP_SIZE 32 rejects it
    const s31 = randomBytes(31);
    const h31 = btcHtlc(net, { hash: sha256(s31), claimPub: pubFromPriv(claimKey), refundPub: pubFromPriv(refundKey), locktime: deadline });
    const u31 = await fund(h31, 50_000n);
    const t31 = spendBtcHtlc({ net, htlc: h31, utxos: u31, to: dest, feeRate: 2, key: claimKey, secret: Buffer.alloc(32) });
    t31.tx.inputs[0].witness[1] = s31; // the signature does not cover the witness
    r = await check(t31.tx.toHex());
    assert.equal(r.allowed, false, '31-byte secret');

    // refund: after the median time passes the deadline
    const u2 = await fund(h, 70_000n);
    const cheat = spend({ htlc: { ...h, locktime: deadline - 1800 }, utxos: u2, key: refundKey });
    await c.core.rpc('setmocktime', [deadline + 4 * 3600]);
    await c.mine(12);
    assert.ok((await c.core.tip()).mtp > deadline);
    r = await check(cheat.hex);
    assert.equal(r.allowed, false, 'nLockTime below the contract deadline');
    r = await check(spend({ utxos: u2, key: claimKey }).hex);
    assert.equal(r.allowed, false, 'refund with the claimer\'s key');
    const refund = spend({ utxos: u2, key: refundKey });
    r = await check(refund.hex);
    assert.equal(r.allowed, true, r['reject-reason']);
    await c.core.broadcast(refund.hex);
    await c.mine(1);
    assert.ok((await c.core.rpc('getrawtransaction', [refund.txid, true])).confirmations >= 1);
  } finally { await c.stop(); }
});

async function mineVia(url, address, n) {
  for (let i = 0; i < n; i++) {
    const t = await rpc(url, 'getblocktemplate', { address });
    const b = Block.deserialize(fromHex(t.block));
    assert.ok(solve(b));
    const r = await rpc(url, 'submitblock', { block: toHex(b.serialize()) });
    assert.equal(r.status, 'accepted', r.reason);
  }
}

test('full atomic swap with the real Bitcoin Core (selling KRV and selling BTC)', { skip, timeout: 180_000 }, async () => {
  const c = await startCore();
  const params = getParams('simnet');
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krv-core-swap-'));
  const port = await freePorts(4);
  const node = new Node({ params, datadir: dir, p2pPort: port, rpcPort: port + 1, log: () => {}, persist: false });
  await node.start();
  const url = `http://127.0.0.1:${port + 1}`;
  try {
    const alice = Wallet.create(path.join(dir, 'alice.json'), params, url);
    const bob = Wallet.create(path.join(dir, 'bob.json'), params, url);
    const miner = Keys.random().tAddress(params);
    await mineVia(url, alice.tAddress, 30);
    await mineVia(url, miner, 12);
    const mineKrv = (n = 1) => mineVia(url, miner, n);
    const aliceBtc = p2wpkhAddress(net, pubFromPriv(0xa11cen)), bobBtc = p2wpkhAddress(net, pubFromPriv(0xb0bn));
    const step = async (w, id, expect) => { const r = await swapStep(w, id); assert.equal(r.action, expect, r.message); return r; };

    // 1) Alice sells 3 KRV for 0.0015 BTC
    let o = createOffer(alice, { sell: 'krv', krv: 3n * COIN, btc: 150_000n, btcNet: 'regtest', btcPayout: aliceBtc, btcRpc: c.url, iWindow: 600, pWindow: 300 });
    let a = acceptOffer(bob, o.code, { btcPayout: bobBtc, btcRpc: c.url });
    importAcceptance(alice, a.code);
    await step(alice, o.id, 'lock');
    await mineKrv(1);
    const pay = await step(bob, a.id, 'pay-btc');
    await c.pay(pay.address, 150_000n);               // Bob pays from the Bitcoin Core wallet
    await c.mine(1);
    await step(bob, a.id, 'wait-secret');
    await step(alice, o.id, 'claim');                  // reveals the secret on Bitcoin
    await c.mine(1);
    await step(bob, a.id, 'claim');                    // Bob reads the secret on Bitcoin Core and claims the KRV
    await mineKrv(1);
    await step(bob, a.id, 'done');
    await step(alice, o.id, 'done');
    const got = await c.received(aliceBtc);
    assert.ok(got > 150_000 - 2_000 && got < 150_000, `Alice recebeu ${got} sat no Bitcoin Core`);

    // 2) Alice sells 0.0008 BTC for 2 KRV (Bob now has KRV)
    o = createOffer(alice, { sell: 'btc', krv: 2n * COIN, btc: 80_000n, btcNet: 'regtest', btcPayout: aliceBtc, btcRpc: c.url, iWindow: 600, pWindow: 300 });
    a = acceptOffer(bob, o.code, { btcPayout: bobBtc, btcRpc: c.url });
    importAcceptance(alice, a.code);
    const p2 = await step(alice, o.id, 'pay-btc');
    await c.pay(p2.address, 80_000n);
    await c.mine(1);
    await step(bob, a.id, 'lock');
    await mineKrv(1);
    await step(alice, o.id, 'claim');                  // reveals the secret on Krevo
    await mineKrv(1);
    await step(bob, a.id, 'claim');                    // Bob claims the BTC on Bitcoin Core
    await c.mine(1);
    await step(bob, a.id, 'done');
    await step(alice, o.id, 'done');
    const gotBob = await c.received(bobBtc);
    assert.ok(gotBob > 80_000 - 2_000 && gotBob < 80_000, `Bob recebeu ${gotBob} sat no Bitcoin Core`);
  } finally {
    await node.stop();
    await c.stop();
  }
});
