// Light wallet: a public server + a wallet that does not trust it.
// Checks: receives and spends (private and transparent), only counts what was PROVEN, does not leak keys,
// asks for outputs with decoys and for key images by buckets, uses much less bandwidth, and a lying
// server that makes up a payment gets caught.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import http from 'node:http';
import { randomBytes } from 'node:crypto';
import { getParams, COIN } from '../src/params.js';
import { Node } from '../src/node/node.js';
import { Wallet } from '../src/wallet/wallet.js';
import { rpc } from '../src/node/rpcclient.js';
import { Block, merkleRoot, merkleProof, verifyMerkleProof } from '../src/consensus/block.js';
import { Transaction } from '../src/consensus/tx.js';
import { solve } from '../src/node/solver.js';
import { fromHex, toHex } from '../src/util/bytes.js';
import { Keys } from '../src/wallet/keys.js';
import { randomScalar } from '../src/crypto/secp256k1.js';
import { makeShieldedOutput } from '../src/crypto/stealth.js';
import { startLightServer } from '../src/light/server.js';
import { LightWallet } from '../src/light/wallet.js';
import { verifyAcceptanceProof } from '../src/light/verify.js';
import { freePorts } from './helpers.js';

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

test('Merkle proofs: all sizes and positions; tampering rejected', () => {
  for (let n = 1; n <= 33; n++) {
    const hs = Array.from({ length: n }, () => randomBytes(32));
    const root = merkleRoot(hs);
    for (let i = 0; i < n; i++) {
      const p = merkleProof(hs, i);
      assert.ok(verifyMerkleProof(hs[i], p, root), `${n}/${i}`);
      assert.equal(verifyMerkleProof(randomBytes(32), p, root), false);
      if (n > 1) assert.equal(verifyMerkleProof(hs[i], { ...p, index: (i + 1) % n }, root), false);
    }
  }
});

test('light wallet: receives, proves, spends, does not leak keys and uses little bandwidth; a lying server gets caught', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krv-light-'));
  const port = await freePorts(4);
  const node = new Node({ params, datadir: dir, p2pPort: port, rpcPort: port + 1, log: () => {}, persist: false });
  await node.start();
  const url = `http://127.0.0.1:${port + 1}`;
  const reqs = [];
  const ls = await startLightServer({ params, rpcUrl: url, port: 0, onRequest: (r) => reqs.push(r) });
  let liar;
  try {
    const alice = Wallet.create(path.join(dir, 'alice.json'), params, url);           // full wallet (own node)
    const bob = LightWallet.create(path.join(dir, 'bob.json'), params, ls.url);       // LIGHT wallet
    const miner = Keys.random();
    await mineVia(url, alice.tAddress, 30);
    await mineVia(url, miner.sAddress(params), 40);                                    // third-party private outputs (decoys)
    await mineVia(url, miner.tAddress(params), 12);

    // Alice pays Bob as private and as transparent
    const p1 = await alice.send({ to: bob.sAddress, amount: 2n * COIN, from: 'transparent', memo: 'cheese bread' });
    await mineVia(url, miner.tAddress(params), 1);
    const p2 = await alice.send({ to: bob.tAddress, amount: COIN, from: 'transparent' });
    await mineVia(url, miner.tAddress(params), 1);
    await alice.waitAccepted(p1.txid);
    await alice.waitAccepted(p2.txid);

    // right after: the server already shows it, but there are not enough blocks on top yet → it does not count
    await bob.sync();
    let b = bob.balance();
    assert.equal(b.transparent + b.shielded + b.shieldedImmature, 0n, 'nothing counts before the proof');
    assert.ok(b.unverified >= 3n * COIN, 'it shows as waiting for a proof');

    // N blocks later: proven (Merkle + headers with PoW), it starts to count
    await mineVia(url, miner.tAddress(params), params.lightProofDepth + 2);
    const st = await bob.sync();
    b = bob.balance();
    assert.equal(b.unverified, 0n);
    assert.equal(b.transparent, COIN);
    assert.equal(b.shielded + b.shieldedImmature, 2n * COIN);
    assert.equal(bob.history().received[0].memo, 'cheese bread', 'the encrypted memo arrives too');
    assert.ok(Object.keys(bob.light.verified).length >= 2);
    assert.deepEqual(bob.fraudReports, {});

    // privacy: no key left; outputs requested with decoys; key images by bucket
    const sent = JSON.stringify(reqs);
    assert.ok(!sent.includes(bob.keys.viewKey(params)), 'the view key was never sent');
    assert.ok(!reqs.some((r) => r.path === '/v1/scan'), 'no delegated scanning');
    const outReqs = reqs.filter((r) => r.path === '/v1/outputs');
    assert.ok(outReqs.length >= 1 && outReqs.every((r) => r.body.indices.length >= 16), 'each real output goes with 15 decoys');
    assert.ok(reqs.filter((r) => r.path.startsWith('/v1/keyimages/')).every((r) => /^\/v1\/keyimages\/[0-9a-f]{2}$/.test(r.path)), 'only 1-byte prefixes');

    // bandwidth: the compact scan vs. downloading all full outputs as the node wallet does
    const total = (await rpc(url, 'getinfo')).shieldedOutputs;
    const fullBytes = Buffer.byteLength(JSON.stringify(await rpc(url, 'getshieldedoutputs', { start: 0, count: total })));
    const compactBytes = 20 + 35 * total;
    assert.ok(compactBytes * 8 < fullBytes, `compacto ${compactBytes} B vs completo ${fullBytes} B`);
    console.log(`    scan bandwidth: ${compactBytes} B (light) vs ${fullBytes} B (full) for ${total} private outputs — ${(fullBytes / compactBytes).toFixed(1)}× less; whole sync: ${st.bytes} B in ${st.requests} requests`);

    // Bob SPENDS through the light wallet: private (ring with decoys fetched from the server) and transparent
    await mineVia(url, miner.tAddress(params), 3); // ring maturity
    await bob.sync();
    const s1 = await bob.send({ to: alice.sAddress, amount: COIN / 2n, from: 'private' });
    await mineVia(url, miner.tAddress(params), 1);
    assert.equal((await rpc(url, 'gettransactionstatus', { txid: s1.txid })).status, 'accepted', 'private spend accepted');
    const s2 = await bob.send({ to: alice.tAddress, amount: COIN / 4n, from: 'transparent' });
    await mineVia(url, miner.tAddress(params), 1);
    assert.equal((await rpc(url, 'gettransactionstatus', { txid: s2.txid })).status, 'accepted', 'transparent spend accepted');
    await mineVia(url, miner.tAddress(params), params.lightProofDepth + 2);
    await bob.sync();
    b = bob.balance();
    assert.ok(b.shielded + b.shieldedImmature < 2n * COIN && b.shielded + b.shieldedImmature > COIN, 'private change proven');

    // delegated scanning (optional): the same wallet restored, the server receives only the view key
    const bobD = LightWallet.restore(path.join(dir, 'bob-d.json'), params, ls.url, { mnemonic: bob.mnemonic });
    bobD.setDelegated(true);
    await bobD.sync();
    const bd = bobD.balance();
    assert.equal(bd.shielded + bd.shieldedImmature, b.shielded + b.shieldedImmature, 'same private balance');
    assert.ok(reqs.some((r) => r.path === '/v1/scan' && r.body.viewKey === bob.keys.viewKey(params)));

    // LYING SERVER: makes up a payment of 1,000 KRV to Bob (anyone can create
    // an output to a public address) and sends the proof of ANOTHER transaction
    const fake = makeShieldedOutput({ A: bob.keys.A, B: bob.keys.B }, randomScalar(), 0, 1000n * COIN);
    const fakeTx = new Transaction({ sOut: [{ R: fake.R.toBytes(), P: fake.P.toBytes(), C: fake.C.toBytes(), encAmount: fake.encAmount, viewTag: fake.viewTag }] });
    const fakeTxid = fakeTx.idHex;
    const realTotal = (await rpc(url, 'getinfo')).shieldedOutputs;
    const realProof = await rpc(url, 'gettxproof', { txid: p2.txid, depth: params.lightProofDepth });
    const fakeEntry = { index: realTotal, outpoint: `${fakeTxid}:0`, P: toHex(fake.P.toBytes()), C: toHex(fake.C.toBytes()), R: toHex(fake.R.toBytes()), encAmount: toHex(fake.encAmount), viewTag: fake.viewTag, j: 0, daa: 1, coinbase: false };
    liar = http.createServer(async (req, res) => {
      const u = new URL(req.url, 'http://x');
      let body = '';
      for await (const c of req) body += c;
      const fwd = await fetch(ls.url + req.url, { method: req.method, body: body || undefined, headers: body ? { 'content-type': 'application/json' } : {} });
      let buf = Buffer.from(await fwd.arrayBuffer());
      const json = (o) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(o)); };
      if (u.pathname === '/v1/info') { const o = JSON.parse(buf); o.outputs = realTotal + 1; return json(o); }
      if (u.pathname === '/v1/compact') {
        const start = Number(u.searchParams.get('start')), n = buf.readUInt32LE(8);
        if (start + n === realTotal) { // appends the fake output at the end
          buf.writeUInt32LE(realTotal + 1, 0); buf.writeUInt32LE(n + 1, 8);
          buf = Buffer.concat([buf, fake.R.toBytes(), Buffer.from([0, fake.viewTag])]);
        }
        res.writeHead(200, { 'content-type': 'application/octet-stream' }); return res.end(buf);
      }
      if (u.pathname === '/v1/outputs') { const o = JSON.parse(buf); if (JSON.parse(body).indices.includes(realTotal)) o.outputs.push(fakeEntry); return json(o); }
      if (u.pathname === `/v1/tx/${fakeTxid}`) return json({ txid: fakeTxid, tx: toHex(fakeTx.serialize()), status: 'accepted', confirmations: 50 });
      if (u.pathname === `/v1/proof/${fakeTxid}`) return json({ ...realProof, txid: fakeTxid });
      res.writeHead(fwd.status, { 'content-type': fwd.headers.get('content-type') ?? 'application/json' });
      return res.end(buf);
    });
    await new Promise((r) => liar.listen(0, '127.0.0.1', r));
    const victim = LightWallet.restore(path.join(dir, 'bob-v.json'), params, `http://127.0.0.1:${liar.address().port}`, { mnemonic: bob.mnemonic });
    await victim.sync();
    const vb = victim.balance();
    assert.ok(vb.shielded + vb.shieldedImmature < 2n * COIN, 'the made-up 1,000 KRV do NOT enter the balance');
    assert.ok(vb.unverified >= 1000n * COIN, 'they stay as "not proven"');
    assert.match(victim.fraudReports[fakeTxid] ?? '', /Merkle/, 'and the wallet records the server\'s fraud');
    await assert.rejects(() => victim.send({ to: alice.tAddress, amount: 500n * COIN, from: 'private' }), /insufficient/, 'you cannot spend made-up money');

    // the real proof, checked separately
    const ok = verifyAcceptanceProof(p2.txid, realProof, { minDepth: params.lightProofDepth });
    assert.equal(ok.depth, params.lightProofDepth);
    assert.throws(() => verifyAcceptanceProof(p2.txid, { ...realProof, chain: realProof.chain.slice(1) }, { minDepth: 1 }), /not chained/);
  } finally {
    liar?.closeAllConnections?.();
    liar?.close();
    await ls.close();
    await node.stop();
  }
});
