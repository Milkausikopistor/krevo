// Carteira leve: servidor público + carteira que não confia nele.
// Confere: recebe e gasta (privado e transparente), só conta o que foi PROVADO, não vaza chaves,
// pede saídas com iscas e imagens de chave por baldes, gasta muito menos banda, e um servidor
// mentiroso que inventa um pagamento é pego.
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

test('provas de Merkle: todos os tamanhos e posições; adulteração recusada', () => {
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

test('carteira leve: recebe, prova, gasta, não vaza chaves e gasta pouca banda; servidor mentiroso é pego', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krv-light-'));
  const port = 19000 + Math.floor(Math.random() * 900);
  const node = new Node({ params, datadir: dir, p2pPort: port, rpcPort: port + 1, log: () => {}, persist: false });
  await node.start();
  const url = `http://127.0.0.1:${port + 1}`;
  const reqs = [];
  const ls = await startLightServer({ params, rpcUrl: url, port: 0, onRequest: (r) => reqs.push(r) });
  let liar;
  try {
    const alice = Wallet.create(path.join(dir, 'alice.json'), params, url);           // carteira completa (nó próprio)
    const bob = LightWallet.create(path.join(dir, 'bob.json'), params, ls.url);       // carteira LEVE
    const miner = Keys.random();
    await mineVia(url, alice.tAddress, 30);
    await mineVia(url, miner.sAddress(params), 40);                                    // saídas privadas de terceiros (iscas)
    await mineVia(url, miner.tAddress(params), 12);

    // Alice paga Bob no privado e no transparente
    const p1 = await alice.send({ to: bob.sAddress, amount: 2n * COIN, from: 'transparente', memo: 'pão de queijo' });
    await mineVia(url, miner.tAddress(params), 1);
    const p2 = await alice.send({ to: bob.tAddress, amount: COIN, from: 'transparente' });
    await mineVia(url, miner.tAddress(params), 1);
    await alice.waitAccepted(p1.txid);
    await alice.waitAccepted(p2.txid);

    // logo depois: o servidor já mostra, mas ainda não há blocos suficientes por cima → não conta
    await bob.sync();
    let b = bob.balance();
    assert.equal(b.transparent + b.shielded + b.shieldedImmature, 0n, 'nada conta antes da prova');
    assert.ok(b.unverified >= 3n * COIN, 'aparece como aguardando prova');

    // N blocos depois: provado (Merkle + cabeçalhos com PoW), passa a contar
    await mineVia(url, miner.tAddress(params), params.lightProofDepth + 2);
    const st = await bob.sync();
    b = bob.balance();
    assert.equal(b.unverified, 0n);
    assert.equal(b.transparent, COIN);
    assert.equal(b.shielded + b.shieldedImmature, 2n * COIN);
    assert.equal(bob.history().received[0].memo, 'pão de queijo', 'o memo cifrado também chega');
    assert.ok(Object.keys(bob.light.verified).length >= 2);
    assert.deepEqual(bob.fraudReports, {});

    // privacidade: nenhuma chave saiu; saídas pedidas com iscas; imagens de chave por balde
    const sent = JSON.stringify(reqs);
    assert.ok(!sent.includes(bob.keys.viewKey(params)), 'a chave de visualização nunca foi enviada');
    assert.ok(!reqs.some((r) => r.path === '/v1/scan'), 'sem varredura delegada');
    const outReqs = reqs.filter((r) => r.path === '/v1/outputs');
    assert.ok(outReqs.length >= 1 && outReqs.every((r) => r.body.indices.length >= 16), 'cada saída real vai com 15 iscas');
    assert.ok(reqs.filter((r) => r.path.startsWith('/v1/keyimages/')).every((r) => /^\/v1\/keyimages\/[0-9a-f]{2}$/.test(r.path)), 'só prefixos de 1 byte');

    // banda: a varredura compacta vs. baixar todas as saídas completas como a carteira de nó faz
    const total = (await rpc(url, 'getinfo')).shieldedOutputs;
    const fullBytes = Buffer.byteLength(JSON.stringify(await rpc(url, 'getshieldedoutputs', { start: 0, count: total })));
    const compactBytes = 20 + 35 * total;
    assert.ok(compactBytes * 8 < fullBytes, `compacto ${compactBytes} B vs completo ${fullBytes} B`);
    console.log(`    banda da varredura: ${compactBytes} B (leve) vs ${fullBytes} B (completa) para ${total} saídas privadas — ${(fullBytes / compactBytes).toFixed(1)}× menos; sincronização inteira: ${st.bytes} B em ${st.requests} requisições`);

    // Bob GASTA pela carteira leve: privado (anel com iscas buscadas no servidor) e transparente
    await mineVia(url, miner.tAddress(params), 3); // maturidade do anel
    await bob.sync();
    const s1 = await bob.send({ to: alice.sAddress, amount: COIN / 2n, from: 'privado' });
    await mineVia(url, miner.tAddress(params), 1);
    assert.equal((await rpc(url, 'gettransactionstatus', { txid: s1.txid })).status, 'accepted', 'gasto privado aceito');
    const s2 = await bob.send({ to: alice.tAddress, amount: COIN / 4n, from: 'transparente' });
    await mineVia(url, miner.tAddress(params), 1);
    assert.equal((await rpc(url, 'gettransactionstatus', { txid: s2.txid })).status, 'accepted', 'gasto transparente aceito');
    await mineVia(url, miner.tAddress(params), params.lightProofDepth + 2);
    await bob.sync();
    b = bob.balance();
    assert.ok(b.shielded + b.shieldedImmature < 2n * COIN && b.shielded + b.shieldedImmature > COIN, 'troco privado provado');

    // varredura delegada (opcional): mesma carteira restaurada, servidor recebe só a chave de visualização
    const bobD = LightWallet.restore(path.join(dir, 'bob-d.json'), params, ls.url, { mnemonic: bob.mnemonic });
    bobD.setDelegated(true);
    await bobD.sync();
    const bd = bobD.balance();
    assert.equal(bd.shielded + bd.shieldedImmature, b.shielded + b.shieldedImmature, 'mesmo saldo privado');
    assert.ok(reqs.some((r) => r.path === '/v1/scan' && r.body.viewKey === bob.keys.viewKey(params)));

    // SERVIDOR MENTIROSO: inventa um pagamento de 1.000 KRV para Bob (qualquer um consegue criar
    // uma saída para um endereço público) e manda a prova de OUTRA transação
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
        if (start + n === realTotal) { // acrescenta a saída falsa no fim
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
    assert.ok(vb.shielded + vb.shieldedImmature < 2n * COIN, 'os 1.000 KRV inventados NÃO entram no saldo');
    assert.ok(vb.unverified >= 1000n * COIN, 'ficam como "não provados"');
    assert.match(victim.fraudReports[fakeTxid] ?? '', /Merkle/, 'e a carteira registra a fraude do servidor');
    await assert.rejects(() => victim.send({ to: alice.tAddress, amount: 500n * COIN, from: 'privado' }), /insuficiente/, 'não dá para gastar dinheiro inventado');

    // a prova real, verificada à parte
    const ok = verifyAcceptanceProof(p2.txid, realProof, { minDepth: params.lightProofDepth });
    assert.equal(ok.depth, params.lightProofDepth);
    assert.throws(() => verifyAcceptanceProof(p2.txid, { ...realProof, chain: realProof.chain.slice(1) }, { minDepth: 1 }), /encadeados/);
  } finally {
    liar?.closeAllConnections?.();
    liar?.close();
    await ls.close();
    await node.stop();
  }
});
