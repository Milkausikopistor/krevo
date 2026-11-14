// Integração: nó real (RPC + mempool) + carteira via RPC, mineração em processo.
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
import { buildPaymentURI, parsePaymentURI } from '../src/wallet/request.js';
import { Transaction } from '../src/consensus/tx.js';
import { multisigKey, encodeMultisigKey, MultisigGroup, proposePayment, checkProposalInputs, describeProposal,
  signProposal, mergeProposals, finalizeProposal, groupUtxos } from '../src/wallet/multisig.js';
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

test('nó + RPC + carteira: minerar, sincronizar, enviar transparente e privado', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krv-node-test-'));
  const port = await freePorts(4);
  const node = new Node({ params, datadir: dir, p2pPort: port, rpcPort: port + 1, log: () => {}, persist: false });
  await node.start();
  const url = `http://127.0.0.1:${port + 1}`;
  try {
    const alice = Wallet.create(path.join(dir, 'a.json'), params, url, { password: 'senha' });
    const bob = Wallet.create(path.join(dir, 'b.json'), params, url);
    // a semente é cifrada no disco quando há senha
    assert.ok(!fs.readFileSync(path.join(dir, 'a.json'), 'utf8').includes('"seed"'));
    assert.throws(() => Wallet.load(path.join(dir, 'a.json'), params, url, 'errada'), /senha incorreta/);

    await mineVia(url, alice.tAddress, 20);
    await mineVia(url, bob.sAddress, 10); // coinbase privada → conjunto de anonimato
    await alice.sync();
    assert.ok(alice.balance().transparent > 0n);

    // transparente → privado, com memo cifrado
    const r1 = await alice.send({ to: bob.sAddress, amount: COIN, from: 'transparente', memo: 'pedido #42 — obrigado!' });
    assert.equal((await rpc(url, 'gettransactionstatus', { txid: r1.txid })).status, 'mempool');
    await mineVia(url, alice.tAddress, 1);
    assert.equal((await rpc(url, 'gettransactionstatus', { txid: r1.txid })).status, 'accepted');

    await mineVia(url, alice.tAddress, 12); // maturidade (coinbase privada de Bob + membros do anel)
    await bob.sync();
    assert.ok(bob.balance().shielded >= COIN);

    // Bob lê o memo; o histórico de Alice registra o envio
    const got = bob.history().received.find((x) => x.txid === r1.txid);
    assert.equal(got.memo, 'pedido #42 — obrigado!');
    assert.equal(alice.history().sent[0].memo, 'pedido #42 — obrigado!');

    // Prova de pagamento: Alice prova a um terceiro, que verifica só com um nó
    const proof = alice.prove(r1.txid, 'fatura 42');
    const ok = await Wallet.verifyProof(params, url, { proof, address: bob.sAddress, message: 'fatura 42' });
    assert.equal(ok.valid, true, ok.reason);
    assert.equal(ok.total, COIN);
    assert.equal(ok.memo, 'pedido #42 — obrigado!');
    assert.equal(ok.status, 'accepted');
    const wrong = await Wallet.verifyProof(params, url, { proof, address: alice.sAddress, message: 'fatura 42' });
    assert.equal(wrong.valid, false);
    assert.throws(() => alice.prove('00'.repeat(32)), /não tem registro/);

    // Cobrança por QR: Bob (loja) gera o link, começa a esperar; Alice paga pelo link.
    const uri = buildPaymentURI(params, { address: bob.sAddress, amount: COIN / 4n, memo: 'KRV-TESTE1', label: 'Loja do Bob' });
    const waiting = bob.waitForPayment(parsePaymentURI(params, uri), { timeoutMs: 30_000, intervalMs: 100 });
    const paid = await alice.payRequest(uri);
    assert.equal(paid.request.label, 'Loja do Bob');
    await mineVia(url, alice.tAddress, 1);
    const arrived = await waiting;
    assert.equal(arrived.txid, paid.txid);
    assert.equal(arrived.amount, COIN / 4n);
    assert.equal(arrived.memo, "KRV-TESTE1");
    await assert.rejects(alice.payRequest(buildPaymentURI(params, { address: bob.sAddress, amount: COIN, expires: 1 })), /expirou/);

    // Subendereços: Bob cria um por cliente; cada pagamento cai no subendereço certo.
    const subA = bob.newSubaddress('Cliente A'), subB = bob.newSubaddress('Cliente B');
    assert.notEqual(subA.address, subB.address);
    assert.notEqual(subA.address, bob.sAddress);
    await alice.send({ to: subA.address, amount: COIN / 5n, from: 'transparente' });
    await mineVia(url, alice.tAddress, 1);
    await alice.send({ to: subB.address, amount: COIN / 8n, from: 'transparente', memo: 'para B' });
    await mineVia(url, alice.tAddress, 1);
    await bob.sync();
    const list = bob.listSubaddresses();
    assert.equal(list[1].label, 'Cliente A');
    assert.equal(list[1].received, COIN / 5n);
    assert.equal(list[2].received, COIN / 8n);
    assert.equal(bob.history().received.find((x) => x.memo === 'para B').subLabel, 'Cliente B');
    // cobrança num subendereço: a espera casa pelo subendereço + memo
    const subUri = buildPaymentURI(params, { address: subA.address, amount: COIN / 10n, memo: 'KRV-SUB01' });
    const waitSub = bob.waitForPayment(parsePaymentURI(params, subUri), { timeoutMs: 30_000, intervalMs: 100 });
    await alice.payRequest(subUri);
    await mineVia(url, alice.tAddress, 1);
    assert.equal((await waitSub).amount, COIN / 10n);

    // Dave só recebe num subendereço e GASTA esse dinheiro: prova que a chave de gasto do
    // subendereço (k + b + m_i) é aceita pela rede.
    const dave = Wallet.create(path.join(dir, 'd.json'), params, url);
    const daveSub = dave.newSubaddress('único');
    await alice.send({ to: daveSub.address, amount: COIN, from: 'transparente' });
    await mineVia(url, alice.tAddress, 4); // maturidade dos membros do anel
    await dave.sync();
    assert.equal(dave.data.sOwned[0].sub, 1);
    const spent = await dave.send({ to: alice.tAddress, amount: COIN / 2n, from: 'privado' });
    await mineVia(url, alice.tAddress, 1);
    assert.equal((await rpc(url, 'gettransactionstatus', { txid: spent.txid })).status, 'accepted');
    // e a frase de recuperação reencontra o subendereço (busca à frente), sem saber que ele existia
    const dave2 = Wallet.restore(path.join(dir, 'd2.json'), params, url, { mnemonic: dave.mnemonic });
    await dave2.sync();
    assert.equal(dave2.subCount, 2);
    await dave.sync();
    assert.deepEqual(dave2.balance(), dave.balance());

    // Multiassinatura 2-de-3 (Bob, Dave e Carol-chave): proposta → 2 assinaturas → envio.
    const carolW = Wallet.create(path.join(dir, 'c.json'), params, url);
    const signers = [bob, dave, carolW];
    const grp = MultisigGroup.create(params, 2, signers.map((s) => encodeMultisigKey(params, multisigKey(s.keys).P)), 'Empresa');
    await alice.send({ to: grp.address, amount: 2n * COIN, from: 'transparente' });
    await mineVia(url, alice.tAddress, 1);
    const prop = await proposePayment({ params, rpcUrl: url, group: grp, to: carolW.sAddress, amount: COIN / 2n, memo: 'NF 881' });
    const seen = await checkProposalInputs(params, url, prop);
    assert.equal(seen.payments[0].amount, COIN / 2n);
    assert.equal(seen.payments[0].memo, 'NF 881');
    // adulteração no caminho: trocar o destinatário declarado é detectado antes de assinar
    assert.throws(() => describeProposal(params, { ...prop, to: alice.sAddress }), /NÃO assine/);
    // alterar o CONTEÚDO da transação (ex.: o troco) muda o txid e é detectado
    const forged = Transaction.deserialize(fromHex(prop.tx)); forged.tOut[0].amount -= 1000n; forged.invalidate();
    assert.throws(() => describeProposal(params, { ...prop, tx: toHex(forged.serialize()) }), /adulterada/);
    assert.throws(() => signProposal(params, structuredClone(prop), alice.keys), /não faz parte/);
    signProposal(params, prop, dave.keys);
    assert.throws(() => finalizeProposal(params, prop), /1 de 2/);
    const copy = structuredClone(prop);
    signProposal(params, copy, bob.keys); // assinado em outra cópia do arquivo
    const msTx = finalizeProposal(params, mergeProposals([prop, copy]));
    await rpc(url, 'sendrawtransaction', { tx: toHex(msTx.serialize()) });
    await mineVia(url, alice.tAddress, 1);
    assert.equal((await rpc(url, 'gettransactionstatus', { txid: msTx.idHex })).status, 'accepted');
    await carolW.sync();
    assert.equal(carolW.history().received[0].memo, 'NF 881');
    const grpLeft = (await groupUtxos(url, grp)).reduce((a, u) => a + BigInt(u.amount), 0n);
    assert.equal(grpLeft, 2n * COIN - COIN / 2n - msTx.fee);

    // privado → transparente
    const r2 = await bob.send({ to: alice.tAddress, amount: COIN / 2n, from: 'privado' });
    await mineVia(url, alice.tAddress, 1);
    assert.equal((await rpc(url, 'gettransactionstatus', { txid: r2.txid })).status, 'accepted');
    await bob.sync();
    assert.ok(bob.data.sOwned.some((o) => o.spent), 'saída privada marcada como gasta');

    // Recuperação: só com as 24 palavras, num arquivo novo, Bob reencontra os fundos
    // privados (varredura completa da rede) e o histórico de gastos.
    const bobBalance = bob.balance();
    const bob2 = Wallet.restore(path.join(dir, 'b2.json'), params, url, { mnemonic: bob.mnemonic });
    await bob2.sync();
    assert.deepEqual(bob2.balance(), bobBalance);
    assert.equal(bob2.data.sOwned.filter((o) => o.spent).length, bob.data.sOwned.filter((o) => o.spent).length);

    const info = await rpc(url, 'getinfo');
    assert.equal(info.network, 'simnet');
    assert.ok(BigInt(info.minted) > 0n);
  } finally {
    await node.stop();
  }
});
