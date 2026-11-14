// Contrato de garantia (escrow) e prova de reservas, num nó real.
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
import { Keys } from '../src/wallet/keys.js';
import { multisigKey, encodeMultisigKey } from '../src/wallet/multisig.js';
import { EscrowContract, myRole, escrowStatus, escrowFund, escrowPropose, describeEscrowProposal, escrowSign, escrowReclaim } from '../src/wallet/escrow.js';
import { proveReserves, verifyReserves, buildLiabilities, verifyLiability, parseAccountsCsv } from '../src/wallet/reserves.js';
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
async function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krv-er-'));
  const port = await freePorts(4);
  const node = new Node({ params, datadir: dir, p2pPort: port, rpcPort: port + 1, log: () => {}, persist: false });
  await node.start();
  const url = `http://127.0.0.1:${port + 1}`;
  const mk = (n) => Wallet.create(path.join(dir, `${n}.json`), params, url);
  const miner = Keys.random().tAddress(params);
  return { dir, node, url, mk, mine: (n = 1) => mineVia(url, miner, n), mineTo: (a, n) => mineVia(url, a, n) };
}
const total = (w) => { const b = w.balance(); return b.transparent + b.transparentImmature + b.transparentPending; };

test('garantia: liberar (comprador+vendedor), disputa decidida pelo árbitro, prazo devolve ao comprador; ninguém age sozinho', async () => {
  const e = await setup();
  try {
    const buyer = e.mk('comprador'), seller = e.mk('vendedor'), arbiter = e.mk('arbitro'), outsider = e.mk('intruso');
    await e.mineTo(buyer.tAddress, 40);
    await e.mine(12);
    const key = (w) => encodeMultisigKey(params, multisigKey(w.keys).P);
    const make = (label, delay = 1000) => EscrowContract.create(params, { buyer: key(buyer), seller: key(seller), arbiter: key(arbiter), delay, amount: 3n * COIN, label });

    // código do contrato: todos chegam ao mesmo endereço e enxergam o próprio papel
    const c = make('Pedido42');
    const viaCode = EscrowContract.fromCode(params, c.code);
    assert.equal(viaCode.address, c.address);
    assert.equal(myRole(viaCode, buyer.keys), 'buyer');
    assert.equal(myRole(viaCode, seller.keys), 'seller');
    assert.equal(myRole(viaCode, arbiter.keys), 'arbiter');
    assert.equal(myRole(viaCode, outsider.keys), null);
    assert.equal(viaCode.amount, 3n * COIN);
    assert.throws(() => EscrowContract.create(params, { buyer: key(buyer), seller: key(buyer), arbiter: key(arbiter), delay: 10, amount: COIN }), /diferentes/);
    await assert.rejects(() => escrowFund(seller, c), /só o comprador/);

    // 1) tudo certo: comprador deposita; comprador propõe liberar; vendedor assina → pago
    await escrowFund(buyer, c);
    await e.mine(1);
    assert.equal((await escrowStatus(params, e.url, c)).funded, true);
    const prop = await escrowPropose({ params, rpcUrl: e.url, contract: c, walletKeys: buyer.keys, kind: 'liberar', to: seller.tAddress });
    const info = describeEscrowProposal(params, JSON.parse(JSON.stringify(prop)));
    assert.equal(info.to, seller.tAddress);
    assert.deepEqual(info.signedBy, ['buyer']);
    await assert.rejects(() => escrowSign({ params, rpcUrl: e.url, prop: JSON.parse(JSON.stringify(prop)), walletKeys: outsider.keys }), /não é parte/);
    const sellerBefore = (await seller.sync(), total(seller));
    const r = await escrowSign({ params, rpcUrl: e.url, prop, walletKeys: seller.keys });
    assert.equal(r.sent, true, 'com 2 de 3 assinaturas vai para a rede');
    await e.mine(2);
    await seller.sync();
    assert.ok(total(seller) - sellerBefore > 3n * COIN - 100_000n, 'vendedor recebeu (menos a taxa)');
    assert.equal((await escrowStatus(params, e.url, c)).empty, true);

    // 2) disputa: o árbitro decide reembolsar; o comprador assina junto
    const d = make('Pedido43');
    await escrowFund(buyer, d);
    await e.mine(1);
    const refund = await escrowPropose({ params, rpcUrl: e.url, contract: d, walletKeys: arbiter.keys, kind: 'reembolsar', to: buyer.tAddress });
    // o vendedor sozinho não consegue nada: a proposta do árbitro, assinada de novo pelo árbitro, segue com 1
    const again = await escrowSign({ params, rpcUrl: e.url, prop: JSON.parse(JSON.stringify(refund)), walletKeys: arbiter.keys });
    assert.equal(again.sent, false);
    assert.equal(again.have, 1);
    const rr = await escrowSign({ params, rpcUrl: e.url, prop: refund, walletKeys: buyer.keys });
    assert.equal(rr.sent, true);
    await e.mine(2);
    assert.equal((await escrowStatus(params, e.url, d)).empty, true, 'reembolsado');

    // 3) ninguém age: depois do prazo o comprador pega de volta SOZINHO (antes não)
    const t = make('Pedido44', 25);
    await escrowFund(buyer, t);
    await e.mine(1);
    await assert.rejects(() => escrowReclaim({ params, rpcUrl: e.url, contract: t, walletKeys: buyer.keys, to: buyer.tAddress }), /bloqueado/);
    await assert.rejects(() => escrowReclaim({ params, rpcUrl: e.url, contract: t, walletKeys: seller.keys, to: seller.tAddress }), /só o comprador/);
    await e.mine(26);
    assert.equal((await escrowStatus(params, e.url, t)).refundable, true);
    const back = await escrowReclaim({ params, rpcUrl: e.url, contract: t, walletKeys: buyer.keys, to: buyer.tAddress });
    assert.ok(back.amount > 3n * COIN - 100_000n);
    await e.mine(1);
    assert.equal((await escrowStatus(params, e.url, t)).empty, true);
  } finally { await e.node.stop(); }
});

test('prova de reservas: ativos (transparentes + privados) conferidos no nó; fraudes recusadas; passivos com árvore de somas', async () => {
  const e = await setup();
  try {
    const ex = e.mk('corretora'), other = e.mk('outra');
    await e.mineTo(ex.tAddress, 25);
    await e.mineTo(ex.sAddress, 15);   // moedas privadas da corretora
    await e.mine(15);
    await ex.sync();
    const b = ex.balance();
    const expected = b.transparent + b.transparentImmature + b.shielded + b.shieldedImmature;
    const msg = 'Exchange X — auditoria de 13/11/2026';
    const proof = await proveReserves(ex, msg);
    assert.ok(proof.private.length > 0 && proof.transparent.length > 0);
    const ok = await verifyReserves(params, e.url, JSON.parse(JSON.stringify(proof)), { message: msg });
    assert.deepEqual(ok.issues, []);
    assert.equal(ok.valid, true);
    assert.equal(ok.total, expected, 'total provado = saldo da carteira');

    // fraudes: valor inflado, prova reaproveitada com outra mensagem, moeda de outra pessoa
    const inflated = JSON.parse(JSON.stringify(proof));
    inflated.private[0].amount = (BigInt(inflated.private[0].amount) * 10n).toString();
    const r1 = await verifyReserves(params, e.url, inflated, { message: msg });
    assert.equal(r1.valid, false);
    assert.ok(r1.issues.some((i) => /compromisso/.test(i)));
    const replay = JSON.parse(JSON.stringify(proof));
    replay.message = 'Exchange X — auditoria de 14/11/2026';
    const r2 = await verifyReserves(params, e.url, replay, { message: replay.message });
    assert.ok(r2.issues.some((i) => /posse inválida|assinatura inválida/.test(i)), 'a prova está amarrada à mensagem');
    await e.mineTo(other.tAddress, 12);
    await other.sync();
    const stolen = JSON.parse(JSON.stringify(proof));
    stolen.transparent.push({ ...stolen.transparent[0], outpoint: other.tUtxos[0].outpoint, amount: String(other.tUtxos[0].amount) });
    const r3 = await verifyReserves(params, e.url, stolen, { message: msg });
    assert.ok(r3.issues.some((i) => /assinatura inválida/.test(i)), 'não dá para contar moeda dos outros');

    // gastou depois de provar → a mesma prova deixa de valer
    const coin = proof.private.find((p) => BigInt(p.amount) > COIN / 2n);
    await ex.send({ to: other.sAddress, amount: COIN / 4n, from: 'privado' });
    await e.mine(1);
    const r4 = await verifyReserves(params, e.url, proof, { message: msg });
    assert.ok(r4.issues.some((i) => /já foi gasta/.test(i)) || r4.total < ok.total, 'moeda gasta não conta mais');
    void coin;

    // passivos: árvore de somas, cada cliente confere a sua conta
    const accounts = parseAccountsCsv('conta;saldo\nana;12,5\nbia;0\ncaio;3\ndani,1.25\neva;7');
    assert.equal(accounts.length, 5);
    const { root, proofs } = buildLiabilities(accounts);
    assert.equal(BigInt(root.total), 23_75_000_000n);
    for (const p of proofs) assert.equal(verifyLiability(p, root).valid, true, p.id);
    const cheat = { ...proofs[0], balance: (BigInt(proofs[0].balance) * 2n).toString() };
    assert.equal(verifyLiability(cheat, root).valid, false, 'saldo alterado não confere');
    const other2 = buildLiabilities(accounts).root;
    assert.equal(verifyLiability(proofs[1], other2).valid, false, 'prova de outra árvore');
    assert.ok(!JSON.stringify(root).includes('ana'), 'a raiz não revela os clientes');
    assert.throws(() => buildLiabilities([{ id: 'x', balance: -1n }]), /negativo/);
    assert.throws(() => parseAccountsCsv('ana,12,5'), /linha inválida/);
  } finally { await e.node.stop(); }
});
