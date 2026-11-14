// Nomes legíveis (@nome): formato, regras de consenso (compromisso/revelação, taxa, dono,
// vencimento, carência) e o fluxo completo na carteira (registrar, pagar para @nome, alterar,
// transferir para um endereço quântico, renovar, liberar).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getParams, COIN } from '../src/params.js';
import { Consensus } from '../src/consensus/consensus.js';
import { Keys } from '../src/wallet/keys.js';
import { buildTransaction } from '../src/wallet/builder.js';
import { validateTxStateless } from '../src/consensus/txvalidation.js';
import { parseAddressData, describeLock } from '../src/address.js';
import {
  checkName, isValidName, normalizeName, nameFee, encodeNameRecord, parseNameRecord, nameCommitHash, nameCommitLock,
  commitWitnessPrefix, parseCommitWitness,
} from '../src/consensus/names.js';
import { Clock, mine, matureTUtxos } from './helpers.js';
import { Node } from '../src/node/node.js';
import { Wallet } from '../src/wallet/wallet.js';
import { rpc } from '../src/node/rpcclient.js';
import { Block } from '../src/consensus/block.js';
import { solve } from '../src/node/solver.js';
import { fromHex, toHex } from '../src/util/bytes.js';
import { nameCommit, nameReveal, nameRevealWait, nameUpdate, nameTransfer, nameRenew, nameRelease, myNames } from '../src/wallet/names.js';

const params = getParams('simnet');
const DEP = params.nameMinDeposit;

test('nomes: sintaxe, taxas por tamanho e formato do registro', () => {
  assert.equal(normalizeName('  @Padaria '), 'padaria');
  for (const ok of ['abc', 'padaria-sol', 'loja24', 'a1b', 'x'.repeat(32)]) assert.ok(isValidName(ok), ok);
  for (const bad of ['ab', '-abc', 'abc-', 'a--b', 'açaí', 'pão', 'ABC', 'a b c', 'x'.repeat(33), 'a_b', 'xn--abc']) assert.equal(isValidName(bad), false, bad);
  assert.throws(() => checkName('@pão'), /inválido/);
  assert.equal(nameFee(params, 'abc'), 100n * COIN);
  assert.equal(nameFee(params, 'abcd'), 20n * COIN);
  assert.equal(nameFee(params, 'abcde'), 5n * COIN);
  assert.equal(nameFee(params, 'padaria'), COIN);
  const k = Keys.random();
  const rec = { name: 'padaria', expiry: 123456, owner: k.tKey(0).lock, target: k.shieldedData };
  const lock = encodeNameRecord(rec);
  assert.deepEqual(parseNameRecord(lock), rec);
  assert.equal(parseAddressData(lock).type, 'n');
  assert.equal(describeLock(params, lock), '@padaria (registro de nome)');
  const salt = Buffer.alloc(32, 7);
  const w = Buffer.concat([commitWitnessPrefix('padaria', salt, rec.owner), Buffer.alloc(64, 1)]);
  const c = parseCommitWitness(w);
  assert.equal(c.name, 'padaria');
  assert.ok(nameCommitHash(c.name, c.salt, c.owner).equals(nameCommitHash('padaria', salt, rec.owner)));
  assert.equal(c.inner.length, 64);
});

/** Ajudantes para montar as transações de nomes direto no consenso. */
function nameKit(c, clock, funder) {
  const daa = () => c.virtual.gd.daaScore;
  const mineN = (n, txs = []) => { for (let i = 0; i < n; i++) mine(c, funder.tKey(0).lock, i === 0 ? txs : [], clock); };
  const fund = (keys, n = 4) => matureTUtxos(c, keys).sort((a, b) => (a.amount > b.amount ? -1 : 1)).slice(0, n);
  const status = (tx) => c.txStatus(tx.idHex).status;
  const commit = (owner, name, salt) => buildTransaction({
    params, tInputs: fund(owner), outputs: [{ type: 't', lock: nameCommitLock(nameCommitHash(name, salt, owner.tKey(0).lock)), amount: 1_000_000n }],
    change: { type: 't', lock: owner.tKey(0).lock },
  }).tx;
  const reveal = (owner, name, salt, commitTx, { target = owner.shieldedData, fee = nameFee(params, name), expiry = daa() + params.namePeriod - 5, payer = owner } = {}) => buildTransaction({
    params,
    tInputs: [{ outpoint: { txid: commitTx.id, index: 0 }, amount: 1_000_000n, signer: owner.tKey(0).signer, prefix: commitWitnessPrefix(name, salt, owner.tKey(0).lock) }, ...fund(payer)],
    outputs: [{ type: 't', lock: encodeNameRecord({ name, expiry, owner: owner.tKey(0).lock, target }), amount: DEP }],
    change: { type: 't', lock: payer.tKey(0).lock }, extraFee: fee,
  }).tx;
  const record = (name) => {
    const live = c.virtual.view.nameEntries(name).map(({ key, e }) => ({ key, e, r: parseNameRecord(e.lock) }))
      .filter((x) => daa() <= x.r.expiry + params.nameGrace);
    return live[0] ?? null;
  };
  /** Gasta o registro atual (assinado por `signer`) recriando-o com mudanças. */
  const spendRecord = (name, signer, payer, { target, owner, expiry, fee = 0n, release = false } = {}) => {
    const cur = record(name);
    const [txid, index] = cur.key.split(':');
    const input = { outpoint: { txid: Buffer.from(txid, 'hex'), index: Number(index) }, amount: cur.e.amount, signer: signer.tKey(0).signer };
    if (release) return buildTransaction({ params, tInputs: [input], sweep: { type: 't', lock: signer.tKey(0).lock } }).tx;
    const lock = encodeNameRecord({ name, expiry: expiry ?? cur.r.expiry, owner: owner ?? cur.r.owner, target: target ?? cur.r.target });
    return buildTransaction({ params, tInputs: [input, ...fund(payer)], outputs: [{ type: 't', lock, amount: cur.e.amount }], change: { type: 't', lock: payer.tKey(0).lock }, extraFee: fee }).tx;
  };
  return { daa, mineN, fund, status, commit, reveal, record, spendRecord };
}

test('consenso: compromisso → revelação, um só dono, taxa para o Fundo, alterar, renovar, vencer', () => {
  const c = new Consensus(params);
  const clock = new Clock();
  const alice = Keys.random(), bob = Keys.random();
  for (let i = 0; i < 40; i++) mine(c, alice.tKey(0).lock, [], clock);
  for (let i = 0; i < 40; i++) mine(c, bob.tKey(0).lock, [], clock);
  const k = nameKit(c, clock, alice);
  const saltA = Buffer.alloc(32, 0xa1), saltB = Buffer.alloc(32, 0xb2);

  // 1) compromisso de Alice; revelar cedo demais é ignorado
  const cA = k.commit(alice, 'padaria', saltA);
  k.mineN(1, [cA]);
  const early = k.reveal(alice, 'padaria', saltA, cA);
  k.mineN(1, [early]);
  assert.equal(k.status(early), 'unknown', 'revelação antes do prazo mínimo');
  k.mineN(params.nameCommitMin);
  // 2) sem a taxa: recusado; com a taxa: registrado
  const cheap = k.reveal(alice, 'padaria', saltA, cA, { fee: 0n });
  k.mineN(1, [cheap]);
  assert.equal(k.status(cheap), 'unknown', 'registro sem taxa');
  const ok = k.reveal(alice, 'padaria', saltA, cA);
  k.mineN(2, [ok]);
  assert.equal(k.status(ok), 'accepted');
  let rec = k.record('padaria');
  assert.ok(rec.r.owner.equals(alice.tKey(0).lock));
  assert.ok(rec.r.target.equals(alice.shieldedData));
  // a taxa foi inteira para o Fundo de Segurança (não para o minerador)
  const nameFees = [...c.acc.values()].reduce((a, x) => a + (x.nameFees ?? 0n), 0n);
  assert.equal(nameFees, nameFee(params, 'padaria'));

  // 3) Bob não consegue registrar o mesmo nome, mesmo com compromisso maduro
  const cB = k.commit(bob, 'padaria', saltB);
  k.mineN(1 + params.nameCommitMin, [cB]);
  const steal = k.reveal(bob, 'padaria', saltB, cB);
  k.mineN(1, [steal]);
  assert.equal(k.status(steal), 'unknown', 'nome já tem dono');
  // ...nem mexer no registro de Alice
  const hijack = k.spendRecord('padaria', bob, bob, { target: bob.shieldedData });
  k.mineN(1, [hijack]);
  assert.equal(k.status(hijack), 'unknown', 'só o dono altera');

  // 4) Alice muda o destino (sem taxa) — mas não pode esticar o prazo sem pagar
  const upd = k.spendRecord('padaria', alice, alice, { target: alice.tKey(0).lock });
  k.mineN(1, [upd]);
  assert.equal(k.status(upd), 'accepted');
  assert.ok(k.record('padaria').r.target.equals(alice.tKey(0).lock));
  const stretch = k.spendRecord('padaria', alice, alice, { expiry: k.record('padaria').r.expiry + 50 });
  k.mineN(1, [stretch]);
  assert.equal(k.status(stretch), 'unknown', 'esticar o vencimento sem taxa');
  const oldExpiry = k.record('padaria').r.expiry;
  const renew = k.spendRecord('padaria', alice, alice, { expiry: oldExpiry + 100, fee: nameFee(params, 'padaria') });
  k.mineN(1, [renew]);
  assert.equal(k.status(renew), 'accepted', 'renovação paga');
  rec = k.record('padaria');
  assert.equal(rec.r.expiry, oldExpiry + 100);

  // 5) vencido, mas na carência: só a dona pode renovar; Bob ainda não registra
  k.mineN(rec.r.expiry - k.daa() + 2);
  assert.ok(k.daa() > rec.r.expiry);
  const cB2 = k.commit(bob, 'padaria', Buffer.alloc(32, 0xb3));
  k.mineN(1 + params.nameCommitMin, [cB2]);
  const graceSteal = k.reveal(bob, 'padaria', Buffer.alloc(32, 0xb3), cB2);
  k.mineN(1, [graceSteal]);
  assert.equal(k.status(graceSteal), 'unknown', 'carência protege a dona');
  const noFee = k.spendRecord('padaria', alice, alice, { target: alice.shieldedData });
  k.mineN(1, [noFee]);
  assert.equal(k.status(noFee), 'unknown', 'na carência, alterar sem renovar não vale');

  // 6) depois da carência o nome fica livre: Bob registra; a dona antiga recupera o depósito
  k.mineN(rec.r.expiry + params.nameGrace - k.daa() + 2);
  const cB3 = k.commit(bob, 'padaria', Buffer.alloc(32, 0xb4));
  k.mineN(1 + params.nameCommitMin, [cB3]);
  const bobReg = k.reveal(bob, 'padaria', Buffer.alloc(32, 0xb4), cB3);
  k.mineN(1, [bobReg]);
  assert.equal(k.status(bobReg), 'accepted', 'nome livre de novo');
  assert.ok(k.record('padaria').r.owner.equals(bob.tKey(0).lock));
  const dead = c.virtual.view.nameEntries('padaria').find((x) => parseNameRecord(x.e.lock).owner.equals(alice.tKey(0).lock));
  const [dtxid, dix] = dead.key.split(':');
  const refund = buildTransaction({ params, tInputs: [{ outpoint: { txid: Buffer.from(dtxid, 'hex'), index: Number(dix) }, amount: dead.e.amount, signer: alice.tKey(0).signer }], sweep: { type: 't', lock: alice.tKey(0).lock } }).tx;
  k.mineN(1, [refund]);
  assert.equal(k.status(refund), 'accepted', 'depósito volta para a antiga dona');
  assert.ok(k.record('padaria').r.owner.equals(bob.tKey(0).lock), 'e o nome continua de Bob');
});

test('consenso: dois registros na mesma transação, dono inválido e minerador com trava de nome são recusados', () => {
  const k = Keys.random();
  const r1 = encodeNameRecord({ name: 'loja-um', expiry: 999, owner: k.tKey(0).lock, target: k.shieldedData });
  const r2 = encodeNameRecord({ name: 'loja-dois', expiry: 999, owner: k.tKey(0).lock, target: k.shieldedData });
  const base = (outs) => buildTransaction({ params, tInputs: [{ outpoint: { txid: Buffer.alloc(32, 1), index: 0 }, amount: 10n * COIN, signer: k.tKey(0).signer }], outputs: outs, change: { type: 't', lock: k.tKey(0).lock } }).tx;
  assert.throws(() => validateTxStateless(base([{ type: 't', lock: r1, amount: DEP }, { type: 't', lock: r2, amount: DEP }]), params), /um registro de nome/);
  const privOwner = encodeNameRecord({ name: 'loja-tres', expiry: 999, owner: k.shieldedData, target: k.shieldedData });
  assert.throws(() => validateTxStateless(base([{ type: 't', lock: privOwner, amount: DEP }]), params), /dono de um nome/);
  // um minerador não pode criar registros pela coinbase
  const c = new Consensus(params);
  assert.throws(() => mine(c, r1, [], new Clock()));
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

test('carteira na rede: registrar @padaria, pagar para @padaria, alterar, transferir para krq, renovar, liberar', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krv-names-'));
  const port = 19000 + Math.floor(Math.random() * 900);
  const node = new Node({ params, datadir: dir, p2pPort: port, rpcPort: port + 1, log: () => {}, persist: false });
  await node.start();
  const url = `http://127.0.0.1:${port + 1}`;
  try {
    const alice = Wallet.create(path.join(dir, 'a.json'), params, url);
    const bob = Wallet.create(path.join(dir, 'b.json'), params, url);
    const miner = Keys.random().tAddress(params);
    await mineVia(url, alice.tAddress, 30);
    await mineVia(url, bob.tAddress, 30);
    await mineVia(url, miner, 12);
    const mineN = (n = 1) => mineVia(url, miner, n);

    // registro em duas etapas
    const c1 = await nameCommit(alice, '@Padaria', { target: 'privado' });
    assert.equal(c1.name, 'padaria');
    assert.equal(c1.nameFee, COIN);
    await assert.rejects(() => nameReveal(alice, 'padaria'), /confirmado|aguarde/);
    await mineN(1);
    await assert.rejects(() => nameReveal(alice, 'padaria'), /aguarde/);
    await mineN(params.nameCommitMin);
    assert.equal(await nameRevealWait(alice, 'padaria'), 0);
    await nameReveal(alice, 'padaria');
    await mineN(1);
    let info = await alice.resolveName('@padaria');
    assert.equal(info.status, 'ativo');
    assert.equal(info.target, alice.sAddress, 'aponta para o endereço privado de Alice');
    assert.equal(info.owner, alice.tAddress);

    // Bob paga para @padaria — o pagamento vai para o endereço privado de Alice
    const pay = await bob.send({ to: '@padaria', amount: COIN });
    assert.equal(pay.name, 'padaria');
    assert.equal(pay.to, alice.sAddress);
    await mineN(1);
    await alice.sync();
    const b = alice.balance();
    assert.ok(b.shielded + b.shieldedImmature >= COIN, 'Alice recebeu no privado');

    // nome ocupado; só a dona altera
    await assert.rejects(() => nameCommit(bob, 'padaria'), /já tem dono/);
    await assert.rejects(() => nameUpdate(bob, 'padaria', 'privado'), /não pertence/);
    await nameUpdate(alice, 'padaria', 'transparente');
    await mineN(1);
    assert.equal((await alice.resolveName('padaria')).target, alice.tAddress);

    // transferência para o endereço QUÂNTICO de Bob; Bob renova assinando com Schnorr + ML-DSA
    await nameTransfer(alice, 'padaria', bob.qAddress);
    await mineN(1);
    info = await bob.resolveName('padaria');
    assert.equal(info.owner, bob.qAddress);
    const before = info.expiry;
    const rn = await nameRenew(bob, 'padaria');
    assert.equal(rn.nameFee, COIN);
    await mineN(1);
    assert.ok((await bob.resolveName('padaria')).expiry > before, 'renovado');
    assert.deepEqual((await myNames(bob)).map((x) => x.name), ['padaria']);
    assert.equal((await myNames(alice)).length, 0);
    const gi = await rpc(url, 'getinfo');
    assert.equal(gi.names, 1);

    // Bob libera o nome: o depósito volta e o nome fica livre
    await nameRelease(bob, 'padaria');
    await mineN(1);
    assert.equal((await bob.resolveName('padaria')).status, 'livre');
    await assert.rejects(() => alice.send({ to: '@padaria', amount: COIN }), /não está registrado/);
  } finally {
    await node.stop();
  }
});
