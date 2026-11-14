// Proteção quântica: endereço híbrido krq (Schnorr + ML-DSA-44) e catraca do pool privado.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { getParams, COIN } from '../src/params.js';
import { Consensus } from '../src/consensus/consensus.js';
import { Mempool } from '../src/node/mempool.js';
import { Node } from '../src/node/node.js';
import { Wallet } from '../src/wallet/wallet.js';
import { rpc } from '../src/node/rpcclient.js';
import { Block } from '../src/consensus/block.js';
import { solve } from '../src/node/solver.js';
import { Keys } from '../src/wallet/keys.js';
import { buildTransaction } from '../src/wallet/builder.js';
import { schnorrSign } from '../src/crypto/schnorr.js';
import { mldsaKeyFromSeed, mldsaSign, mldsaVerify, MLDSA_PUB_SIZE, MLDSA_SIG_SIZE } from '../src/crypto/pq.js';
import { verifyPqWitness, encodePqWitness, isPqWitness, PQ_WITNESS_SIZE } from '../src/consensus/pqlock.js';
import { shieldedDelta } from '../src/consensus/txvalidation.js';
import { computeMass } from '../src/consensus/mass.js';
import { decodeAddress } from '../src/address.js';
import { parseOutpointKey, Transaction } from '../src/consensus/tx.js';
import { toHex, fromHex } from '../src/util/bytes.js';
import { Clock, mine, matureTUtxos, tUtxos, scanShielded, makeRing } from './helpers.js';

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

/** Moedas maduras de um endereço quântico, prontas para o construtor. */
function qUtxos(c, keys) {
  const k = keys.qKey(0), daa = c.virtual.gd.daaScore;
  return c.utxosByLock(toHex(k.lock))
    .filter((u) => !u.coinbase || daa - u.daa >= c.params.coinbaseMaturity)
    .map((u) => ({ outpoint: parseOutpointKey(u.key), amount: u.amount, signer: k.signer, pq: k }));
}

test('ML-DSA-44: chaves determinísticas pela semente, assinatura e adulteração', () => {
  const seed = randomBytes(32);
  const a = mldsaKeyFromSeed(seed), b = mldsaKeyFromSeed(Buffer.from(seed));
  assert.equal(a.pub.length, MLDSA_PUB_SIZE);
  assert.ok(a.pub.equals(b.pub), 'mesma semente → mesma chave (recuperável pela frase)');
  assert.ok(!mldsaKeyFromSeed(randomBytes(32)).pub.equals(a.pub));
  const msg = Buffer.from('transação');
  const sig = mldsaSign(a.priv, msg);
  assert.equal(sig.length, MLDSA_SIG_SIZE);
  assert.ok(mldsaVerify(a.pub, msg, sig));
  assert.equal(mldsaVerify(a.pub, Buffer.from('outra'), sig), false, 'outra mensagem');
  const bad = Buffer.from(sig); bad[100] ^= 1;
  assert.equal(mldsaVerify(a.pub, msg, bad), false, 'assinatura adulterada');
  assert.equal(mldsaVerify(mldsaKeyFromSeed(randomBytes(32)).pub, msg, sig), false, 'chave de outra pessoa');
  assert.equal(mldsaVerify(a.pub, msg, sig.subarray(1)), false, 'tamanho errado');

  // a carteira deriva o endereço krq da semente: restaurar dá o mesmo endereço
  const s = randomBytes(32);
  const k1 = new Keys(s), k2 = new Keys(Buffer.from(s));
  assert.match(k1.qAddress(params), /^krqsim1/);
  assert.equal(k1.qAddress(params), k2.qAddress(params));
  assert.equal(decodeAddress(params, k1.qAddress(params)).type, 'q');
  assert.throws(() => decodeAddress(getParams('devnet'), k1.qAddress(params)), /outra rede/);
  assert.notEqual(k1.qAddress(params), Keys.random().qAddress(params));
});

test('testemunha híbrida: precisa das DUAS assinaturas e das chaves certas', () => {
  const me = new Keys(randomBytes(32)).qKey(0), other = Keys.random().qKey(0);
  const msg = Buffer.from('corpo da transação');
  const w = (k, sSig, qSig) => encodePqWitness(k.sPub, k.mldsa.pub, sSig, qSig);
  const good = w(me, me.signer.sign(msg), me.mldsa.sign(msg));
  assert.equal(good.length, PQ_WITNESS_SIZE);
  assert.ok(isPqWitness(good));
  assert.ok(verifyPqWitness(me.lock, good, msg), 'válida');
  assert.equal(verifyPqWitness(me.lock, good, Buffer.from('outra transação')), false, 'replay em outra transação');

  // "quebrou a curva elíptica": tem a chave Schnorr, mas não a ML-DSA
  const forgedQ = w(me, me.signer.sign(msg), other.mldsa.sign(msg));
  assert.equal(verifyPqWitness(me.lock, forgedQ, msg), false, 'ML-DSA errada');
  // "quebrou o reticulado": tem a ML-DSA, mas não a Schnorr
  const forgedS = w(me, other.signer.sign(msg), me.mldsa.sign(msg));
  assert.equal(verifyPqWitness(me.lock, forgedS, msg), false, 'Schnorr errada');
  // trocar a chave ML-DSA por uma própria não bate com o hash do endereço
  const swapped = encodePqWitness(me.sPub, other.mldsa.pub, me.signer.sign(msg), other.mldsa.sign(msg));
  assert.equal(verifyPqWitness(me.lock, swapped, msg), false, 'chave trocada');
  // testemunha válida de outra pessoa
  const theirs = w(other, other.signer.sign(msg), other.mldsa.sign(msg));
  assert.equal(verifyPqWitness(me.lock, theirs, msg), false, 'endereço de outra pessoa');
  assert.equal(verifyPqWitness(me.lock, good.subarray(0, -1), msg), false, 'truncada');
  assert.equal(verifyPqWitness(me.lock, me.signer.sign(msg), msg), false, 'só Schnorr não basta');
});

test('krq na rede: minerar, receber, gastar; ataque com só uma das chaves falha', () => {
  const c = new Consensus(params);
  const clock = new Clock();
  const alice = Keys.random(), bob = Keys.random(), carol = Keys.random(), eve = Keys.random();
  // recompensa de mineração direto no endereço quântico
  for (let i = 0; i < 14; i++) mine(c, bob.qKey(0).lock, [], clock);
  for (let i = 0; i < 16; i++) mine(c, alice.tKey(0).lock, [], clock);
  const bobCoins = qUtxos(c, bob);
  assert.ok(bobCoins.length >= 3, 'recompensas maduras no krq');

  // Alice (clássica) paga o krq de Bob
  const fund = buildTransaction({ params, tInputs: matureTUtxos(c, alice).slice(0, 4), outputs: [{ type: 't', lock: bob.qKey(0).lock, amount: 2n * COIN }], change: { type: 't', lock: alice.tKey(0).lock } });
  mine(c, alice.tKey(0).lock, [fund.tx], clock);
  assert.equal(c.txStatus(fund.tx.idHex).status, 'accepted');

  // Bob gasta do krq (assinatura híbrida), troco volta ao krq
  const spend = buildTransaction({ params, tInputs: bobCoins.slice(0, 2), outputs: [{ type: 't', lock: carol.tKey(0).lock, amount: COIN }], change: { type: 't', lock: bob.qKey(0).lock } });
  assert.ok(spend.tx.tIn.every((i) => i.sig.length === PQ_WITNESS_SIZE));
  assert.equal(spend.tx.mass, Math.max(computeMass(spend.tx, params), spend.tx.mass), 'massa declarada cobre a computação');
  assert.ok(spend.fee < 50_000n, `taxa ainda insignificante: ${spend.fee} grãos`);
  mine(c, alice.tKey(0).lock, [spend.tx], clock);
  assert.equal(c.txStatus(spend.tx.idHex).status, 'accepted');
  assert.equal(tUtxos(c, carol)[0].amount, COIN);

  // Eve "quebrou" a curva elíptica: conhece a chave Schnorr de Bob, mas não a ML-DSA.
  const coin = qUtxos(c, bob).find((u) => u.amount === 2n * COIN);
  const k = bob.qKey(0);
  const evePq = { ...k, mldsa: { pub: k.mldsa.pub, sign: eve.qKey(0).mldsa.sign } };
  const theft = buildTransaction({ params, tInputs: [{ ...coin, pq: evePq }], outputs: [{ type: 't', lock: eve.tKey(0).lock, amount: COIN }], change: { type: 't', lock: eve.tKey(0).lock } });
  mine(c, alice.tKey(0).lock, [theft.tx], clock);
  assert.equal(c.txStatus(theft.tx.idHex).status, 'unknown', 'roubo com só Schnorr é ignorado');
  // …e usar a própria chave ML-DSA não bate com o hash do endereço
  const theft2 = buildTransaction({ params, tInputs: [{ ...coin, pq: { ...k, mldsa: eve.qKey(0).mldsa } }], outputs: [{ type: 't', lock: eve.tKey(0).lock, amount: COIN }] });
  mine(c, alice.tKey(0).lock, [theft2.tx], clock);
  assert.equal(c.txStatus(theft2.tx.idHex).status, 'unknown');
  // Schnorr simples também não abre um krq
  const plain = buildTransaction({ params, tInputs: [{ outpoint: coin.outpoint, amount: coin.amount, signer: k.signer }], outputs: [{ type: 't', lock: eve.tKey(0).lock, amount: COIN }] });
  mine(c, alice.tKey(0).lock, [plain.tx], clock);
  assert.equal(c.txStatus(plain.tx.idHex).status, 'unknown');
  assert.equal(tUtxos(c, eve).length, 0);
  assert.ok(qUtxos(c, bob).some((u) => u.amount === 2n * COIN), 'moeda de Bob intacta');
});

test('catraca do pool privado: contabilidade pública e bloqueio de saída de moedas forjadas', () => {
  // delta = entradas transparentes − saídas transparentes − taxa (só em transações com parte privada)
  const plainTx = { sIn: [], sOut: [], tOut: [{ amount: 5n }], fee: 1n };
  assert.equal(shieldedDelta(plainTx, 6n), 0n);
  assert.equal(shieldedDelta({ sIn: [], sOut: [{}], tOut: [], fee: 2n }, 100n), 98n, 'blindar');
  assert.equal(shieldedDelta({ sIn: [{}], sOut: [{}], tOut: [{ amount: 40n }], fee: 2n }, 0n), -42n, 'desblindar');

  const c = new Consensus(params);
  const clock = new Clock();
  const alice = Keys.random(), bob = Keys.random(), carol = Keys.random();
  const Q = COIN / 4n;
  const sumS = () => scanShielded(c, bob).reduce((a, u) => a + u.amount, 0n);
  assert.equal(c.supplyInfo().shieldedSupply, 0n);
  for (let i = 0; i < 14; i++) mine(c, bob.shieldedData, [], clock);
  for (let i = 0; i < 4; i++) mine(c, alice.tKey(0).lock, [], clock);
  // todo KRV privado existente é de Bob: a catraca (pública) tem que bater com o saldo dele
  assert.ok(sumS() > 0n);
  assert.equal(c.supplyInfo().shieldedSupply, sumS(), 'recompensas privadas entram na catraca');

  // Bob tira 0,25 KRV do pool para um endereço transparente (troco continua privado)
  const coin = scanShielded(c, bob).find((o) => c.virtual.gd.daaScore - o.daa >= params.coinbaseMaturity);
  const unshield = () => buildTransaction({ params, sInputs: [{ ...coin, ring: makeRing(c, coin) }], outputs: [{ type: 't', lock: carol.tKey(0).lock, amount: Q }], change: { type: 's', A: bob.A, B: bob.B } }).tx;
  const ok = unshield();
  const before = c.supplyInfo().shieldedSupply;
  mine(c, alice.tKey(0).lock, [ok], clock);
  assert.equal(c.txStatus(ok.idHex).status, 'accepted');
  assert.equal(c.supplyInfo().shieldedSupply, before - Q - ok.fee, 'desblindar reduz a catraca');
  assert.equal(c.supplyInfo().shieldedSupply, sumS());
  // (num DAG, as transações de um bloco são aceitas pelo filho: mais um bloco fixa o desblindamento)
  mine(c, alice.tKey(0).lock, [], clock);

  // Simulação: alguém forjou moedas DENTRO do pool (bug ou computador quântico). Para a
  // rede, isso aparece como tentar tirar do pool mais do que entrou. Fingimos que o
  // registro público diz que o pool está quase vazio e tentamos desblindar 1 KRV.
  const tip = c.virtual.gd.selectedParent;
  const acc = c.acc.get(tip);
  acc.shielded = Q / 2n; acc.cbShielded = 0n;
  c.virtual.acceptance.shielded = Q / 2n; // o nó reaproveita a aceitação do virtual (cache)
  const coin2 = scanShielded(c, bob).find((o) => o !== coin && c.virtual.gd.daaScore - o.daa >= params.coinbaseMaturity && o.amount > Q);
  const forged = buildTransaction({ params, sInputs: [{ ...coin2, ring: makeRing(c, coin2) }], outputs: [{ type: 't', lock: carol.tKey(0).lock, amount: Q }], change: { type: 's', A: bob.A, B: bob.B } }).tx;
  mine(c, alice.tKey(0).lock, [forged], clock, [tip]);
  assert.equal(c.txStatus(forged.idHex).status, 'unknown', 'catraca barra a saída: as moedas forjadas ficam presas no pool');
  assert.equal(tUtxos(c, carol).reduce((a, u) => a + u.amount, 0n), Q, 'Carol só tem os 0,25 KRV legítimos');
  assert.ok(c.supplyInfo().shieldedSupply >= 0n);
  // o mempool recusa logo na entrada
  const mp = new Mempool(c);
  const r = mp.add(forged);
  assert.equal(r.ok, false);
  assert.match(r.reason, /catraca/);
  // movimentos DENTRO do pool continuam funcionando (privado → privado não mexe na catraca)
  const inside = buildTransaction({ params, sInputs: [{ ...coin2, ring: makeRing(c, coin2) }], outputs: [{ type: 's', A: carol.A, B: carol.B, amount: Q / 10n }], change: { type: 's', A: bob.A, B: bob.B } });
  assert.ok(shieldedDelta(inside.tx, 0n) < 0n && -shieldedDelta(inside.tx, 0n) === inside.fee, 'só a taxa sai do pool');
});

test('carteira na rede: status, migração krv → krq, envio a partir do krq e restauração pela frase', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krv-quantum-test-'));
  const port = 19000 + Math.floor(Math.random() * 900);
  const node = new Node({ params, datadir: dir, p2pPort: port, rpcPort: port + 1, log: () => {}, persist: false });
  await node.start();
  const url = `http://127.0.0.1:${port + 1}`;
  try {
    const alice = Wallet.create(path.join(dir, 'a.json'), params, url);
    const bob = Wallet.create(path.join(dir, 'b.json'), params, url);
    assert.match(alice.qAddress, /^krqsim1/);
    await mineVia(url, alice.tAddress, 6);
    await mineVia(url, bob.sAddress, 6);
    await mineVia(url, bob.tAddress, 12);

    let st = await alice.quantumStatus();
    assert.equal(st.enabled, false);
    assert.ok(st.classic > 0n);
    assert.equal(st.quantum, 0n);

    // migração: liga o modo quântico e move tudo que é clássico e maduro para krq
    const before = st.classic;
    const m = await alice.migrateQuantum();
    assert.ok(m.txs.length >= 1);
    await mineVia(url, bob.tAddress, 1);
    st = await alice.quantumStatus();
    assert.equal(st.enabled, true);
    assert.equal(st.classic, 0n, 'nada sobrou no endereço clássico');
    assert.equal(st.quantum, before - m.txs.reduce((a, t) => a + t.fee, 0n), 'só a taxa foi gasta');
    assert.ok(m.txs.every((t) => t.fee < 100_000n), 'migração custa frações de centavo');

    // gastar do krq: a carteira assina com Schnorr + ML-DSA, troco volta para o krq
    const r = await alice.send({ to: bob.tAddress, amount: COIN / 10n });
    assert.equal(r.from, 'transparente');
    await mineVia(url, bob.tAddress, 1);
    assert.equal((await rpc(url, 'gettransactionstatus', { txid: r.txid })).status, 'accepted');
    const tx = Transaction.deserialize(fromHex((await rpc(url, 'gettransaction', { txid: r.txid })).tx));
    assert.ok(tx.tIn.every((i) => i.sig.length === PQ_WITNESS_SIZE), 'testemunha híbrida na rede');
    st = await alice.quantumStatus();
    assert.equal(st.classic, 0n, 'troco foi para o krq');
    assert.ok(st.quantum > 0n);

    // o explorador / getinfo mostram a catraca do pool privado
    const info = await rpc(url, 'getinfo');
    assert.ok(BigInt(info.shieldedSupply) > 0n);

    // mesma frase → mesmo endereço quântico e mesmo saldo (as chaves ML-DSA vêm da semente)
    const restored = Wallet.restore(path.join(dir, 'r.json'), params, url, { mnemonic: alice.mnemonic });
    assert.equal(restored.qAddress, alice.qAddress);
    assert.equal((await restored.quantumStatus()).quantum, st.quantum);
  } finally {
    await node.stop();
  }
});
