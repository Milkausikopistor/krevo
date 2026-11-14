// Troca atômica Krevo ⇄ Bitcoin, ponta a ponta: nó Krevo real (RPC) + Bitcoin simulado com a
// API do mempool.space (HTTP) + duas carteiras. Direções: vender KRV e vender BTC; e as falhas:
// participante some, iniciador some, prazo curto demais, trava de hash na Krevo.
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
import { Consensus } from '../src/consensus/consensus.js';
import { Keys } from '../src/wallet/keys.js';
import { buildTransaction } from '../src/wallet/builder.js';
import { schnorrSign } from '../src/crypto/schnorr.js';
import { encodePolicyPaths, multisigLock, encodeWitness, verifyMultisigWitness, parseWitnessPath, sha256 } from '../src/consensus/policy.js';
import { BTC_NETWORKS, p2wpkhAddress } from '../src/btc/address.js';
import { pubFromPriv } from '../src/btc/ecdsa.js';
import { SimBitcoin, startSimBitcoin } from '../src/btc/simbtc.js';
import { createOffer, acceptOffer, importAcceptance, swapStep, decodeSwapCode, checkPairing, describeSwap } from '../src/wallet/swap.js';
import { Clock, mine, matureTUtxos, tUtxos } from './helpers.js';

const params = getParams('simnet');
const net = BTC_NETWORKS.regtest;

async function mineVia(url, address, n) {
  for (let i = 0; i < n; i++) {
    const t = await rpc(url, 'getblocktemplate', { address });
    const b = Block.deserialize(fromHex(t.block));
    assert.ok(solve(b));
    const r = await rpc(url, 'submitblock', { block: toHex(b.serialize()) });
    assert.equal(r.status, 'accepted', r.reason);
  }
}

/** Ambiente: nó Krevo + Bitcoin simulado + carteiras de Alice e Bob (Alice com KRV). */
async function setup() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krv-swap-test-'));
  const port = 19000 + Math.floor(Math.random() * 900);
  const node = new Node({ params, datadir: dir, p2pPort: port, rpcPort: port + 1, log: () => {}, persist: false });
  await node.start();
  const url = `http://127.0.0.1:${port + 1}`;
  const btc = await startSimBitcoin({ port: 0, sim: new SimBitcoin({ net, spacing: 1 }) });
  const alice = Wallet.create(path.join(dir, 'alice.json'), params, url);
  const bob = Wallet.create(path.join(dir, 'bob.json'), params, url);
  const miner = Keys.random().tAddress(params);
  await mineVia(url, alice.tAddress, 30);
  await mineVia(url, miner, 12);
  const btcAddr = { alice: p2wpkhAddress(net, pubFromPriv(0xa11cen)), bob: p2wpkhAddress(net, pubFromPriv(0xb0bn)) };
  return {
    url, btc, sim: btc.sim, alice, bob, btcAddr, mineKrv: (n = 1) => mineVia(url, miner, n),
    close: async () => { await btc.close(); await node.stop(); },
  };
}

async function krvBalance(w) { await w.sync(); const b = w.balance(); return b.transparent + b.transparentImmature + b.transparentPending; }

test('trava de hash na Krevo (consenso): segredo certo resgata; errado, ausente ou de outro tamanho não', () => {
  const c = new Consensus(params);
  const clock = new Clock();
  const alice = Keys.random(), bob = Keys.random();
  for (let i = 0; i < 30; i++) mine(c, alice.tKey(0).lock, [], clock);
  const secret = Buffer.alloc(32, 9), hash = sha256(secret);
  const policy = encodePolicyPaths([{ m: 1, keys: [bob.tKey(0).P], delay: 0, hash }, { m: 1, keys: [alice.tKey(0).P], delay: 50 }]);
  const lock = multisigLock(policy);
  assert.equal(parseWitnessPath(Buffer.concat([policy, Buffer.from([0]), secret, Buffer.from([1])])).secret.toString('hex'), secret.toString('hex'));
  const fund = buildTransaction({ params, tInputs: matureTUtxos(c, alice).slice(0, 6), outputs: [{ type: 't', lock, amount: 2n * COIN }], change: { type: 't', lock: alice.tKey(0).lock } });
  mine(c, alice.tKey(0).lock, [fund.tx], clock);
  const coin = { outpoint: { txid: fund.tx.id, index: 0 }, amount: 2n * COIN, policy };
  const spend = (path, key, to, sec) => {
    const { tx } = buildTransaction({ params, tInputs: [{ ...coin, path }], sweep: { type: 't', lock: to } });
    tx.tIn[0].sig = encodeWitness(policy, new Map([[0, key.signer.sign(tx.sighash())]]), path, sec);
    tx.invalidate();
    return tx;
  };
  // segredo errado não monta nem passa na regra
  assert.throws(() => spend(0, bob.tKey(0), bob.tKey(0).lock, Buffer.alloc(32, 1)), /segredo/);
  const forged = spend(0, bob.tKey(0), bob.tKey(0).lock, secret);
  forged.tIn[0].sig = Buffer.from(forged.tIn[0].sig);
  forged.tIn[0].sig.fill(1, forged.tIn[0].sig.length - 98, forged.tIn[0].sig.length - 66); // troca o segredo
  assert.equal(verifyMultisigWitness(lock, forged.tIn[0].sig, forged.sighash()), false);
  mine(c, alice.tKey(0).lock, [forged], clock);
  assert.equal(c.txStatus(forged.idHex).status, 'unknown');
  // reembolso antes do prazo: ignorado
  const early = spend(1, alice.tKey(0), alice.tKey(0).lock);
  mine(c, alice.tKey(0).lock, [early], clock);
  assert.equal(c.txStatus(early.idHex).status, 'unknown');
  // Alice não pode usar o caminho de resgate (é a chave de Bob)
  const steal = spend(0, alice.tKey(0), alice.tKey(0).lock, secret);
  mine(c, alice.tKey(0).lock, [steal], clock);
  assert.equal(c.txStatus(steal.idHex).status, 'unknown');
  // Bob com o segredo: aceito, e o segredo fica público na testemunha
  const ok = spend(0, bob.tKey(0), bob.tKey(0).lock, secret);
  mine(c, alice.tKey(0).lock, [ok], clock);
  assert.equal(c.txStatus(ok.idHex).status, 'accepted');
  assert.ok(parseWitnessPath(ok.tIn[0].sig).secret.equals(secret));
  assert.ok(tUtxos(c, bob)[0].amount > 2n * COIN - 100_000n);
});

test('códigos krx e regras de rede', () => {
  assert.throws(() => checkPairing(params, 'mainnet'), /bitcoins de verdade/);
  assert.throws(() => checkPairing(getParams('mainnet'), 'testnet'), /mainnet/);
  checkPairing(params, 'regtest');
  const w = Wallet.create(path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'krv-swap-codes-')), 'w.json'), params, 'http://127.0.0.1:1');
  const { code } = createOffer(w, { sell: 'krv', krv: COIN, btc: 50_000n, btcPayout: p2wpkhAddress(net, pubFromPriv(5n)), iWindow: 7200, pWindow: 3600 });
  assert.match(code, /^krxsim1/);
  const d = decodeSwapCode(params, code);
  assert.equal(d.kind, 'offer');
  assert.equal(d.offer.krv, COIN);
  assert.throws(() => decodeSwapCode(getParams('devnet'), code), /outra rede/);
  assert.throws(() => createOffer(w, { sell: 'krv', krv: COIN, btc: 50_000n, btcPayout: 'bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4' }), /outra rede/);
  assert.throws(() => createOffer(w, { sell: 'krv', krv: COIN, btc: 50_000n, btcPayout: p2wpkhAddress(net, pubFromPriv(5n)), iWindow: 3600, pWindow: 3600 }), /1,5×/);
});

test('troca: Alice VENDE KRV, Bob paga em BTC — ponta a ponta', async () => {
  const e = await setup();
  try {
    const { alice, bob, sim } = e;
    const KRV = 3n * COIN, SATS = 150_000n;
    const offer = createOffer(alice, { sell: 'krv', krv: KRV, btc: SATS, btcNet: 'regtest', btcPayout: e.btcAddr.alice, btcApi: e.btc.url, iWindow: 600, pWindow: 300 });
    const acc = acceptOffer(bob, offer.code, { btcPayout: e.btcAddr.bob, btcApi: e.btc.url });
    assert.equal(describeSwap(bob, bob.data.swaps[acc.id]).give, '0,0015 BTC');
    assert.equal((await swapStep(alice, offer.id)).action, 'wait-accept');
    importAcceptance(alice, acc.code);
    assert.throws(() => importAcceptance(bob, acc.code), /não corresponde/);

    // Bob ainda não trava: o iniciador precisa travar primeiro
    assert.equal((await swapStep(bob, acc.id)).action, 'wait-their-lock');
    const aliceBefore = await krvBalance(alice);
    const s1 = await swapStep(alice, offer.id);
    assert.equal(s1.action, 'lock', s1.message);
    await e.mineKrv(1);
    assert.equal((await swapStep(alice, offer.id)).action, 'wait-their-lock');

    // Bob vê o contrato da Alice na Krevo e recebe as instruções de pagamento em BTC
    const s2 = await swapStep(bob, acc.id);
    assert.equal(s2.action, 'pay-btc', s2.message);
    assert.match(s2.uri, /^bitcoin:bcrt1q.*\?amount=0\.0015$/);
    sim.fund(s2.address, SATS);                    // Bob paga pela carteira Bitcoin dele
    assert.equal((await swapStep(bob, acc.id)).action, 'pay-btc', 'visto, mas sem confirmação');
    assert.equal((await swapStep(alice, offer.id)).action, 'wait-their-lock', 'Alice espera confirmação');
    sim.mine(1, 5);
    assert.equal((await swapStep(bob, acc.id)).action, 'wait-secret');

    // Alice resgata os BTC — e revela o segredo
    const s3 = await swapStep(alice, offer.id);
    assert.equal(s3.action, 'claim', s3.message);
    sim.mine(1, 5);
    assert.ok(sim.balance(e.btcAddr.alice) > SATS - 2_000n, 'Alice recebeu os BTC');

    // Bob lê o segredo no Bitcoin e resgata os KRV
    const s4 = await swapStep(bob, acc.id);
    assert.equal(s4.action, 'claim', s4.message);
    await e.mineKrv(1);
    assert.equal((await swapStep(bob, acc.id)).action, 'done');
    assert.equal((await swapStep(alice, offer.id)).action, 'done');
    const bobKrv = await krvBalance(bob);
    assert.ok(bobKrv > KRV - 100_000n && bobKrv < KRV, `Bob recebeu ${bobKrv} grãos`);
    const spent = aliceBefore - (await krvBalance(alice));
    assert.ok(spent >= KRV && spent < KRV + 100_000n, 'Alice gastou só os KRV + taxa');
    assert.equal(alice.data.swaps[offer.id].status, 'concluída');
  } finally { await e.close(); }
});

test('troca: Alice VENDE BTC, Bob paga em KRV — o segredo aparece na Krevo', async () => {
  const e = await setup();
  try {
    const { alice, bob, sim } = e;
    // aqui quem tem KRV é Bob: Alice manda KRV para ele antes (só para montar o cenário)
    const pre = await alice.send({ to: bob.tAddress, amount: 5n * COIN });
    await e.mineKrv(1);
    await bob.waitAccepted(pre.txid);
    const KRV = 2n * COIN, SATS = 80_000n;
    const offer = createOffer(alice, { sell: 'btc', krv: KRV, btc: SATS, btcNet: 'regtest', btcPayout: e.btcAddr.alice, btcApi: e.btc.url, iWindow: 600, pWindow: 300 });
    const acc = acceptOffer(bob, offer.code, { btcPayout: e.btcAddr.bob, btcApi: e.btc.url });
    importAcceptance(alice, acc.code);

    const s1 = await swapStep(alice, offer.id);
    assert.equal(s1.action, 'pay-btc');
    sim.fund(s1.address, SATS);
    sim.mine(1, 5);
    const s2 = await swapStep(bob, acc.id);
    assert.equal(s2.action, 'lock', s2.message);   // Bob trava os KRV
    await e.mineKrv(1);
    const s3 = await swapStep(alice, offer.id);
    assert.equal(s3.action, 'claim', s3.message);  // Alice resgata os KRV (segredo vai para a Krevo)
    await e.mineKrv(1);
    const s4 = await swapStep(bob, acc.id);
    assert.equal(s4.action, 'claim', s4.message);  // Bob usa o segredo para os BTC
    sim.mine(1, 5);
    assert.ok(sim.balance(e.btcAddr.bob) > SATS - 2_000n, 'Bob recebeu os BTC');
    assert.equal((await swapStep(bob, acc.id)).action, 'done');
    assert.equal((await swapStep(alice, offer.id)).action, 'done');
  } finally { await e.close(); }
});

test('troca: participante some → iniciador é reembolsado; prazo curto → participante não trava', async () => {
  const e = await setup();
  try {
    const { alice, bob } = e;
    const offer = createOffer(alice, { sell: 'krv', krv: COIN, btc: 50_000n, btcNet: 'regtest', btcPayout: e.btcAddr.alice, btcApi: e.btc.url, iWindow: 20, pWindow: 10 });
    const acc = acceptOffer(bob, offer.code, { btcPayout: e.btcAddr.bob, btcApi: e.btc.url });
    importAcceptance(alice, acc.code);
    const before = await krvBalance(alice);
    assert.equal((await swapStep(alice, offer.id)).action, 'lock');
    await e.mineKrv(1);
    // 15 dos 20 segundos (150 blocos) passam antes de Bob olhar: tarde demais para ele travar
    await e.mineKrv(150);
    const late = await swapStep(bob, acc.id);
    assert.equal(late.action, 'abort', late.message);
    assert.equal(late.done, true);
    assert.equal((await swapStep(alice, offer.id)).action, 'wait-their-lock');
    await e.mineKrv(60);
    const r = await swapStep(alice, offer.id);
    assert.equal(r.action, 'refund', r.message);
    await e.mineKrv(1);
    assert.equal((await swapStep(alice, offer.id)).action, 'done');
    assert.equal(alice.data.swaps[offer.id].status, 'reembolsada');
    const lost = before - (await krvBalance(alice));
    assert.ok(lost > 0n && lost < 100_000n, `Alice só perdeu taxas: ${lost} grãos`);
  } finally { await e.close(); }
});

test('troca: iniciador some depois que os dois travaram → cada um recupera o seu; segredo nunca é revelado tarde', async () => {
  const e = await setup();
  try {
    const { alice, bob, sim } = e;
    const offer = createOffer(alice, { sell: 'krv', krv: COIN, btc: 60_000n, btcNet: 'regtest', btcPayout: e.btcAddr.alice, btcApi: e.btc.url, iWindow: 40, pWindow: 20 });
    const acc = acceptOffer(bob, offer.code, { btcPayout: e.btcAddr.bob, btcApi: e.btc.url });
    importAcceptance(alice, acc.code);
    assert.equal((await swapStep(alice, offer.id)).action, 'lock');
    await e.mineKrv(1);
    const p = await swapStep(bob, acc.id);
    assert.equal(p.action, 'pay-btc');
    sim.fund(p.address, 60_000n);
    sim.mine(1, 1);
    assert.equal((await swapStep(bob, acc.id)).action, 'wait-secret');
    // Alice "some". O tempo do Bitcoin passa do prazo de Bob (20 s).
    sim.mine(8, 30);
    assert.ok(sim.mtp() > Number(p.myContract.locktime));
    // se Alice voltar agora, ela NÃO revela o segredo (Bob poderia ficar sem tempo)
    const a = await swapStep(alice, offer.id);
    assert.equal(a.action, 'wait-refund', a.message);
    // Bob pega os BTC de volta
    const r = await swapStep(bob, acc.id);
    assert.equal(r.action, 'refund', r.message);
    sim.mine(1, 1);
    assert.ok(sim.balance(e.btcAddr.bob) > 60_000n - 2_000n);
    assert.equal((await swapStep(bob, acc.id)).action, 'done');
    // Alice recupera os KRV depois do prazo dela (40 s = 400 blocos)
    await e.mineKrv(400);
    assert.equal((await swapStep(alice, offer.id)).action, 'refund');
    await e.mineKrv(1);
    assert.equal((await swapStep(alice, offer.id)).action, 'done');
  } finally { await e.close(); }
});
