// Anonimato do tamanho da rede inteira: provas de pertencimento à árvore de TODAS as saídas
// privadas (FCMP, árvore de curvas sobre o ciclo secp256k1/secq256k1).
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
import { Keys } from '../src/wallet/keys.js';
import { mulG, randomScalar } from '../src/crypto/secp256k1.js';
import { commit } from '../src/crypto/pedersen.js';
import { keyImage } from '../src/crypto/clsag.js';
import { E1, E2, P as PRIME_P } from '../src/fcmp/curve.js';
import { CurveTree } from '../src/fcmp/tree.js';
import { fcmpProve, fcmpVerify, fcmpProofSize, fcmpFinish } from '../src/fcmp/fcmp.js';
import { fcmpPrepareMany, nativeProver } from '../src/fcmp/parallel.js';
import * as parallel from '../src/fcmp/parallel.js';
import { ConstraintSystem } from '../src/fcmp/circuit.js';
import { bpProve, bpVerifyInto, BpBatch, Transcript, bpGens } from '../src/fcmp/bp.js';
import { validateTxStateless, validateTxInContext } from '../src/consensus/txvalidation.js';
import { UtxoView } from '../src/consensus/utxo.js';
import { startLightServer } from '../src/light/server.js';
import { LightWallet } from '../src/light/wallet.js';

const params = getParams('simnet');

test('fcmp: Bulletproofs de circuito com compromissos vetoriais — provador desonesto não convence', () => {
  for (const curve of [E1, E2]) {
    const gens = bpGens(curve, 8);
    // circuito: o compromisso abre (a, b, c) nas posições 0..2 e prova a·b = c
    const build = (vals, point) => {
      const cs = new ConstraintSystem(curve.S.m, !!vals);
      cs.addVC(point, vals ? new Map(vals.map((v, i) => [i, v])) : null, vals ? 7n : 0n);
      const g = cs.mul(cs.vc(0, 0), cs.vc(0, 1));
      cs.constrain(g.o.sub(cs.vc(0, 2)));
      cs.n = 4;
      return cs;
    };
    const commitTo = (vals) => curve.msm([...vals, 7n], [...gens.G.slice(0, 3), gens.h]);
    const verify = (C, pr) => { const b = new BpBatch(curve); bpVerifyInto(b, build(null, C), pr, new Transcript('t')); return b.check(); };
    const good = [3n, 5n, 15n], Cg = commitTo(good);
    assert.ok(verify(Cg, bpProve(curve, build(good, Cg), new Transcript('t'))), curve.name + ': honesto passa');
    const lie = [3n, 5n, 16n], Cl = commitTo(lie);
    assert.ok(!verify(Cl, bpProve(curve, build(lie, Cl), new Transcript('t'), { unsafeSkipChecks: true })), curve.name + ': 3·5 ≠ 16 não passa');
    // abrir o compromisso com valores diferentes dos comprometidos também não passa
    assert.ok(!verify(Cl, bpProve(curve, build(good, Cl), new Transcript('t'), { unsafeSkipChecks: true })), curve.name + ': abertura falsa não passa');
  }
});

test('fcmp: ciclo de curvas, prova contra a árvore inteira e recusas', () => {
  // secq256k1 tem exatamente p pontos: o campo de uma curva é a ordem da outra
  assert.ok(E2.gen('teste').mul(PRIME_P).isInf());
  assert.ok(E1.gen('teste').mul(E1.order).isInf());

  const branch = 4, outs = [];
  for (let i = 0; i < 21; i++) { const p = randomScalar(), x = randomScalar(), v = BigInt(1000 + i); outs.push({ p, x, v, P: mulG(p), C: commit(v, x) }); }
  const tree = new CurveTree(branch, (i) => ({ key: 'o' + i, P: outs[i].P.toBytes(), C: outs[i].C.toBytes() }));
  const N = 21, i = 6, o = outs[i];
  const root = tree.root(N);
  assert.equal(root.depth, 3, '21 folhas com 4 filhos por nó → profundidade 3');
  const pm = randomScalar(), msg = Buffer.from('sighash');
  const { proof, keyImage: KI, pseudo } = fcmpProve({ branch, N, path: tree.pathForChunk(N, Math.floor(i / branch)), leafPos: i % branch,
    P: o.P, C: o.C, p: o.p, x: o.x, v: o.v, pseudoMask: pm, msg });
  assert.equal(proof.length, fcmpProofSize(N, branch));
  const ok = (over = {}) => fcmpVerify({ branch, N, root, proof, keyImage: KI, pseudo, msg, ...over });
  assert.ok(ok(), 'prova válida');
  assert.ok(KI.equals(keyImage(o.p, o.P)), 'a imagem de chave é a mesma dos anéis: não há gasto duplo entre os dois tipos');
  assert.ok(!ok({ msg: Buffer.from('outra tx') }), 'presa à transação');
  assert.ok(!ok({ keyImage: mulG(randomScalar()) }), 'imagem de chave inventada');
  assert.ok(!ok({ pseudo: commit(o.v + 1n, pm) }), 'valor diferente');
  assert.ok(!ok({ root: tree.root(20) }), 'outra árvore');
  const bad = Buffer.from(proof); bad[400] ^= 1;
  assert.ok(!ok({ proof: bad }), 'prova adulterada');
  // a saída precisa estar NA árvore: com a árvore de 6 saídas, a de índice 6 não está
  assert.throws(() => fcmpProve({ branch, N: 6, path: tree.pathForChunk(6, 1), leafPos: 2, P: o.P, C: o.C, p: o.p, x: o.x, v: o.v, pseudoMask: pm, msg }));
});

const nativeBin = await nativeProver();
test('fcmp: provador nativo em Rust (krevod provar) — o verificador JavaScript aceita as provas', { skip: !nativeBin && 'krevod não compilado (cd rust/krevod && cargo build --release, ou KREVO_PROVER=…)' }, async () => {
  const branch = 4, outs = [];
  for (let i = 0; i < 21; i++) { const p = randomScalar(), x = randomScalar(), v = BigInt(500 + i); outs.push({ p, x, v, P: mulG(p), C: commit(v, x) }); }
  const tree = new CurveTree(branch, (i) => ({ key: 'n' + i, P: outs[i].P.toBytes(), C: outs[i].C.toBytes() }));
  const cases = [[21, 6], [16, 13], [3, 2]];
  const args = cases.map(([N, i]) => ({ branch, N, path: tree.pathForChunk(N, Math.floor(i / branch)), leafPos: i % branch, P: outs[i].P, C: outs[i].C }));
  const t = Date.now();
  const pres = await fcmpPrepareMany(args);
  const ms = Date.now() - t;
  assert.equal(parallel.lastProver, 'nativo');
  cases.forEach(([N, i], k) => {
    const o = outs[i], msg = Buffer.from('nativo ' + N), pm = randomScalar();
    const { proof, keyImage: KI, pseudo } = fcmpFinish(pres[k], { p: o.p, x: o.x, v: o.v, pseudoMask: pm, msg });
    const root = tree.root(N);
    assert.ok(fcmpVerify({ branch, N, root, proof, keyImage: KI, pseudo, msg }), `prova nativa aceita pelo verificador JS (N=${N})`);
    assert.ok(KI.equals(keyImage(o.p, o.P)));
    const bad = Buffer.from(proof); bad[500] ^= 1;
    assert.ok(!fcmpVerify({ branch, N, root, proof: bad, keyImage: KI, pseudo, msg }));
  });
  console.log(`    provador nativo: 3 entradas (profundidades 3, 2 e 1) em ${ms} ms`);
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

test('fcmp: pagamento privado provado contra todas as saídas da rede (nó, carteira e carteira leve)', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krv-fcmp-'));
  const port = 19000 + Math.floor(Math.random() * 900);
  const node = new Node({ params, datadir: dir, p2pPort: port, rpcPort: port + 1, log: () => {}, persist: false });
  await node.start();
  const url = `http://127.0.0.1:${port + 1}`;
  const light = await startLightServer({ params, rpcUrl: url, port: 0 });
  try {
    const alice = Wallet.create(path.join(dir, 'alice.json'), params, url);
    const bob = LightWallet.create(path.join(dir, 'bob.json'), params, light.url);
    alice.privateInputs = 'fcmp'; bob.privateInputs = 'fcmp';
    const miner = Keys.random();
    const mine = (n) => mineVia(url, miner.tAddress(params), n);
    await mineVia(url, alice.tAddress, 30);
    await mineVia(url, miner.sAddress(params), 12); // várias saídas privadas de terceiros na árvore
    // Alice blinda uma moeda e espera ela entrar numa âncora madura
    await alice.send({ to: alice.sAddress, amount: 5n * COIN, from: 'transparente' });
    await mine(params.fcmpMaturity + 3);
    await alice.sync();
    assert.equal(alice.balance().shielded, 5n * COIN);

    // privado → privado com FCMP
    const res = await alice.send({ to: bob.sAddress, amount: 2n * COIN, from: 'privado', memo: 'entre todas' });
    const raw = Transaction.deserialize(fromHex((await rpc(url, 'gettransaction', { txid: res.txid })).tx));
    assert.equal(raw.sIn.length, 1);
    assert.equal(raw.sIn[0].ring.length, 0, 'sem anel');
    const total = (await rpc(url, 'getshieldedoutputs', { start: 0, count: 0 })).total;
    assert.ok(raw.sIn[0].anchor >= total - 4 - params.fcmpMaturity && raw.sIn[0].anchor <= total, 'a âncora cobre (quase) todas as saídas');
    await mine(params.fcmpMaturity + 3);
    await alice.sync();
    await bob.sync();
    assert.equal(bob.balance().shielded, 2n * COIN);
    assert.deepEqual(bob.history().received.map((r) => r.memo), ['entre todas']);
    assert.ok(alice.data.sOwned.find((o) => o.keyImage === toHex(raw.sIn[0].keyImage)).spent, 'a moeda gasta aparece como gasta');

    const c = node.consensus;
    // gasto duplo: a mesma prova reaproveitada numa tx nova bate na imagem de chave
    assert.throws(() => validateTxInContext(raw, c.virtual.view, c.virtual.gd.daaScore, params), /gasto duplo/);
    // âncora imatura: recusada antes de qualquer verificação cara
    await mineVia(url, miner.sAddress(params), 3); // saídas privadas recém-criadas no fim da árvore
    const young = Transaction.deserialize(raw.serialize());
    young.sIn[0].anchor = c.utxo.sList.length;
    young.sIn[0].fcmp = Buffer.alloc(fcmpProofSize(young.sIn[0].anchor, params.fcmpBranch));
    young.sIn[0].keyImage = mulG(randomScalar()).toBytes();
    young.invalidate();
    assert.throws(() => validateTxInContext(young, c.virtual.view, c.virtual.gd.daaScore, params), /âncora recente demais/);
    // numa rede sem anéis (todas menos a simnet), uma entrada em anel é recusada
    const noRings = { ...params, ringInputs: false };
    const ringTx = Transaction.deserialize(raw.serialize());
    ringTx.sIn[0] = { ring: Array.from({ length: params.ringSize }, (_, k) => ({ txid: Buffer.alloc(32, k + 1), index: 0 })), pseudo: raw.sIn[0].pseudo, keyImage: raw.sIn[0].keyImage, clsag: Buffer.alloc(32 + 32 * params.ringSize + 33) };
    ringTx.invalidate();
    assert.throws(() => validateTxStateless(ringTx, noRings), /anel não são aceitas/);

    // carteira leve gasta com FCMP pedindo o caminho com pedaços-isca
    const back = await bob.send({ to: alice.sAddress, amount: COIN, from: 'privado' });
    const raw2 = Transaction.deserialize(fromHex((await rpc(url, 'gettransaction', { txid: back.txid })).tx));
    assert.equal(raw2.sIn[0].ring.length, 0);
    await mine(params.lightProofDepth + 3);
    assert.equal((await rpc(url, 'gettransactionstatus', { txid: back.txid })).status, 'accepted');
    await bob.sync();
    const bb = bob.balance(), change = bb.shielded + bb.shieldedImmature + bb.unverified;
    assert.ok(change > COIN * 9n / 10n && change < COIN, `o troco volta para Bob (${JSON.stringify(bb, (k, v) => (typeof v === 'bigint' ? v.toString() : v))})`);
    console.log(`    entrada privada: ${raw.sIn[0].fcmp.length} B de prova, conjunto de anonimato = ${raw.sIn[0].anchor} saídas`);
  } finally {
    await light.close();
    await node.stop();
  }
});
