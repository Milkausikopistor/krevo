import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getParams, COIN, MAX_SUPPLY } from '../src/params.js';
import { Consensus } from '../src/consensus/consensus.js';
import { Block } from '../src/consensus/block.js';
import { Keys } from '../src/wallet/keys.js';
import { buildTransaction } from '../src/wallet/builder.js';
import { scheduledSubsidy } from '../src/consensus/emission.js';
import { toHex } from '../src/util/bytes.js';
import { Clock, mine, tUtxos, matureTUtxos, scanShielded, makeRing } from './helpers.js';
import { solve } from '../src/node/solver.js';

const params = getParams('simnet');

function sumT(c, keys) { return tUtxos(c, keys).reduce((a, u) => a + u.amount, 0n); }
function sumS(c, keys) { return scanShielded(c, keys).reduce((a, u) => a + u.amount, 0n); }

test('consenso: mineração, recompensas, transações transparentes e privadas, gasto duplo e invariante de oferta', () => {
  const c = new Consensus(params);
  const clock = new Clock();
  const alice = Keys.random(), bob = Keys.random(), carol = Keys.random(), miner2 = Keys.random();
  const A = alice.tKey(0).lock;

  // 1) Mineração sequencial: o gênesis não paga nada (zero pré-mineração).
  for (let i = 0; i < 15; i++) mine(c, A, [], clock);
  assert.equal(c.virtual.gd.blueScore, 16);
  const sub = scheduledSubsidy(1, params);
  // 15 blocos minerados; o virtual já aceitou a coinbase do último pai selecionado,
  // que paga os blocos 1..14 (o bloco 15 será pago pelo próximo bloco da cadeia).
  assert.equal(sumT(c, alice), sub * 14n);

  // 2) Blocos paralelos (DAG): dois mineradores sobre os mesmos pais, ambos recompensados.
  const parents = c.virtual.parents.map(toHex);
  const b1 = mine(c, A, [], clock, parents);
  const b2 = mine(c, miner2.tKey(0).lock, [], clock, parents);
  assert.equal(c.tips.size, 2, 'duas pontas paralelas');
  mine(c, A, [], clock); // funde as duas pontas
  const gd = c.gd(c.virtual.gd.selectedParent);
  assert.equal(gd.mergesetBlues.length, 2, 'as duas paralelas são azuis');
  mine(c, A, [], clock);
  assert.equal(sumT(c, miner2), sub, 'minerador do bloco paralelo foi pago');
  assert.ok(b1 && b2);

  // 3) Transação transparente Alice → Bob.
  const inputs = matureTUtxos(c, alice).slice(0, 2);
  assert.ok(inputs.length === 2);
  const pay = buildTransaction({ params, tInputs: inputs, outputs: [{ type: 't', lock: bob.tKey(0).lock, amount: 3n * COIN / 10n }], change: { type: 't', lock: A } });
  mine(c, A, [pay.tx], clock);
  assert.equal(c.txStatus(pay.tx.idHex).status, 'accepted');
  assert.equal(sumT(c, bob), 3n * COIN / 10n);
  assert.ok(pay.fee > 0n && pay.fee < 10_000n, `taxa insignificante: ${pay.fee} grãos`);

  // gasto duplo da mesma entrada: o bloco é válido, mas a transação é ignorada.
  const dbl = buildTransaction({ params, tInputs: inputs, outputs: [{ type: 't', lock: carol.tKey(0).lock, amount: COIN / 10n }], change: { type: 't', lock: A } });
  mine(c, A, [dbl.tx], clock);
  assert.equal(c.txStatus(dbl.tx.idHex).status, 'unknown');
  assert.equal(sumT(c, carol), 0n);

  // 4) Blindar: transparente → privado (várias saídas para formar o conjunto de anonimato),
  //    e mineração direto para endereço privado (coinbase privada).
  const shieldIn = matureTUtxos(c, alice).filter((u) => !inputs.some((i) => toHex(i.outpoint.txid) === toHex(u.outpoint.txid)));
  const sh = buildTransaction({
    params, tInputs: shieldIn.slice(0, 3),
    outputs: [
      { type: 's', A: bob.A, B: bob.B, amount: COIN / 2n },
      { type: 's', A: bob.A, B: bob.B, amount: COIN / 4n },
      { type: 's', A: carol.A, B: carol.B, amount: COIN / 8n },
    ],
    change: { type: 't', lock: A },
  });
  mine(c, A, [sh.tx], clock);
  assert.equal(c.txStatus(sh.tx.idHex).status, 'accepted');
  for (let i = 0; i < 12; i++) mine(c, miner2.shieldedData, [], clock);
  assert.equal(sumS(c, bob), COIN / 2n + COIN / 4n);
  assert.ok(sumS(c, miner2) > 0n, 'coinbase privada recebida');

  // 5) Privado → privado com anel.
  const bobOut = scanShielded(c, bob).find((o) => o.amount === COIN / 2n);
  const priv = buildTransaction({
    params, sInputs: [{ ...bobOut, ring: makeRing(c, bobOut) }],
    outputs: [{ type: 's', A: carol.A, B: carol.B, amount: COIN / 5n }],
    change: { type: 's', A: bob.A, B: bob.B },
  });
  assert.equal(priv.tx.tOut.length, 0);
  mine(c, A, [priv.tx], clock);
  assert.equal(c.txStatus(priv.tx.idHex).status, 'accepted');
  assert.equal(sumS(c, carol), COIN / 8n + COIN / 5n);
  assert.equal(sumS(c, bob), COIN / 4n + COIN / 2n - COIN / 5n - priv.fee);

  // gasto duplo privado (mesma saída, outro anel): mesma imagem de chave → rejeitada.
  const priv2 = buildTransaction({
    params, sInputs: [{ ...bobOut, ring: makeRing(c, bobOut) }],
    outputs: [{ type: 's', A: carol.A, B: carol.B, amount: COIN / 5n }],
    change: { type: 's', A: bob.A, B: bob.B },
  });
  mine(c, A, [priv2.tx], clock);
  assert.equal(c.txStatus(priv2.tx.idHex).status, 'unknown');

  // 6) Desblindar: privado → transparente.
  for (let i = 0; i < 3; i++) mine(c, A, [], clock);
  const carolOuts = scanShielded(c, carol);
  const un = buildTransaction({
    params, sInputs: carolOuts.map((o) => ({ ...o, ring: makeRing(c, o) })),
    outputs: [{ type: 't', lock: carol.tKey(0).lock, amount: COIN / 4n }],
    change: { type: 's', A: carol.A, B: carol.B },
  });
  mine(c, A, [un.tx], clock);
  assert.equal(c.txStatus(un.tx.idHex).status, 'accepted');
  assert.equal(sumT(c, carol), COIN / 4n);

  // 7) Invariante: tudo que existe = tudo que foi cunhado (nada criado do nada).
  mine(c, A, [], clock);
  const sp = c.virtual.gd.selectedParent;
  const spAcc = c.acc.get(sp);
  const everyone = [alice, bob, carol, miner2];
  const total = everyone.reduce((a, k) => a + sumT(c, k) + sumS(c, k), 0n);
  assert.equal(total + spAcc.pool + c.virtual.acceptance.feeTotal, spAcc.minted);
  assert.ok(spAcc.minted <= MAX_SUPPLY);
});

test('consenso: reorganização — o ramo mais pesado vence e a transação conflitante é revertida', () => {
  const c = new Consensus(params);
  const clock = new Clock();
  const alice = Keys.random(), bob = Keys.random(), carol = Keys.random();
  const A = alice.tKey(0).lock;
  for (let i = 0; i < 14; i++) mine(c, A, [], clock);
  const coin = matureTUtxos(c, alice)[0];
  const toBob = buildTransaction({ params, tInputs: [coin], outputs: [{ type: 't', lock: bob.tKey(0).lock, amount: COIN / 10n }], change: { type: 't', lock: A } });
  const toCarol = buildTransaction({ params, tInputs: [coin], outputs: [{ type: 't', lock: carol.tKey(0).lock, amount: COIN / 10n }], change: { type: 't', lock: A } });

  // Um "atacante" copia o estado atual e minera em segredo.
  const attacker = new Consensus(params);
  const history = [...c.blocks.values()].filter((b) => b.header.parents.length).sort((x, y) => x.header.daaScore - y.header.daaScore);
  for (const b of history) assert.equal(attacker.addBlock(b, { now: clock.t + 1000 }).status, 'accepted');

  // ramo A (público): 1 bloco com o pagamento para Bob
  const a1 = mine(c, A, [toBob.tx], clock);
  assert.equal(c.txStatus(toBob.tx.idHex).status, 'accepted');
  // ramo B (secreto, sem fundir A): 3 blocos, o primeiro paga Carol
  const bBlocks = [];
  for (let i = 0; i < 3; i++) bBlocks.push(mine(attacker, A, i === 0 ? [toCarol.tx] : [], clock));
  // Publica o ramo B: ele tem mais trabalho; A ainda é ponta e é fundido como vermelho/azul,
  // mas na ordem de consenso a transação de B vem antes → Carol recebe, Bob não.
  for (const b of bBlocks) assert.equal(c.addBlock(b, { now: clock.t + 1000 }).status, 'accepted');
  assert.equal(c.virtual.gd.selectedParent, bBlocks[2].hashHex);
  assert.equal(c.txStatus(toCarol.tx.idHex).status, 'accepted');
  assert.equal(c.txStatus(toBob.tx.idHex).status, 'unknown');
  assert.equal(sumT(c, bob), 0n);
  assert.equal(sumT(c, carol), COIN / 10n);
  // todos os nós chegam ao mesmo estado independentemente da ordem de chegada
  const c2 = new Consensus(params);
  const all = [...c.blocks.values()].filter((b) => b.header.parents.length).sort((x, y) => x.header.daaScore - y.header.daaScore);
  for (const b of all.reverse()) c2.addBlock(b, { now: clock.t + 1000 }); // ordem invertida: vários órfãos
  let pending = all.filter((b) => !c2.has(b.hashHex));
  while (pending.length) {
    for (const b of pending) c2.addBlock(b, { now: clock.t + 1000 });
    pending = pending.filter((b) => !c2.has(b.hashHex));
  }
  assert.equal(c2.virtual.gd.selectedParent, c.virtual.gd.selectedParent);
  assert.deepEqual(c2.virtual.acceptance.muhash.digest(), c.virtual.acceptance.muhash.digest());
  assert.ok(a1);
});

test('consenso: blocos inválidos são rejeitados', () => {
  const c = new Consensus(params);
  const clock = new Clock();
  const alice = Keys.random();
  const A = alice.tKey(0).lock;
  for (let i = 0; i < 3; i++) mine(c, A, [], clock);

  // coinbase pagando mais do que o devido → desqualificado da cadeia
  const t = clock.next();
  const greedy = c.buildTemplate(A, [], Buffer.alloc(0), t);
  greedy.txs[0].tOut[0].amount += 1n;
  greedy.txs[0].invalidate();
  greedy.header.hashMerkleRoot = (() => { const b = c.buildTemplate(A, [], Buffer.alloc(0), t); return b.header.hashMerkleRoot; })();
  // recomputa a raiz de Merkle correta para a coinbase adulterada
  const { merkleRoot } = awaitImport;
  greedy.header.hashMerkleRoot = merkleRoot(greedy.txs.map((x) => x.hash));
  assert.ok(solve(greedy));
  const r = c.addBlock(greedy, { now: t + 1000 });
  assert.equal(r.status, 'accepted');
  assert.equal(r.chainValid, false, 'coinbase gananciosa é desqualificada');
  assert.notEqual(c.virtual.gd.selectedParent, greedy.hashHex);

  // PoW inválida
  const t2 = clock.next();
  const bad = c.buildTemplate(A, [], Buffer.alloc(0), t2);
  bad.header.bits = 0x1d00ffff; // alvo difícil, nonce não resolve
  const r2 = c.addBlock(new Block(bad.header, bad.txs), { now: t2 + 1000 });
  assert.equal(r2.status, 'invalid');

  // timestamp muito no futuro (política): aguarda
  const t3 = clock.next();
  const fut = c.buildTemplate(A, [], Buffer.alloc(0), t3 + 10 * 60_000);
  assert.ok(solve(fut));
  assert.equal(c.addBlock(fut, { now: t3 }).status, 'future');
});

const awaitImport = await import('../src/consensus/block.js');
