import { test } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { getParams, COIN } from '../src/params.js';
import { mulG, randomScalar, Point } from '../src/crypto/secp256k1.js';
import { sharedSecret, encryptMemo, decryptMemo, scanShieldedOutput, MEMO_BLOCK_SIZE } from '../src/crypto/stealth.js';
import { Keys } from '../src/wallet/keys.js';
import { buildTransaction } from '../src/wallet/builder.js';
import { createPaymentProof, verifyPaymentProof } from '../src/wallet/proof.js';
import { Transaction } from '../src/consensus/tx.js';

const params = getParams('devnet');

test('memo: só o destinatário lê; tamanho fixo esconde se há mensagem', () => {
  const a = randomScalar(), A = mulG(a), r = randomScalar();
  const ss = sharedSecret(r, A);
  const text = 'Pedido nº 123 — obrigado! 🙂';
  const blk = encryptMemo(text, ss, 0);
  assert.equal(blk.length, MEMO_BLOCK_SIZE);
  assert.equal(decryptMemo(blk, sharedSecret(a, mulG(r)), 0), text, 'destinatário lê (a·R = r·A)');
  assert.equal(decryptMemo(blk, ss, 1), null, 'índice de saída errado');
  assert.equal(decryptMemo(blk, sharedSecret(randomScalar(), A), 0), null, 'outra pessoa não lê');
  const bad = Buffer.from(blk); bad[20] ^= 1;
  assert.equal(decryptMemo(bad, ss, 0), null, 'adulteração detectada');
  assert.equal(encryptMemo('', ss, 0).length, blk.length, 'memo vazio tem o mesmo tamanho');
  assert.throws(() => encryptMemo('x'.repeat(128), ss, 0), /longo demais/);
});

function fakeInput(keys, amount) {
  return { outpoint: { txid: randomBytes(32), index: 0 }, amount, signer: keys.tKey(0).signer };
}

test('transação: toda saída privada leva bloco de memo; prova de pagamento válida e à prova de adulteração', () => {
  const alice = Keys.random(), bob = Keys.random(), carol = Keys.random();
  const bobAddr = bob.sAddress(params), carolAddr = carol.sAddress(params);
  const amount = 3n * COIN;
  const withMemo = buildTransaction({
    params, tInputs: [fakeInput(alice, 10n * COIN)], outputs: [{ type: 's', A: bob.A, B: bob.B, amount }],
    change: { type: 't', lock: alice.tKey(0).lock }, memo: 'fatura 2026-117',
  });
  const noMemo = buildTransaction({
    params, tInputs: [fakeInput(alice, 10n * COIN)], outputs: [{ type: 's', A: bob.A, B: bob.B, amount }],
    change: { type: 't', lock: alice.tKey(0).lock },
  });
  assert.equal(withMemo.tx.payload.length, MEMO_BLOCK_SIZE);
  assert.equal(noMemo.tx.payload.length, withMemo.tx.payload.length, 'com e sem memo são indistinguíveis');
  assert.equal(noMemo.tx.size, withMemo.tx.size);
  assert.throws(() => buildTransaction({
    params, tInputs: [fakeInput(alice, 10n * COIN)], outputs: [{ type: 't', lock: bob.tKey(0).lock, amount }], memo: 'x',
  }), /ficaria público/);

  // o destinatário encontra a saída e o memo só com as próprias chaves
  const tx = Transaction.deserialize(withMemo.tx.serialize());
  const R = Point.fromBytes(tx.sOut[0].R);
  const o = tx.sOut[0];
  const got = scanShieldedOutput(bob.scanKeys, R, 0, { P: Point.fromBytes(o.P), C: Point.fromBytes(o.C), encAmount: o.encAmount, viewTag: o.viewTag });
  assert.equal(got.v, amount);
  assert.equal(decryptMemo(tx.payload, got.ss, 0), 'fatura 2026-117');

  // prova de pagamento
  const proof = createPaymentProof(params, { txid: tx.id, r: withMemo.r, address: bobAddr, message: 'pedido 117' });
  assert.match(proof, /^krpdev1/);
  const ok = verifyPaymentProof(params, { proof, address: bobAddr, tx, message: 'pedido 117' });
  assert.equal(ok.valid, true, ok.reason);
  assert.equal(ok.total, amount);
  assert.equal(ok.memo, 'fatura 2026-117');

  // não serve para outro endereço, outra mensagem, outra transação, nem adulterada
  assert.equal(verifyPaymentProof(params, { proof, address: carolAddr, tx, message: 'pedido 117' }).valid, false);
  assert.equal(verifyPaymentProof(params, { proof, address: bobAddr, tx, message: 'pedido 118' }).valid, false);
  assert.equal(verifyPaymentProof(params, { proof, address: bobAddr, tx: noMemo.tx, message: 'pedido 117' }).valid, false);
  const tampered = proof.slice(0, 40) + (proof[40] === 'q' ? 'p' : 'q') + proof.slice(41);
  assert.equal(verifyPaymentProof(params, { proof: tampered, address: bobAddr, tx, message: 'pedido 117' }).valid, false);
  // alguém sem o segredo r não consegue forjar uma prova para Carol
  const forged = createPaymentProof(params, { txid: tx.id, r: randomScalar(), address: carolAddr });
  assert.equal(verifyPaymentProof(params, { proof: forged, address: carolAddr, tx }).valid, false);
});
