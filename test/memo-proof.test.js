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

test('memo: only the recipient reads it; a fixed size hides whether there is a message', () => {
  const a = randomScalar(), A = mulG(a), r = randomScalar();
  const ss = sharedSecret(r, A);
  const text = 'Order #123 — thank you! 🙂';
  const blk = encryptMemo(text, ss, 0);
  assert.equal(blk.length, MEMO_BLOCK_SIZE);
  assert.equal(decryptMemo(blk, sharedSecret(a, mulG(r)), 0), text, 'the recipient reads it (a·R = r·A)');
  assert.equal(decryptMemo(blk, ss, 1), null, 'wrong output index');
  assert.equal(decryptMemo(blk, sharedSecret(randomScalar(), A), 0), null, 'someone else cannot read it');
  const bad = Buffer.from(blk); bad[20] ^= 1;
  assert.equal(decryptMemo(bad, ss, 0), null, 'tampering detected');
  assert.equal(encryptMemo('', ss, 0).length, blk.length, 'an empty memo has the same size');
  assert.throws(() => encryptMemo('x'.repeat(128), ss, 0), /too long/);
});

function fakeInput(keys, amount) {
  return { outpoint: { txid: randomBytes(32), index: 0 }, amount, signer: keys.tKey(0).signer };
}

test('transaction: every private output carries a memo block; payment proof valid and tamper-proof', () => {
  const alice = Keys.random(), bob = Keys.random(), carol = Keys.random();
  const bobAddr = bob.sAddress(params), carolAddr = carol.sAddress(params);
  const amount = 3n * COIN;
  const withMemo = buildTransaction({
    params, tInputs: [fakeInput(alice, 10n * COIN)], outputs: [{ type: 's', A: bob.A, B: bob.B, amount }],
    change: { type: 't', lock: alice.tKey(0).lock }, memo: 'invoice 2026-117',
  });
  const noMemo = buildTransaction({
    params, tInputs: [fakeInput(alice, 10n * COIN)], outputs: [{ type: 's', A: bob.A, B: bob.B, amount }],
    change: { type: 't', lock: alice.tKey(0).lock },
  });
  assert.equal(withMemo.tx.payload.length, MEMO_BLOCK_SIZE);
  assert.equal(noMemo.tx.payload.length, withMemo.tx.payload.length, 'with and without a memo they are indistinguishable');
  assert.equal(noMemo.tx.size, withMemo.tx.size);
  assert.throws(() => buildTransaction({
    params, tInputs: [fakeInput(alice, 10n * COIN)], outputs: [{ type: 't', lock: bob.tKey(0).lock, amount }], memo: 'x',
  }), /would be public/);

  // the recipient finds the output and the memo with their own keys only
  const tx = Transaction.deserialize(withMemo.tx.serialize());
  const R = Point.fromBytes(tx.sOut[0].R);
  const o = tx.sOut[0];
  const got = scanShieldedOutput(bob.scanKeys, R, 0, { P: Point.fromBytes(o.P), C: Point.fromBytes(o.C), encAmount: o.encAmount, viewTag: o.viewTag });
  assert.equal(got.v, amount);
  assert.equal(decryptMemo(tx.payload, got.ss, 0), 'invoice 2026-117');

  // payment proof
  const proof = createPaymentProof(params, { txid: tx.id, r: withMemo.r, address: bobAddr, message: 'order 117' });
  assert.match(proof, /^krpdev1/);
  const ok = verifyPaymentProof(params, { proof, address: bobAddr, tx, message: 'order 117' });
  assert.equal(ok.valid, true, ok.reason);
  assert.equal(ok.total, amount);
  assert.equal(ok.memo, 'invoice 2026-117');

  // it does not work for another address, another message, another transaction, nor when tampered with
  assert.equal(verifyPaymentProof(params, { proof, address: carolAddr, tx, message: 'order 117' }).valid, false);
  assert.equal(verifyPaymentProof(params, { proof, address: bobAddr, tx, message: 'order 118' }).valid, false);
  assert.equal(verifyPaymentProof(params, { proof, address: bobAddr, tx: noMemo.tx, message: 'order 117' }).valid, false);
  const tampered = proof.slice(0, 40) + (proof[40] === 'q' ? 'p' : 'q') + proof.slice(41);
  assert.equal(verifyPaymentProof(params, { proof: tampered, address: bobAddr, tx, message: 'order 117' }).valid, false);
  // someone without the secret r cannot forge a proof for Carol
  const forged = createPaymentProof(params, { txid: tx.id, r: randomScalar(), address: carolAddr });
  assert.equal(verifyPaymentProof(params, { proof: forged, address: carolAddr, tx }).valid, false);
});
