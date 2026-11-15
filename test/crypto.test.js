import { test } from 'node:test';
import assert from 'node:assert/strict';
import { G, N, mulG, randomScalar, Point, hashToPoint, multiexp, INF, modN } from '../src/crypto/secp256k1.js';
import { schnorrSign, schnorrVerify } from '../src/crypto/schnorr.js';
import { commit, mulH, Hv } from '../src/crypto/pedersen.js';
import { makeShieldedOutput, scanShieldedOutput, subaddressKeys } from '../src/crypto/stealth.js';
import { clsagSign, clsagVerify, keyImage, encodeClsag, decodeClsag } from '../src/crypto/clsag.js';
import { proveRange, verifyRange, rangeProofSize } from '../src/crypto/bulletproofs.js';
import { MuHash } from '../src/crypto/muhash.js';
import { encode, decode } from '../src/util/bech32m.js';

test('secp256k1: known vectors and group properties', () => {
  assert.equal(G.add(G).hex(), '02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5');
  assert.ok(mulG(N).isInf());
  const k = randomScalar();
  assert.ok(mulG(k).equals(G.add(INF).mul(k)));
  const H1 = hashToPoint('t', 'a');
  assert.ok(Point.fromBytes(H1.toBytes()).equals(H1));
  assert.throws(() => Point.fromBytes(Buffer.alloc(33)));
  const ks = Array.from({ length: 40 }, randomScalar);
  const ps = ks.map((_, i) => hashToPoint('t', String(i)));
  let naive = INF;
  ks.forEach((kk, i) => { naive = naive.add(ps[i].mul(kk)); });
  assert.ok(multiexp(ks, ps).equals(naive));
});

test('schnorr: signs, verifies and rejects tampering', () => {
  const x = randomScalar(), P = mulG(x), msg = Buffer.from('message');
  const sig = schnorrSign(x, msg);
  assert.ok(schnorrVerify(P, msg, sig));
  assert.ok(!schnorrVerify(P, Buffer.from('other'), sig));
  assert.ok(!schnorrVerify(mulG(randomScalar()), msg, sig));
  const bad = Buffer.from(sig); bad[40] ^= 1;
  assert.ok(!schnorrVerify(P, msg, bad));
  assert.ok(!schnorrVerify(P, msg, sig, 'other-domain'));
});

test('pedersen: homomorfismo', () => {
  const x1 = randomScalar(), x2 = randomScalar();
  assert.ok(commit(5n, x1).add(commit(7n, x2)).equals(commit(12n, modN(x1 + x2))));
  assert.ok(!commit(5n, x1).equals(commit(6n, x1)));
});

test('stealth: the recipient recognizes the output; third parties do not', () => {
  const a = randomScalar(), b = randomScalar(), B = mulG(b);
  const main = subaddressKeys(a, B, 0);
  const addr = { A: main.C, B: main.D };
  assert.ok(main.D.equals(B) && main.C.equals(B.mul(a)), 'main address = (a·B, B)');
  const r = randomScalar();
  const out = makeShieldedOutput(addr, r, 3, 123456789n);
  const got = scanShieldedOutput({ a, b, B }, out.R, 3, out);
  assert.ok(got);
  assert.equal(got.v, 123456789n);
  assert.equal(got.index, 0);
  assert.ok(mulG(got.p).equals(out.P), 'one-time private key matches');
  assert.ok(commit(got.v, got.x).equals(out.C));
  const other = randomScalar();
  assert.equal(scanShieldedOutput({ a: other, B: mulG(randomScalar()) }, out.R, 3, out), null);
  assert.equal(scanShieldedOutput({ a, b, B }, out.R, 4, out), null, 'wrong index');
  // coinbase (zero blinding)
  const cb = makeShieldedOutput(addr, r, 0, 50n, true);
  assert.ok(cb.C.equals(mulH(50n)));
  assert.equal(scanShieldedOutput({ a, b, B }, cb.R, 0, cb).x, 0n);
});

test('subaddresses: one multiplication per output finds any subaddress; unlinkable', () => {
  const a = randomScalar(), b = randomScalar(), B = mulG(b);
  const subs = Array.from({ length: 200 }, (_, i) => subaddressKeys(a, B, i));
  const table = new Map(subs.map((s) => [s.D.hex(), s.index]));
  const sub = (i) => subs[i].m;
  // payment to subaddress 137
  const s137 = subs[137];
  const out = makeShieldedOutput({ A: s137.C, B: s137.D }, randomScalar(), 0, 4242n);
  const got = scanShieldedOutput({ a, b, B, table, sub }, out.R, 0, out);
  assert.equal(got.index, 137);
  assert.equal(got.v, 4242n);
  assert.ok(mulG(got.p).equals(out.P), 'the subaddress spend key matches');
  // the view key (without b) also finds the output, but does not produce a spend key
  const viewOnly = scanShieldedOutput({ a, B, table, sub }, out.R, 0, out);
  assert.equal(viewOnly.index, 137);
  assert.equal(viewOnly.p, undefined);
  // without the table (only the main one), the subaddress output is not recognized
  assert.equal(scanShieldedOutput({ a, b, B }, out.R, 0, out), null);
  // subaddresses share no visible point with each other
  const seen = new Set();
  for (const s of subs.slice(0, 50)) for (const pt of [s.C, s.D]) { assert.ok(!seen.has(pt.hex())); seen.add(pt.hex()); }
  // two outputs to the SAME subaddress have different ephemeral and one-time keys
  const o1 = makeShieldedOutput({ A: s137.C, B: s137.D }, randomScalar(), 0, 1n);
  const o2 = makeShieldedOutput({ A: s137.C, B: s137.D }, randomScalar(), 0, 1n);
  assert.ok(!o1.P.equals(o2.P) && !o1.R.equals(o2.R));
});

function makeRing(n, pi, v) {
  const ring = [];
  let p, x;
  for (let i = 0; i < n; i++) {
    const pk = randomScalar(), xi = randomScalar();
    ring.push({ P: mulG(pk), C: commit(i === pi ? v : BigInt(i * 1000), xi) });
    if (i === pi) { p = pk; x = xi; }
  }
  return { ring, p, x };
}

test('clsag: ring signature valid, linkable and unforgeable', () => {
  const n = 11, pi = 6, v = 777n;
  const { ring, p, x } = makeRing(n, pi, v);
  const xp = randomScalar();
  const pseudo = commit(v, xp);
  const msg = Buffer.from('tx');
  const sig = clsagSign(msg, ring, pseudo, pi, p, modN(x - xp));
  assert.ok(clsagVerify(msg, ring, pseudo, sig));
  assert.ok(sig.I.equals(keyImage(p, ring[pi].P)), 'deterministic key image');
  // serialization
  const dec = decodeClsag(encodeClsag(sig), n, sig.I);
  assert.ok(clsagVerify(msg, ring, pseudo, dec));
  // wrong message
  assert.ok(!clsagVerify(Buffer.from('tx2'), ring, pseudo, sig));
  // pseudo-commitment with another amount (inflation attempt)
  assert.ok(!clsagVerify(msg, ring, commit(v + 1n, xp), sig));
  // swapping the key image (double spend attempt)
  assert.ok(!clsagVerify(msg, ring, pseudo, { ...sig, I: mulG(randomScalar()) }));
  // signing the same member again produces the same key image
  const sig2 = clsagSign(Buffer.from('other tx'), ring, pseudo, pi, p, modN(x - xp));
  assert.ok(sig2.I.equals(sig.I));
  // it is not possible to sign without the key
  assert.throws(() => clsagSign(msg, ring, pseudo, pi, randomScalar(), modN(x - xp)));
});

test('bulletproofs: valid aggregated proof and rejection of out-of-range amounts', () => {
  const vals = [0n, (1n << 64n) - 1n, 42n];
  const gam = vals.map(() => randomScalar());
  const { V, proof } = proveRange(vals, gam);
  assert.equal(proof.length, rangeProofSize(3));
  assert.ok(verifyRange(V, proof));
  // tampered proof
  const bad = Buffer.from(proof); bad[200] ^= 1;
  assert.ok(!verifyRange(V, bad));
  // swapped commitment
  assert.ok(!verifyRange([V[0], commit(43n, gam[1]), V[2]], proof));
  // swapped order
  assert.ok(!verifyRange([V[1], V[0], V[2]], proof));
  // a "negative" amount (n - 1) cannot be proven
  assert.throws(() => proveRange([N - 1n], [randomScalar()]));
  // proof for 1 output
  const one = proveRange([1000n], [randomScalar()]);
  assert.ok(verifyRange(one.V, one.proof));
  assert.ok(!verifyRange(one.V, proof));
});

test('muhash: order independent, removal works', () => {
  const a = new MuHash().add(Buffer.from('a')).add(Buffer.from('b')).add(Buffer.from('c'));
  const b = new MuHash().add(Buffer.from('c')).add(Buffer.from('a')).add(Buffer.from('b'));
  assert.deepEqual(a.digest(), b.digest());
  const c = new MuHash().add(Buffer.from('a')).add(Buffer.from('b')).add(Buffer.from('x')).add(Buffer.from('c')).remove(Buffer.from('x'));
  assert.deepEqual(c.digest(), a.digest());
  assert.notDeepEqual(new MuHash().add(Buffer.from('a')).digest(), a.digest());
});

test('bech32m: round trip and error detection', () => {
  const data = Buffer.from('00' + '02'.repeat(33), 'hex');
  const s = encode('krv', data);
  assert.deepEqual(decode(s).bytes, data);
  const broken = s.slice(0, -3) + (s.at(-3) === 'q' ? 'p' : 'q') + s.slice(-2);
  assert.throws(() => decode(broken));
});
