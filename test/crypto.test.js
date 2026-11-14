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

test('secp256k1: vetores conhecidos e propriedades do grupo', () => {
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

test('schnorr: assina, verifica e rejeita adulterações', () => {
  const x = randomScalar(), P = mulG(x), msg = Buffer.from('mensagem');
  const sig = schnorrSign(x, msg);
  assert.ok(schnorrVerify(P, msg, sig));
  assert.ok(!schnorrVerify(P, Buffer.from('outra'), sig));
  assert.ok(!schnorrVerify(mulG(randomScalar()), msg, sig));
  const bad = Buffer.from(sig); bad[40] ^= 1;
  assert.ok(!schnorrVerify(P, msg, bad));
  assert.ok(!schnorrVerify(P, msg, sig, 'outro-dominio'));
});

test('pedersen: homomorfismo', () => {
  const x1 = randomScalar(), x2 = randomScalar();
  assert.ok(commit(5n, x1).add(commit(7n, x2)).equals(commit(12n, modN(x1 + x2))));
  assert.ok(!commit(5n, x1).equals(commit(6n, x1)));
});

test('stealth: destinatário reconhece a saída; terceiros não', () => {
  const a = randomScalar(), b = randomScalar(), B = mulG(b);
  const main = subaddressKeys(a, B, 0);
  const addr = { A: main.C, B: main.D };
  assert.ok(main.D.equals(B) && main.C.equals(B.mul(a)), 'endereço principal = (a·B, B)');
  const r = randomScalar();
  const out = makeShieldedOutput(addr, r, 3, 123456789n);
  const got = scanShieldedOutput({ a, b, B }, out.R, 3, out);
  assert.ok(got);
  assert.equal(got.v, 123456789n);
  assert.equal(got.index, 0);
  assert.ok(mulG(got.p).equals(out.P), 'chave privada de uso único confere');
  assert.ok(commit(got.v, got.x).equals(out.C));
  const other = randomScalar();
  assert.equal(scanShieldedOutput({ a: other, B: mulG(randomScalar()) }, out.R, 3, out), null);
  assert.equal(scanShieldedOutput({ a, b, B }, out.R, 4, out), null, 'índice errado');
  // coinbase (cegamento zero)
  const cb = makeShieldedOutput(addr, r, 0, 50n, true);
  assert.ok(cb.C.equals(mulH(50n)));
  assert.equal(scanShieldedOutput({ a, b, B }, cb.R, 0, cb).x, 0n);
});

test('subendereços: uma multiplicação por saída encontra qualquer subendereço; não ligáveis', () => {
  const a = randomScalar(), b = randomScalar(), B = mulG(b);
  const subs = Array.from({ length: 200 }, (_, i) => subaddressKeys(a, B, i));
  const table = new Map(subs.map((s) => [s.D.hex(), s.index]));
  const sub = (i) => subs[i].m;
  // pagamento ao subendereço 137
  const s137 = subs[137];
  const out = makeShieldedOutput({ A: s137.C, B: s137.D }, randomScalar(), 0, 4242n);
  const got = scanShieldedOutput({ a, b, B, table, sub }, out.R, 0, out);
  assert.equal(got.index, 137);
  assert.equal(got.v, 4242n);
  assert.ok(mulG(got.p).equals(out.P), 'chave de gasto do subendereço confere');
  // a chave de visualização (sem b) também acha a saída, mas não gera chave de gasto
  const viewOnly = scanShieldedOutput({ a, B, table, sub }, out.R, 0, out);
  assert.equal(viewOnly.index, 137);
  assert.equal(viewOnly.p, undefined);
  // sem a tabela (só o principal), a saída do subendereço não é reconhecida
  assert.equal(scanShieldedOutput({ a, b, B }, out.R, 0, out), null);
  // subendereços não compartilham nenhum ponto visível entre si
  const seen = new Set();
  for (const s of subs.slice(0, 50)) for (const pt of [s.C, s.D]) { assert.ok(!seen.has(pt.hex())); seen.add(pt.hex()); }
  // duas saídas para o MESMO subendereço têm chaves efêmeras e de uso único diferentes
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

test('clsag: assinatura em anel válida, ligável e não forjável', () => {
  const n = 11, pi = 6, v = 777n;
  const { ring, p, x } = makeRing(n, pi, v);
  const xp = randomScalar();
  const pseudo = commit(v, xp);
  const msg = Buffer.from('tx');
  const sig = clsagSign(msg, ring, pseudo, pi, p, modN(x - xp));
  assert.ok(clsagVerify(msg, ring, pseudo, sig));
  assert.ok(sig.I.equals(keyImage(p, ring[pi].P)), 'imagem de chave determinística');
  // serialização
  const dec = decodeClsag(encodeClsag(sig), n, sig.I);
  assert.ok(clsagVerify(msg, ring, pseudo, dec));
  // mensagem errada
  assert.ok(!clsagVerify(Buffer.from('tx2'), ring, pseudo, sig));
  // pseudo-compromisso com outro valor (tentativa de inflação)
  assert.ok(!clsagVerify(msg, ring, commit(v + 1n, xp), sig));
  // trocar a imagem de chave (tentativa de gasto duplo)
  assert.ok(!clsagVerify(msg, ring, pseudo, { ...sig, I: mulG(randomScalar()) }));
  // assinar o mesmo membro de novo gera a mesma imagem de chave
  const sig2 = clsagSign(Buffer.from('outra tx'), ring, pseudo, pi, p, modN(x - xp));
  assert.ok(sig2.I.equals(sig.I));
  // não é possível assinar sem a chave
  assert.throws(() => clsagSign(msg, ring, pseudo, pi, randomScalar(), modN(x - xp)));
});

test('bulletproofs: prova agregada válida e rejeição de valores fora do intervalo', () => {
  const vals = [0n, (1n << 64n) - 1n, 42n];
  const gam = vals.map(() => randomScalar());
  const { V, proof } = proveRange(vals, gam);
  assert.equal(proof.length, rangeProofSize(3));
  assert.ok(verifyRange(V, proof));
  // proof adulterada
  const bad = Buffer.from(proof); bad[200] ^= 1;
  assert.ok(!verifyRange(V, bad));
  // compromisso trocado
  assert.ok(!verifyRange([V[0], commit(43n, gam[1]), V[2]], proof));
  // ordem trocada
  assert.ok(!verifyRange([V[1], V[0], V[2]], proof));
  // um valor "negativo" (n - 1) não pode ser provado
  assert.throws(() => proveRange([N - 1n], [randomScalar()]));
  // prova de 1 saída
  const one = proveRange([1000n], [randomScalar()]);
  assert.ok(verifyRange(one.V, one.proof));
  assert.ok(!verifyRange(one.V, proof));
});

test('muhash: independente de ordem, remoção funciona', () => {
  const a = new MuHash().add(Buffer.from('a')).add(Buffer.from('b')).add(Buffer.from('c'));
  const b = new MuHash().add(Buffer.from('c')).add(Buffer.from('a')).add(Buffer.from('b'));
  assert.deepEqual(a.digest(), b.digest());
  const c = new MuHash().add(Buffer.from('a')).add(Buffer.from('b')).add(Buffer.from('x')).add(Buffer.from('c')).remove(Buffer.from('x'));
  assert.deepEqual(c.digest(), a.digest());
  assert.notDeepEqual(new MuHash().add(Buffer.from('a')).digest(), a.digest());
});

test('bech32m: ida e volta e detecção de erro', () => {
  const data = Buffer.from('00' + '02'.repeat(33), 'hex');
  const s = encode('krv', data);
  assert.deepEqual(decode(s).bytes, data);
  const broken = s.slice(0, -3) + (s.at(-3) === 'q' ? 'p' : 'q') + s.slice(-2);
  assert.throws(() => decode(broken));
});
