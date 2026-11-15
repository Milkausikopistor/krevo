// Rust/WebAssembly crypto core (src/crypto/wasm.js, rust/krevo-wasm): the same
// results as the JavaScript implementation, hostile inputs rejected without bringing the module down,
// and the JavaScript plan B when WebAssembly is not available.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

process.env.KREVO_NO_NATIVE = '1'; // this file tests the WebAssembly path, not the native binary

const core = await import('../src/crypto/wasm.js');
const { G, mulG, multiexp, randomScalar, Point, modN, N } = await import('../src/crypto/secp256k1.js');
const { Hv, mulH, commit } = await import('../src/crypto/pedersen.js');
const { schnorrSign, schnorrVerify } = await import('../src/crypto/schnorr.js');
const { proveRange, verifyRange } = await import('../src/crypto/bulletproofs.js');
const { mldsaKeyFromSeed, mldsaSign, mldsaVerify } = await import('../src/crypto/pq.js');
const { CurveTree } = await import('../src/fcmp/tree.js');
const { fcmpVerify, fcmpFinish } = await import('../src/fcmp/fcmp.js');
const parallel = await import('../src/fcmp/parallel.js');
const { keyImage } = await import('../src/crypto/clsag.js');

const ref = (k, P) => multiexp([k], [P]);
const skip = !core.available() && 'WebAssembly turned off (KREVO_NO_WASM)'; // multi-exponentiation in JavaScript (does not go through the core)

test('wasm core: loaded, self-test and the same results as JavaScript', { skip }, () => {
  assert.ok(core.available(), `WebAssembly unavailable: ${core.loadError?.message}`);
  for (let i = 0; i < 20; i++) {
    const k = randomScalar(), P = ref(randomScalar(), G);
    assert.ok(P.mul(k).equals(ref(k, P)), 'k·P');
    assert.ok(mulG(k).equals(ref(k, G)), 'k·G');
    assert.ok(mulH(k).equals(ref(k, Hv)), 'k·H');
  }
  for (const k of [1n, 2n, N - 1n, N - 2n, 1n << 255n]) assert.ok(mulG(k).equals(ref(k, G)), `edge cases: ${k}`);
  assert.ok(mulG(0n).isInf() && G.mul(N).isInf() && mulH(0n).isInf());
  assert.ok(commit(5n, 7n).equals(ref(7n, G).add(ref(5n, Hv))));
});

test('wasm core: hedged Schnorr — two signatures of the same message differ and both are valid', { skip }, () => {
  const x = randomScalar(), P = mulG(x), msg = Buffer.from('message');
  const a = schnorrSign(x, msg), b = schnorrSign(x, msg);
  assert.ok(!a.equals(b), 'nonce with a random part');
  assert.ok(schnorrVerify(P, msg, a) && schnorrVerify(P, msg, b));
  assert.ok(!schnorrVerify(P, Buffer.from('other'), a));
  assert.ok(schnorrVerify(P, msg, schnorrSign(x, msg, 'binding'), 'binding'));
  assert.throws(() => schnorrSign(0n, msg), /zero/);
});

test('wasm core: range proof accepted by the JavaScript verifier; a tampered one is rejected', { skip }, () => {
  for (const vals of [[0n], [(1n << 64n) - 1n], [5n, 1000n, 7n]]) {
    const gs = vals.map(() => randomScalar());
    const { V, proof } = proveRange(vals, gs);
    vals.forEach((v, j) => assert.ok(V[j].equals(commit(v, gs[j]))));
    assert.ok(verifyRange(V, proof));
    const bad = Buffer.from(proof); bad[100] ^= 1;
    assert.ok(!verifyRange(V, bad));
  }
  assert.throws(() => proveRange([1n << 64n], [1n]), /range/);
});

test('wasm core: AES-256-GCM identical to Node\'s; a wrong tag is rejected', { skip }, () => {
  const key = crypto.randomBytes(32), iv = crypto.randomBytes(12), data = crypto.randomBytes(1000);
  const c = crypto.createCipheriv('aes-256-gcm', key, iv);
  const ct = Buffer.concat([c.update(data), c.final()]), tag = c.getAuthTag();
  const r = core.aesGcmEncrypt(key, iv, data);
  assert.ok(Buffer.from(r.ct).equals(ct) && Buffer.from(r.tag).equals(tag));
  assert.ok(Buffer.from(core.aesGcmDecrypt(key, iv, ct, tag)).equals(data));
  const t2 = Buffer.from(tag); t2[0] ^= 1;
  assert.throws(() => core.aesGcmDecrypt(key, iv, ct, t2), /authenticate/);
});

test('wasm core: ML-DSA-44 — same key as OpenSSL, signatures accepted both ways', { skip }, () => {
  const seed = crypto.randomBytes(32), msg = crypto.randomBytes(50);
  const { priv, pub } = mldsaKeyFromSeed(seed);
  assert.ok(core.mldsaPub(seed).equals(pub));
  assert.ok(mldsaVerify(pub, msg, core.mldsaSign(seed, msg)), 'OpenSSL aceita a do Rust');
  assert.ok(core.mldsaVerify(pub, msg, mldsaSign(priv, msg)), 'Rust aceita a do OpenSSL');
  assert.ok(!core.mldsaVerify(pub, Buffer.from('x'), mldsaSign(priv, msg)));
});

test('wasm core: hostile inputs become errors — the module keeps working', { skip }, () => {
  const P = mulG(5n), [x, y] = P.affine();
  assert.throws(() => core.mul(x, y + 1n, 3n), /not on the curve/);
  assert.throws(() => core.mul(x, y, N), /scalar/, 'non-canonical scalar');
  assert.throws(() => core.mulG(N + 5n), /scalar/);
  assert.throws(() => core.fcmpHead({ branch: 4 }), /missing|invalid/);
  assert.throws(() => core.fcmpHalf({ path: 'x' }, 'E3'), /invalid/);
  assert.throws(() => core.gspProve(Buffer.alloc(32), Buffer.alloc(33), Buffer.alloc(33), Buffer.alloc(33), [1n, 2n, 3n, 4n, 5n, 6n]), /invalid/);
  assert.throws(() => core.proveRange([1n, 2n], [1n]), /invalid/);
  for (let i = 0; i < 200; i++) {
    const junk = crypto.randomBytes(Math.floor(Math.random() * 400));
    try { core.mldsaVerify(junk.subarray(0, 1312), junk, junk); } catch { /* erro esperado */ }
    try { core.aesGcmDecrypt(junk.subarray(0, 32), junk.subarray(0, 12), junk, junk.subarray(0, 16)); } catch { /* idem */ }
  }
  assert.ok(mulG(7n).equals(ref(7n, G)), 'still works after all of that');
});

test('wasm core: FCMP — preparation in WebAssembly (sequential and in threads), accepted by the JS verifier', { skip }, async () => {
  const branch = 4, outs = [];
  for (let i = 0; i < 21; i++) { const p = randomScalar(), x = randomScalar(), v = BigInt(700 + i); outs.push({ p, x, v, P: mulG(p), C: commit(v, x) }); }
  const tree = new CurveTree(branch, (i) => ({ key: 'w' + i, P: outs[i].P.toBytes(), C: outs[i].C.toBytes() }));
  const cases = [[21, 6], [3, 2]];
  const args = cases.map(([N, i]) => ({ branch, N, path: tree.pathForChunk(N, Math.floor(i / branch)), leafPos: i % branch, P: outs[i].P, C: outs[i].C }));
  const pres = await parallel.fcmpPrepareMany(args);
  assert.equal(parallel.lastProver, 'wasm-threads');
  cases.forEach(([N, i], k) => {
    const o = outs[i], msg = Buffer.from('wasm ' + N), pm = randomScalar();
    const { proof, keyImage: KI, pseudo } = fcmpFinish(pres[k], { p: o.p, x: o.x, v: o.v, pseudoMask: pm, msg });
    const root = tree.root(N);
    assert.ok(fcmpVerify({ branch, N, root, proof, keyImage: KI, pseudo, msg }), `proof accepted (N=${N})`);
    assert.ok(KI.equals(keyImage(o.p, o.P)));
    assert.ok(!fcmpVerify({ branch, N, root, proof, keyImage: KI, pseudo, msg: Buffer.from('other') }));
  });
  // sequential (as in the browser): header + self-checked halves in a single step
  const blinds = { r1: randomScalar(), r2: 12345n };
  const job = core.fcmpJob({ ...args[1], P: outs[2].P.toBytes(), C: outs[2].C.toBytes() }, blinds);
  const r = core.fcmpPrepare(job);
  assert.ok(r.head.equals(core.fcmpHead(job)));
  assert.ok(r.e1Len > 0 && r.bps.length > r.e1Len);
});

test('without WebAssembly (KREVO_NO_WASM=1): JavaScript takes over, with hedged nonces and verification after signing', () => {
  const code = `
    const core = await import('./src/crypto/wasm.js');
    const { mulG, randomScalar } = await import('./src/crypto/secp256k1.js');
    const { schnorrSign, schnorrVerify } = await import('./src/crypto/schnorr.js');
    const { proveRange, verifyRange } = await import('./src/crypto/bulletproofs.js');
    const x = randomScalar(), m = Buffer.from('m');
    const r = proveRange([42n], [randomScalar()]);
    console.log(JSON.stringify({ wasm: core.available(), sig: schnorrVerify(mulG(x), m, schnorrSign(x, m)), range: verifyRange(r.V, r.proof) }));`;
  const root = fileURLToPath(new URL('..', import.meta.url));
  const out = spawnSync(process.execPath, ['--input-type=module', '-e', code], { cwd: root, env: { ...process.env, KREVO_NO_WASM: '1' }, encoding: 'utf8' });
  assert.equal(out.status, 0, out.stderr);
  assert.deepEqual(JSON.parse(out.stdout), { wasm: false, sig: true, range: true });
});
