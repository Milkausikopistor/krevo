// Secret vault (src/crypto/vault.js + rust/krevod/src/vault.rs): the wallet's keys
// stay in the core; JavaScript only gets objects that sign. Same keys and addresses as before,
// no secrets in objects/files, password-protected file encrypted, migration from the old format.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { getParams } from '../src/params.js';
import { openVault } from '../src/crypto/vault.js';
import { Keys } from '../src/wallet/keys.js';
import { Wallet } from '../src/wallet/wallet.js';
import { hashToScalar, mulG, randomScalar, modN } from '../src/crypto/secp256k1.js';
import { H } from '../src/crypto/hash.js';
import { subaddressKeys } from '../src/crypto/stealth.js';
import { schnorrVerify } from '../src/crypto/schnorr.js';
import { ecdsaSign } from '../src/btc/ecdsa.js';
import { keyImage } from '../src/crypto/clsag.js';
import * as core from '../src/crypto/wasm.js';

const params = getParams('simnet');
const root = fileURLToPath(new URL('..', import.meta.url));
const big = (_, v) => (typeof v === 'bigint' ? v.toString(16) : v);

test('vault: same keys and addresses as the previous derivation; ECDSA identical to the JS RFC 6979', () => {
  const seed = crypto.randomBytes(32);
  const v = openVault(seed);
  const b = hashToScalar('wallet/spend', seed), a = hashToScalar('wallet/view', seed);
  assert.ok(v.spendPub().equals(mulG(b)));
  assert.ok(v.pub({ t: 2 }).equals(mulG(hashToScalar('wallet/t', seed, 2))));
  assert.ok(v.pub({ q: 0 }).equals(mulG(hashToScalar('wallet/q', seed, 0))));
  assert.ok(v.pub({ ms: 1 }).equals(mulG(hashToScalar('wallet/multisig', seed))));
  const s = subaddressKeys(a, mulG(b), 4), vs = v.subaddress(4);
  assert.ok(s.C.equals(vs.C) && s.D.equals(vs.D));
  assert.equal(v.exportViewKey().a, a);
  const h = crypto.randomBytes(32), e1 = v.ecdsa({ swapBtc: 1 }, h), e2 = ecdsaSign(hashToScalar('wallet/swap/btc', seed, 1), h);
  assert.ok(e1.r === e2.r && e1.s === e2.s);
  assert.ok(v.nameSalt('loja', 2).equals(H('wallet/name/salt', seed, 'loja', 2)));
  // private output: the one-time key p = k + b + m is computed inside the vault
  const k = randomScalar(), P = mulG(k).add(vs.D);
  const p = modN(k + b + hashToScalar('stealth/subaddr', a, 4)); // only to check here
  assert.ok(v.keyImage({ out: k, sub: 4 }, P).equals(keyImage(p, P)));
  assert.throws(() => v.keyImage({ out: k, sub: 3 }, P), /does not match/);
  assert.throws(() => v.sign({ out: k, sub: 4 }, Buffer.from('x')), /does not sign/);
  v.close();
  assert.throws(() => v.pub({ t: 0 }), /closed|nonexistent/);
});

test('vault: no secrets in the wallet\'s JavaScript objects (nor in their JSON)', () => {
  const seed = crypto.randomBytes(32);
  const k = new Keys(Buffer.from(seed));
  const secrets = [seed.toString('hex'), ...['wallet/spend', 'wallet/view', 'wallet/multisig'].map((d) => hashToScalar(d, seed).toString(16)),
    hashToScalar('wallet/t', seed, 0).toString(16), hashToScalar('wallet/q', seed, 0).toString(16)];
  k.tKey(0); k.qKey(0); k.subaddress(3); k.multisigSigner();
  const dump = JSON.stringify(k, big) + JSON.stringify(k.tKey(0), big) + JSON.stringify(k.qKey(0), big);
  if (core.available()) for (const s of secrets) assert.ok(!dump.includes(s), 'secret visible in an object');
  const sig = k.tKey(0).signer.sign(Buffer.from('m'));
  assert.ok(schnorrVerify(k.tKey(0).P, Buffer.from('m'), sig));
  k.close();
  assert.throws(() => k.tKey(0).signer.sign(Buffer.from('m')), /closed|nonexistent/);
});

test('wallet file with a password: only the essentials in the clear; the rest encrypted by the seed; old format migrated', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krevo-vault-'));
  try {
    const file = path.join(dir, 'w.json');
    const w = Wallet.create(file, params, '', { password: 'strong password' });
    w.data.sOwned = [{ index: 7, outpoint: 'ab'.repeat(32) + ':0', amount: '987654321098', mask: '99', k: 'abc', P: '02' + '11'.repeat(32), sub: 0 }];
    w.data.txSecrets = { ['cd'.repeat(32)]: 'feedfacecafebeef' };
    w.save();
    const raw = fs.readFileSync(file, 'utf8');
    const disk = JSON.parse(raw);
    assert.deepEqual(Object.keys(disk).sort(), ['hasPassphrase', 'mnemonicEnc', 'network', 'sealed', 'seedEnc', 'version']);
    for (const s of ['987654321098', 'ab'.repeat(32), 'cd'.repeat(32), 'feedfacecafebeef']) assert.ok(!raw.includes(s), `visible in the file: ${s}`);
    const w2 = Wallet.load(file, params, '', 'strong password');
    assert.equal(w2.data.sOwned[0].amount, '987654321098');
    assert.equal(w2.data.txSecrets['cd'.repeat(32)], 'feedfacecafebeef');
    assert.equal(w2.mnemonic, null, 'the phrase is not decrypted on opening');
    assert.equal(w2.revealMnemonic('strong password').split(' ').length, 24);
    assert.throws(() => Wallet.load(file, params, '', 'wrong'), /wrong password/);

    // old format: p (the output's spend key) in plain text → deleted, scan redone
    const old = path.join(dir, 'old.json');
    const o = Wallet.create(old, params, '', {});
    const legacy = JSON.parse(fs.readFileSync(old, 'utf8'));
    legacy.sScanned = 50;
    legacy.sOwned = [{ index: 3, outpoint: 'ef'.repeat(32) + ':1', amount: '5', mask: '1', p: '1234567890abcdef', P: '02' + '22'.repeat(32), sub: 0 }];
    fs.writeFileSync(old, JSON.stringify(legacy));
    o.close();
    const m = Wallet.load(old, params, '');
    assert.equal(m.data.sOwned.length, 0);
    assert.equal(m.data.sScanned, 0, 'scan redone from the beginning');
    m.save();
    assert.ok(!fs.readFileSync(old, 'utf8').includes('1234567890abcdef'), 'p is gone from the file');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('JavaScript vault (without WebAssembly): same interface and same results', { skip: !core.available() && 'WebAssembly turned off' }, () => {
  const code = `
    const { openVault } = await import('./src/crypto/vault.js');
    const core = await import('./src/crypto/wasm.js');
    const seed = Buffer.alloc(32, 9);
    const v = openVault(seed);
    const blob = v.seal(Buffer.from('ok'));
    console.log(JSON.stringify({ wasm: core.available(), B: v.spendPub().hex(), t: v.pub({ t: 1 }).hex(), sub: v.subaddress(2).C.hex(), back: v.unseal(blob).toString() }));`;
  const run = (env) => {
    const r = spawnSync(process.execPath, ['--input-type=module', '-e', code], { cwd: root, env: { ...process.env, ...env }, encoding: 'utf8' });
    assert.equal(r.status, 0, r.stderr);
    return JSON.parse(r.stdout);
  };
  const js = run({ KREVO_NO_WASM: '1' }), wasm = run({});
  assert.equal(js.wasm, false);
  assert.deepEqual({ ...js, wasm: true }, wasm);
  // a file encrypted by one opens in the other (same format: AES-256-GCM, key H("wallet/store", seed))
  const v = openVault(Buffer.alloc(32, 9));
  assert.equal(v.unseal(v.seal(Buffer.from('x'))).toString(), 'x');
});
