// Cofre de segredos (src/crypto/vault.js + rust/krevod/src/vault.rs): as chaves da carteira
// ficam no núcleo; o JavaScript só recebe quem assina. Mesmas chaves e endereços de antes,
// nada de segredo em objetos/arquivos, arquivo com senha cifrado, migração do formato antigo.
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

test('cofre: mesmas chaves e endereços da derivação anterior; ECDSA idêntico ao RFC 6979 do JS', () => {
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
  // saída privada: a chave de uso único p = k + b + m é calculada dentro do cofre
  const k = randomScalar(), P = mulG(k).add(vs.D);
  const p = modN(k + b + hashToScalar('stealth/subaddr', a, 4)); // só para conferir aqui
  assert.ok(v.keyImage({ out: k, sub: 4 }, P).equals(keyImage(p, P)));
  assert.throws(() => v.keyImage({ out: k, sub: 3 }, P), /não corresponde/);
  assert.throws(() => v.sign({ out: k, sub: 4 }, Buffer.from('x')), /não assina/);
  v.close();
  assert.throws(() => v.pub({ t: 0 }), /fechado|inexistente/);
});

test('cofre: nenhum segredo nos objetos JavaScript da carteira (nem no JSON deles)', () => {
  const seed = crypto.randomBytes(32);
  const k = new Keys(Buffer.from(seed));
  const secrets = [seed.toString('hex'), ...['wallet/spend', 'wallet/view', 'wallet/multisig'].map((d) => hashToScalar(d, seed).toString(16)),
    hashToScalar('wallet/t', seed, 0).toString(16), hashToScalar('wallet/q', seed, 0).toString(16)];
  k.tKey(0); k.qKey(0); k.subaddress(3); k.multisigSigner();
  const dump = JSON.stringify(k, big) + JSON.stringify(k.tKey(0), big) + JSON.stringify(k.qKey(0), big);
  if (core.available()) for (const s of secrets) assert.ok(!dump.includes(s), 'segredo à vista num objeto');
  const sig = k.tKey(0).signer.sign(Buffer.from('m'));
  assert.ok(schnorrVerify(k.tKey(0).P, Buffer.from('m'), sig));
  k.close();
  assert.throws(() => k.tKey(0).signer.sign(Buffer.from('m')), /fechado|inexistente/);
});

test('arquivo da carteira com senha: só o essencial à vista; o resto cifrado pela semente; formato antigo migrado', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krevo-cofre-'));
  try {
    const file = path.join(dir, 'w.json');
    const w = Wallet.create(file, params, '', { password: 'senha forte' });
    w.data.sOwned = [{ index: 7, outpoint: 'ab'.repeat(32) + ':0', amount: '123456', mask: '99', k: 'abc', P: '02' + '11'.repeat(32), sub: 0 }];
    w.data.txSecrets = { ['cd'.repeat(32)]: 'ffee' };
    w.save();
    const raw = fs.readFileSync(file, 'utf8');
    const disk = JSON.parse(raw);
    assert.deepEqual(Object.keys(disk).sort(), ['hasPassphrase', 'mnemonicEnc', 'network', 'sealed', 'seedEnc', 'version']);
    for (const s of ['123456', 'ab'.repeat(32), 'cd'.repeat(32), 'ffee']) assert.ok(!raw.includes(s), `à vista no arquivo: ${s}`);
    const w2 = Wallet.load(file, params, '', 'senha forte');
    assert.equal(w2.data.sOwned[0].amount, '123456');
    assert.equal(w2.data.txSecrets['cd'.repeat(32)], 'ffee');
    assert.equal(w2.mnemonic, null, 'a frase não é decifrada ao abrir');
    assert.equal(w2.revealMnemonic('senha forte').split(' ').length, 24);
    assert.throws(() => Wallet.load(file, params, '', 'errada'), /senha incorreta/);

    // formato antigo: p (chave de gasto da saída) em texto puro → apagado, varredura refeita
    const old = path.join(dir, 'old.json');
    const o = Wallet.create(old, params, '', {});
    const legacy = JSON.parse(fs.readFileSync(old, 'utf8'));
    legacy.sScanned = 50;
    legacy.sOwned = [{ index: 3, outpoint: 'ef'.repeat(32) + ':1', amount: '5', mask: '1', p: '1234567890abcdef', P: '02' + '22'.repeat(32), sub: 0 }];
    fs.writeFileSync(old, JSON.stringify(legacy));
    o.close();
    const m = Wallet.load(old, params, '');
    assert.equal(m.data.sOwned.length, 0);
    assert.equal(m.data.sScanned, 0, 'varredura refeita desde o início');
    m.save();
    assert.ok(!fs.readFileSync(old, 'utf8').includes('1234567890abcdef'), 'p sumiu do arquivo');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('cofre em JavaScript (sem WebAssembly): mesma interface e mesmos resultados', { skip: !core.available() && 'WebAssembly desligado' }, () => {
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
  // o arquivo cifrado por um abre no outro (mesmo formato: AES-256-GCM, chave H("wallet/store", semente))
  const v = openVault(Buffer.alloc(32, 9));
  assert.equal(v.unseal(v.seal(Buffer.from('x'))).toString(), 'x');
});
