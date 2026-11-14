import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {
  entropyToMnemonic, mnemonicToEntropy, mnemonicToSeed, generateMnemonic, normalizeMnemonic, validateMnemonic,
} from '../src/wallet/bip39.js';
import { WORDS } from '../src/wallet/wordlist-en.js';
import { Wallet } from '../src/wallet/wallet.js';
import { getParams } from '../src/params.js';

// Vetores oficiais do BIP-39 (trezor/python-mnemonic, frase extra "TREZOR").
const VECTORS = [
  ['00000000000000000000000000000000', 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
    'c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04'],
  ['7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f', 'legal winner thank year wave sausage worth useful legal winner thank yellow',
    '2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607'],
  ['80808080808080808080808080808080', 'letter advice cage absurd amount doctor acoustic avoid letter advice cage above',
    'd71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8'],
  ['ffffffffffffffffffffffffffffffff', 'zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong',
    'ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069'],
  ['0000000000000000000000000000000000000000000000000000000000000000', 'abandon '.repeat(23) + 'art',
    'bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8'],
  ['ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff', 'zoo '.repeat(23) + 'vote',
    'dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad'],
];

test('bip39: lista oficial de 2048 palavras', () => {
  assert.equal(WORDS.length, 2048);
  assert.equal(WORDS[0], 'abandon');
  assert.equal(WORDS[2047], 'zoo');
});

test('bip39: vetores oficiais (frase e semente)', () => {
  for (const [ent, phrase, seed] of VECTORS) {
    assert.equal(entropyToMnemonic(Buffer.from(ent, 'hex')), phrase);
    assert.equal(mnemonicToEntropy(phrase).toString('hex'), ent);
    assert.equal(mnemonicToSeed(phrase, 'TREZOR').toString('hex'), seed);
  }
});

test('bip39: geração, prefixos de 4 letras e detecção de erros', () => {
  for (const n of [12, 24]) {
    const m = generateMnemonic(n);
    assert.equal(m.split(' ').length, n);
    assert.ok(validateMnemonic(m));
    // aceita só as 4 primeiras letras, maiúsculas e espaços extras
    const short = '  ' + m.split(' ').map((w) => w.slice(0, 4).toUpperCase()).join('   ') + ' ';
    assert.equal(normalizeMnemonic(short), m);
  }
  const m = generateMnemonic(24).split(' ');
  // trocar a última palavra por outra quase sempre quebra o checksum
  let broken = 0;
  for (let i = 0; i < 50; i++) {
    const alt = [...m.slice(0, 23), WORDS[(WORDS.indexOf(m[23]) + 1 + i) % 2048]].join(' ');
    if (!validateMnemonic(alt)) broken++;
  }
  assert.ok(broken >= 40, `checksum detectou ${broken}/50 alterações`);
  assert.throws(() => normalizeMnemonic(m.slice(0, 23).join(' ')), /23 palavras/);
  assert.throws(() => normalizeMnemonic([...m.slice(0, 5), 'xyzzy', ...m.slice(6)].join(' ')), /palavra 6/);
});

test('carteira: restaurar pela frase recria exatamente as mesmas chaves', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'krv-bip39-'));
  const params = getParams('devnet');
  const a = Wallet.create(path.join(dir, 'a.json'), params, '', { password: 'x' });
  assert.equal(a.mnemonic.split(' ').length, 24);
  const b = Wallet.restore(path.join(dir, 'b.json'), params, '', { mnemonic: a.mnemonic });
  assert.equal(b.tAddress, a.tAddress);
  assert.equal(b.sAddress, a.sAddress);
  assert.equal(b.keys.viewKey(params), a.keys.viewKey(params));
  // a frase fica cifrada no arquivo quando há senha
  assert.ok(!fs.readFileSync(path.join(dir, 'a.json'), 'utf8').includes(a.mnemonic.split(' ')[0] + ' '));
  // frase extra diferente → carteira diferente (proteção extra contra roubo da frase)
  const c = Wallet.restore(path.join(dir, 'c.json'), params, '', { mnemonic: a.mnemonic, passphrase: 'segredo' });
  assert.notEqual(c.tAddress, a.tAddress);
  // não sobrescreve um arquivo existente
  assert.throws(() => Wallet.restore(path.join(dir, 'a.json'), params, '', { mnemonic: a.mnemonic }), /já existe/);
  // os vetores oficiais também funcionam como frase de carteira
  const v = Wallet.restore(path.join(dir, 'v.json'), params, '', { mnemonic: VECTORS[0][1] });
  assert.match(v.tAddress, /^krvdev1/);
});
