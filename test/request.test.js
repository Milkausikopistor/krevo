import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { encodeQR, qrToSvg, qrToTerminal, rsRemainder } from '../src/util/qrcode.js';
import { buildPaymentURI, parsePaymentURI, isExpired, newOrderCode } from '../src/wallet/request.js';
import { getParams, COIN } from '../src/params.js';
import { Keys } from '../src/wallet/keys.js';

const dev = getParams('devnet'), main = getParams('mainnet');
const fp = (q) => createHash('sha256').update(q.modules.map((r) => r.map((b) => (b ? 1 : 0)).join('')).join(',')).digest('hex').slice(0, 16);

// Estes 6 códigos foram decodificados com sucesso por um leitor independente (jsQR)
// antes de virarem referência; o teste garante que o gerador não muda sem querer.
const GOLDEN = [
  ['HELLO', 'M', 1, 'bb3fad50cced8728'],
  ['krevo:krsdev1qypvqxz4ed28hsffz7zp03jdcdacwam5k337rzgaw4gd6t3vm57huwsrd83tc527c29fgfa4p9u8n7hpy6esq3f5purjku65w535460gzetqe5hmp7?amount=2.5&memo=Pedido%20123&label=Loja%20X', 'M', 9, 'f869d0053675877b'],
  ['krevo:krv1qqp7uehakekvu95lrnx5c2r56vucfnzxlsej86n65nzyhk8ea8799qcqxwh4s?amount=0.001&label=Caf%C3%A9%20S%C3%A3o%20Jo%C3%A3o', 'Q', 9, 'db40ae229a0c5a72'],
  ['Pagamento: São João — ação ✓ ' + 'x'.repeat(330), 'M', 15, '0f0604e640310c2d'],
  ['LOW-ECC test ' + '0123456789'.repeat(12), 'L', 6, 'c86f70ea0f3a3a60'],
  ['HIGH-ECC test ' + 'abcdef'.repeat(15), 'H', 10, '41a1a05eba776b8b'],
];

test('qr: códigos verificados por leitor independente continuam idênticos', () => {
  for (const [text, level, version, hash] of GOLDEN) {
    const q = encodeQR(text, level);
    assert.equal(q.version, version, text.slice(0, 20));
    assert.equal(fp(q), hash, `matriz mudou para "${text.slice(0, 20)}…"`);
  }
});

test('qr: estrutura (informação de formato BCH, módulo escuro, Reed–Solomon)', () => {
  for (const text of ['a', 'krevo:teste?amount=1', 'z'.repeat(200)]) {
    const q = encodeQR(text, 'M'), n = q.size, m = q.modules;
    assert.equal(n, 17 + 4 * q.version);
    assert.ok(m[n - 8][8], 'módulo escuro fixo');
    // formato: 15 bits ao redor do localizador superior esquerdo
    let bits = 0;
    for (let i = 0; i <= 5; i++) bits |= (m[i][8] ? 1 : 0) << i;
    bits |= (m[7][8] ? 1 : 0) << 6; bits |= (m[8][8] ? 1 : 0) << 7; bits |= (m[8][7] ? 1 : 0) << 8;
    for (let i = 9; i < 15; i++) bits |= (m[8][14 - i] ? 1 : 0) << i;
    const raw = bits ^ 0x5412;
    let rem = raw;
    for (let i = 14; i >= 10; i--) if ((rem >>> i) & 1) rem ^= 0x537 << (i - 10);
    assert.equal(rem, 0, 'código BCH do formato válido');
    assert.equal(raw >>> 13, 0, 'nível M'); assert.equal((raw >>> 10) & 7, q.mask);
  }
  // Reed–Solomon: dados + paridade formam um código sem resto
  const data = [0x40, 0x11, 0x20, 0xec, 0x11, 0xec, 0x11, 0xec, 0x11];
  const gen = (deg) => { const r = new Array(deg).fill(0); r[deg - 1] = 1; return r; };
  assert.equal(rsRemainder(data, gen(1)).length, 1);
  const q = encodeQR('HELLO'); assert.ok(qrToTerminal(q).includes('▀'));
});

test('cobrança: link krevo: ida e volta, validações e QR em SVG', () => {
  const k = Keys.random();
  const s = k.sAddress(dev), t = k.tAddress(dev);
  const memo = 'Pedido nº 7 & cia = 100% ✓ + extras?';
  const uri = buildPaymentURI(dev, { address: s, amount: 250_000_001n, memo, label: 'Padaria Sol', expires: 2_000_000_000 });
  assert.match(uri, /^krevo:krsdev1[^?]+\?amount=2\.50000001&memo=/);
  const r = parsePaymentURI(dev, uri);
  assert.deepEqual([r.address, r.type, r.amount, r.memo, r.label, r.expires], [s, 's', 250_000_001n, memo, 'Padaria Sol', 2_000_000_000]);
  assert.equal(parsePaymentURI(dev, uri.replace('krevo:', 'KREVO:')).memo, memo, 'esquema sem diferenciar maiúsculas');
  assert.equal(parsePaymentURI(dev, `krevo:${t}?amount=1&futuro=x`).amount, COIN, 'parâmetro desconhecido é ignorado');
  assert.equal(parsePaymentURI(dev, `krevo:${t}`).amount, null);
  assert.throws(() => parsePaymentURI(dev, `krevo:${t}?req-algo=1`), /recurso desconhecido/);
  assert.throws(() => buildPaymentURI(dev, { address: t, amount: COIN, memo: 'x' }), /privado/);
  assert.throws(() => parsePaymentURI(dev, `krevo:${t}?memo=oi`), /privado/);
  assert.throws(() => parsePaymentURI(main, uri), /outra rede/, 'link da devnet recusado na mainnet');
  assert.throws(() => parsePaymentURI(dev, `bitcoin:${t}`), /krevo:/);
  assert.throws(() => parsePaymentURI(dev, `krevo:${t}?amount=-1`));
  const typo = uri[20] === 'x' ? 'y' : 'x'; // um caractere DIFERENTE do original (antes: falhava 1 vez em 32)
  assert.throws(() => parsePaymentURI(dev, uri.slice(0, 20) + typo + uri.slice(21)), 'checksum do endereço');
  assert.ok(isExpired({ expires: 1 }));
  assert.ok(!isExpired({ expires: null }));
  assert.match(newOrderCode(), /^KRV-[0-9A-HJKMNP-TV-Z]{6}$/);
  const svg = qrToSvg(encodeQR(uri), { caption: ['Padaria <Sol>', '2,5 KRV'] });
  assert.ok(svg.startsWith('<?xml') && svg.includes('<svg') && svg.includes('Padaria &lt;Sol&gt;'));
});
