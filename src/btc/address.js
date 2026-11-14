// Endereços Bitcoin: segwit (Bech32 / Bech32m — BIP-173 e BIP-350) e legados (Base58Check).
// Só o necessário para trocas atômicas: gerar o endereço P2WSH da HTLC e entender qualquer
// endereço de destino que o usuário informar (bc1q…, bc1p…, 1…, 3…).

import { createHash } from 'node:crypto';

export const BTC_NETWORKS = {
  mainnet: { name: 'mainnet', hrp: 'bc', p2pkh: 0x00, p2sh: 0x05, index: 0 },
  testnet: { name: 'testnet', hrp: 'tb', p2pkh: 0x6f, p2sh: 0xc4, index: 1 },
  signet: { name: 'signet', hrp: 'tb', p2pkh: 0x6f, p2sh: 0xc4, index: 2 },
  regtest: { name: 'regtest', hrp: 'bcrt', p2pkh: 0x6f, p2sh: 0xc4, index: 3 },
};
const BY_INDEX = Object.values(BTC_NETWORKS);
const ALIASES = { main: 'mainnet', bitcoin: 'mainnet', test: 'testnet', testnet3: 'testnet', testnet4: 'testnet' };

export function btcNetwork(nameOrIndex) {
  if (typeof nameOrIndex === 'number') {
    const n = BY_INDEX[nameOrIndex];
    if (!n) throw new Error('rede Bitcoin desconhecida');
    return n;
  }
  const n = BTC_NETWORKS[ALIASES[nameOrIndex] ?? nameOrIndex];
  if (!n) throw new Error(`rede Bitcoin desconhecida: ${nameOrIndex} (use mainnet, testnet, signet ou regtest)`);
  return n;
}

export const sha256 = (b) => createHash('sha256').update(b).digest();
export const hash256 = (b) => sha256(sha256(b));
export const hash160 = (b) => createHash('ripemd160').update(sha256(b)).digest();

// ------------------------------------------------------------- Bech32 / Bech32m
const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32 = 1, BECH32M = 0x2bc830a3;

function polymod(values) {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >>> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >>> i) & 1) chk ^= GEN[i];
  }
  return chk >>> 0;
}
const hrpExpand = (hrp) => [...[...hrp].map((c) => c.charCodeAt(0) >> 5), 0, ...[...hrp].map((c) => c.charCodeAt(0) & 31)];

function convertBits(data, from, to, pad) {
  let acc = 0, bits = 0;
  const out = [], maxv = (1 << to) - 1;
  for (const v of data) {
    if (v < 0 || v >> from) return null;
    acc = (acc << from) | v; bits += from;
    while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); }
  }
  if (pad) { if (bits) out.push((acc << (to - bits)) & maxv); }
  else if (bits >= from || ((acc << (to - bits)) & maxv)) return null;
  return out;
}

export function encodeSegwit(hrp, version, program) {
  const data = [version, ...convertBits([...program], 8, 5, true)];
  const spec = version === 0 ? BECH32 : BECH32M;
  const mod = polymod([...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ spec;
  const checksum = Array.from({ length: 6 }, (_, i) => (mod >>> (5 * (5 - i))) & 31);
  return hrp + '1' + [...data, ...checksum].map((d) => CHARSET[d]).join('');
}

export function decodeSegwit(hrp, addr) {
  if (addr.length > 90) throw new Error('endereço Bitcoin longo demais');
  if (addr !== addr.toLowerCase() && addr !== addr.toUpperCase()) throw new Error('endereço Bitcoin com maiúsculas e minúsculas misturadas');
  const s = addr.toLowerCase();
  const pos = s.lastIndexOf('1');
  if (pos < 1 || pos + 7 > s.length) throw new Error('endereço Bitcoin malformado');
  if (s.slice(0, pos) !== hrp) throw new Error(`endereço Bitcoin de outra rede (prefixo ${s.slice(0, pos)}, esperado ${hrp})`);
  const data = [];
  for (const c of s.slice(pos + 1)) {
    const d = CHARSET.indexOf(c);
    if (d < 0) throw new Error('caractere inválido no endereço Bitcoin');
    data.push(d);
  }
  const c = polymod([...hrpExpand(hrp), ...data]);
  const spec = c === BECH32 ? BECH32 : c === BECH32M ? BECH32M : null;
  if (!spec) throw new Error('soma de verificação inválida no endereço Bitcoin');
  if (data.length < 7) throw new Error('endereço Bitcoin sem dados');
  const version = data[0];
  if (version > 16) throw new Error('versão de testemunha inválida');
  const prog = convertBits(data.slice(1, -6), 5, 8, false);
  if (!prog) throw new Error('preenchimento inválido no endereço Bitcoin');
  if (prog.length < 2 || prog.length > 40) throw new Error('programa de testemunha com tamanho inválido');
  if (version === 0 && prog.length !== 20 && prog.length !== 32) throw new Error('programa v0 precisa ter 20 ou 32 bytes');
  if ((version === 0) !== (spec === BECH32)) throw new Error('soma de verificação errada para a versão (Bech32 × Bech32m)');
  return { version, program: Buffer.from(prog) };
}

export const segwitScript = (version, program) =>
  Buffer.concat([Buffer.from([version === 0 ? 0 : 0x50 + version, program.length]), program]);

// ------------------------------------------------------------------ Base58Check
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

export function base58checkEncode(payload) {
  const full = Buffer.concat([payload, hash256(payload).subarray(0, 4)]);
  let n = BigInt('0x' + (full.toString('hex') || '0'));
  let out = '';
  while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of full) { if (b !== 0) break; out = '1' + out; }
  return out;
}

export function base58checkDecode(s) {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error('caractere inválido no endereço Bitcoin');
    n = n * 58n + BigInt(i);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  let bytes = n === 0n ? Buffer.alloc(0) : Buffer.from(hex, 'hex');
  let zeros = 0;
  while (s[zeros] === '1') zeros++;
  bytes = Buffer.concat([Buffer.alloc(zeros), bytes]);
  if (bytes.length < 5) throw new Error('endereço Bitcoin curto demais');
  const payload = bytes.subarray(0, -4);
  if (!hash256(payload).subarray(0, 4).equals(bytes.subarray(-4))) throw new Error('soma de verificação inválida no endereço Bitcoin');
  return Buffer.from(payload);
}

// --------------------------------------------------------------------- geral
/** Endereço → { type, script } (scriptPubKey). Lança erro se for de outra rede ou inválido. */
export function decodeBtcAddress(net, str) {
  const s = String(str).trim();
  if (s.toLowerCase().startsWith(net.hrp + '1')) {
    const { version, program } = decodeSegwit(net.hrp, s);
    const type = version === 0 ? (program.length === 20 ? 'p2wpkh' : 'p2wsh') : version === 1 && program.length === 32 ? 'p2tr' : 'segwit';
    return { type, script: segwitScript(version, program) };
  }
  let payload;
  try { payload = base58checkDecode(s); } catch (e) {
    if (/^(bc|tb|bcrt)1/i.test(s)) throw new Error(`endereço Bitcoin de outra rede (esta troca usa ${net.name})`);
    throw e;
  }
  if (payload.length !== 21) throw new Error('endereço Bitcoin inválido');
  const h = payload.subarray(1);
  if (payload[0] === net.p2pkh) return { type: 'p2pkh', script: Buffer.concat([Buffer.from([0x76, 0xa9, 0x14]), h, Buffer.from([0x88, 0xac])]) };
  if (payload[0] === net.p2sh) return { type: 'p2sh', script: Buffer.concat([Buffer.from([0xa9, 0x14]), h, Buffer.from([0x87])]) };
  throw new Error(`endereço Bitcoin de outra rede (esta troca usa ${net.name})`);
}

/** scriptPubKey → endereço (ou null se não for um tipo padrão). */
export function scriptToAddress(net, script) {
  const s = Buffer.from(script);
  const v = s[0] === 0 ? 0 : s[0] >= 0x51 && s[0] <= 0x60 ? s[0] - 0x50 : -1;
  if (v >= 0 && s.length >= 4 && s[1] === s.length - 2 && s[1] >= 2 && s[1] <= 40) return encodeSegwit(net.hrp, v, s.subarray(2));
  if (s.length === 25 && s[0] === 0x76 && s[1] === 0xa9 && s[2] === 0x14 && s[23] === 0x88 && s[24] === 0xac) {
    return base58checkEncode(Buffer.concat([Buffer.from([net.p2pkh]), s.subarray(3, 23)]));
  }
  if (s.length === 23 && s[0] === 0xa9 && s[1] === 0x14 && s[22] === 0x87) {
    return base58checkEncode(Buffer.concat([Buffer.from([net.p2sh]), s.subarray(2, 22)]));
  }
  return null;
}

/** Endereço P2WPKH (bc1q…) de uma chave pública comprimida. */
export const p2wpkhAddress = (net, pub33) => encodeSegwit(net.hrp, 0, hash160(pub33));
