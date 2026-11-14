// Bech32m (BIP-350) — codificação de endereços com soma de verificação forte.
// Sem o limite de 90 caracteres (endereços privados têm 67 bytes de dados).

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
const BECH32M_CONST = 0x2bc830a3;

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
    if (v < 0 || v >> from) throw new Error('bech32m: valor inválido');
    acc = (acc << from) | v; bits += from;
    while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); }
  }
  if (pad) { if (bits) out.push((acc << (to - bits)) & maxv); }
  else if (bits >= from || ((acc << (to - bits)) & maxv)) throw new Error('bech32m: preenchimento inválido');
  return out;
}

export function encode(hrp, bytes) {
  const data = convertBits([...bytes], 8, 5, true);
  const values = [...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0];
  const mod = polymod(values) ^ BECH32M_CONST;
  const checksum = [];
  for (let i = 0; i < 6; i++) checksum.push((mod >>> (5 * (5 - i))) & 31);
  return hrp + '1' + [...data, ...checksum].map((d) => CHARSET[d]).join('');
}

export function decode(str) {
  if (str !== str.toLowerCase() && str !== str.toUpperCase()) throw new Error('bech32m: maiúsculas misturadas');
  str = str.toLowerCase();
  const pos = str.lastIndexOf('1');
  if (pos < 1 || pos + 7 > str.length) throw new Error('bech32m: formato inválido');
  const hrp = str.slice(0, pos);
  const data = [];
  for (const c of str.slice(pos + 1)) {
    const d = CHARSET.indexOf(c);
    if (d < 0) throw new Error('bech32m: caractere inválido');
    data.push(d);
  }
  if (polymod([...hrpExpand(hrp), ...data]) !== BECH32M_CONST) throw new Error('bech32m: soma de verificação inválida');
  return { hrp, bytes: Buffer.from(convertBits(data.slice(0, -6), 5, 8, false)) };
}
