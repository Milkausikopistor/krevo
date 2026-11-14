// Endereços (Bech32m).
//   transparente: krv1...  dados = [0x00] + chave pública (33)          — valores públicos
//   privado:      krs1...  dados = [0x01] + A (33) + B (33)             — valores e destinatário ocultos
//   visualização: krw1...  dados = [0x02] + a (32) + B (33)             — só leitura, para auditoria
//   multiassinatura: krv1… dados = [0x03] + hash da política M-de-N (32) — transparente, exige M assinaturas
//   quântico:     krq1...  dados = [0x04] + hash(chave Schnorr ‖ chave ML-DSA) (32) — transparente, resistente a quântico
// O prefixo muda por rede (krvdev/krsdev em devnet), evitando enviar para a rede errada.

import { encode, decode } from './util/bech32m.js';
import { Point, scalarFromBytes, scalarToBytes } from './crypto/secp256k1.js';
import { LOCK_NAME, LOCK_NAME_COMMIT, parseNameRecord } from './consensus/names.js';

export const ADDR_TRANSPARENT = 0x00;
export const ADDR_SHIELDED = 0x01;
export const ADDR_VIEWKEY = 0x02;
export const ADDR_MULTISIG = 0x03;
export const ADDR_PQ = 0x04;

/** Dados de endereço transparente = trava (lock) de uma saída transparente. */
export const transparentData = (pubkey) => Buffer.concat([Buffer.from([ADDR_TRANSPARENT]), pubkey.toBytes()]);
export const shieldedData = (A, B) => Buffer.concat([Buffer.from([ADDR_SHIELDED]), A.toBytes(), B.toBytes()]);

/** Interpreta dados de endereço (também usados no payload da coinbase). Lança erro se inválido. */
export function parseAddressData(data) {
  data = Buffer.from(data);
  if (data[0] === ADDR_TRANSPARENT && data.length === 34) {
    return { type: 't', data, pubkey: Point.fromBytes(data.subarray(1)) };
  }
  if (data[0] === ADDR_SHIELDED && data.length === 67) {
    return { type: 's', data, A: Point.fromBytes(data.subarray(1, 34)), B: Point.fromBytes(data.subarray(34)) };
  }
  if (data[0] === ADDR_MULTISIG && data.length === 33) {
    return { type: 'm', data, hash: data.subarray(1) };
  }
  if (data[0] === ADDR_PQ && data.length === 33) {
    return { type: 'q', data, hash: data.subarray(1) };
  }
  // travas que não são endereços: registro de nome (@nome) e compromisso de nome
  if (data[0] === LOCK_NAME) return { type: 'n', data, record: parseNameRecord(data) };
  if (data[0] === LOCK_NAME_COMMIT && data.length === 33) return { type: 'c', data, hash: data.subarray(1) };
  throw new Error('dados de endereço inválidos');
}

/** Texto para exibir uma trava qualquer: o endereço, ou o que ela é (registro/compromisso de nome). */
export function describeLock(params, lock) {
  if (lock[0] === LOCK_NAME) {
    try { return `@${parseNameRecord(lock).name} (registro de nome)`; } catch { return 'registro de nome inválido'; }
  }
  if (lock[0] === LOCK_NAME_COMMIT) return 'compromisso de nome (oculto até a revelação)';
  return encodeAddress(params, lock);
}

const HRP_OF = { t: 't', m: 't', s: 's', q: 'q' };

export function encodeAddress(params, data) {
  const t = data[0];
  if (t === LOCK_NAME || t === LOCK_NAME_COMMIT) throw new Error('esta trava não é um endereço (é um registro de nome)');
  const hrp = t === ADDR_TRANSPARENT || t === ADDR_MULTISIG ? params.hrp.t : t === ADDR_SHIELDED ? params.hrp.s : t === ADDR_PQ ? params.hrp.q : params.hrp.v;
  return encode(hrp, data);
}

export function decodeAddress(params, str) {
  const { hrp, bytes } = decode(str.trim());
  const info = parseAddressData(bytes);
  const expected = params.hrp[HRP_OF[info.type]];
  if (hrp !== expected) throw new Error(`endereço de outra rede ou tipo (prefixo ${hrp}, esperado ${expected})`);
  return info;
}

export function encodeViewKey(params, a, B) {
  return encode(params.hrp.v, Buffer.concat([Buffer.from([ADDR_VIEWKEY]), scalarToBytes(a), B.toBytes()]));
}
export function decodeViewKey(params, str) {
  const { hrp, bytes } = decode(str.trim());
  if (hrp !== params.hrp.v || bytes[0] !== ADDR_VIEWKEY || bytes.length !== 66) throw new Error('chave de visualização inválida');
  return { a: scalarFromBytes(bytes.subarray(1, 33)), B: Point.fromBytes(bytes.subarray(33)) };
}
