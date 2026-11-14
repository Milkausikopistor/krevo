// Endereços furtivos (stealth) com subendereços.
//
// Carteira: chave de visualização a, chave de gasto b, B = b·G.
// Subendereço i (o endereço principal é o subendereço 0):
//   m_i = 0 se i = 0, senão Hs("subaddr", a, i)
//   D_i = B + m_i·G          C_i = a·D_i          endereço_i = (C_i, D_i)
// Todos os endereços têm a MESMA forma: ninguém distingue principal de subendereço,
// nem descobre que dois subendereços são da mesma carteira.
//
// Remetente, para a saída de índice j paga ao endereço (C, D):
//   r_j aleatório POR SAÍDA,  R_j = r_j·D   (publicado na própria saída)
//   ss = r_j·C               (o destinatário calcula a·R_j = a·r_j·D = r_j·C)
//   k  = Hs(ss, j)
//   P  = k·G + D             (chave de uso único)
//   x  = Hs'(ss, j)          (cegamento do compromisso)
//   C  = x·G + v·H, valor cifrado = v XOR H''(ss, j), etiqueta = H'''(ss, j)[0]
//
// Destinatário: ss = a·R_j, D' = P − k·G e procura D' numa tabela de subendereços
// (UMA multiplicação por saída, não importa quantos subendereços existam).
// Chave privada de uso único p = k + b + m_i; imagem de chave I = p·Hp(P).
// Quem tem só (a, B) — a "chave de visualização" — vê entradas de todos os
// subendereços, mas não pode gastar.

import { createCipheriv, createDecipheriv } from 'node:crypto';
import { H } from './hash.js';
import { mulG, hashToScalar, modN } from './secp256k1.js';

/** Escalar do subendereço i (0 para o endereço principal). */
export const subaddressScalar = (a, i) => (i === 0 ? 0n : hashToScalar('stealth/subaddr', a, i));

/** Pontos (C, D) do subendereço i. */
export function subaddressKeys(a, B, i) {
  const m = subaddressScalar(a, i);
  const D = m === 0n ? B : B.add(mulG(m));
  return { index: i, m, D, C: D.mul(a) };
}
import { commit, mulH } from './pedersen.js';
import { u64le } from '../util/bytes.js';

export const sharedSecret = (scalar, point) => point.mul(scalar).toBytes();
export const outputScalar = (ss, i) => hashToScalar('stealth/key', ss, i);
export const viewTag = (ss, i) => H('stealth/tag', ss, i)[0];
export const blindingFactor = (ss, i) => hashToScalar('stealth/blind', ss, i);
const amountMask = (ss, i) => H('stealth/amount', ss, i).subarray(0, 8);

export function encryptAmount(v, ss, i) {
  const b = u64le(v), m = amountMask(ss, i);
  for (let j = 0; j < 8; j++) b[j] ^= m[j];
  return b;
}
export function decryptAmount(enc, ss, i) {
  const b = Buffer.from(enc), m = amountMask(ss, i);
  for (let j = 0; j < 8; j++) b[j] ^= m[j];
  return b.readBigUInt64LE(0);
}

/**
 * Cria a saída privada de índice i para o endereço (A, B) = (C, D) com o segredo r
 * desta saída. coinbase=true usa cegamento zero (o valor da recompensa já é público).
 */
export function makeShieldedOutput({ A, B }, r, i, v, coinbase = false) {
  const R = B.mul(r);
  const ss = sharedSecret(r, A);
  const k = outputScalar(ss, i);
  const P = mulG(k).add(B);
  const x = coinbase ? 0n : blindingFactor(ss, i);
  const C = coinbase ? mulH(v) : commit(v, x);
  return { R, P, C, encAmount: encryptAmount(v, ss, i), viewTag: viewTag(ss, i), x, ss };
}

/**
 * Tenta reconhecer uma saída privada.
 * keys = { a, B, b?, table?, sub? } (chaves cruas: servidor leve, chave de visualização, testes)
 *     ou { vault, B, table } — a carteira: a·R é calculado DENTRO do cofre (src/crypto/vault.js).
 * table: Map(D.hex → índice do subendereço); sem ela, só reconhece o endereço principal.
 * ss: segredo compartilhado já calculado (varredura em lote), opcional.
 * Retorna null se não for nossa; senão { v, x, k, ss, index, p? } (index = subendereço que
 * recebeu; p só com chaves cruas que incluem b — a carteira gasta com keys.spender(k, index)).
 */
export function scanShieldedOutput(keys, R, i, out, ss = null) {
  ss ??= keys.vault ? keys.vault.shared(R) : sharedSecret(keys.a, R);
  if (viewTag(ss, i) !== out.viewTag) return null;
  const k = outputScalar(ss, i);
  const D = out.P.sub(mulG(k));
  let index = 0;
  if (keys.table) {
    index = keys.table.get(D.hex());
    if (index === undefined) return null;
  } else if (!D.equals(keys.B)) return null;
  const v = decryptAmount(out.encAmount, ss, i);
  let x = blindingFactor(ss, i);
  if (!commit(v, x).equals(out.C)) {
    if (mulH(v).equals(out.C)) x = 0n; // saída de coinbase
    else return null; // compromisso não confere: valor corrompido
  }
  const res = { v, x, k, ss, index };
  if (keys.b !== undefined) res.p = modN(k + keys.b + (keys.sub ? keys.sub(index) : subaddressScalar(keys.a, index)));
  return res;
}

// ------------------------------------------------------------------ memos
// Memo criptografado no campo `payload` da transação: AES-256-GCM com chave
// derivada do segredo compartilhado da saída do destinatário. Só quem tem a
// chave de visualização do destinatário (ou o remetente) consegue ler.
//
// Tamanho FIXO (1 + 128 + 16 bytes): toda transação com saída privada leva um
// bloco de memo — vazio quando o usuário não escreve nada —, então quem observa
// a rede não descobre nem SE há uma mensagem, nem o tamanho dela.

export const MEMO_VERSION = 0x01;
export const MEMO_MAX_BYTES = 127;
const MEMO_PLAIN = 128;
export const MEMO_BLOCK_SIZE = 1 + MEMO_PLAIN + 16;
const memoKey = (ss, j) => H('memo/key', ss, j);
const ZERO_IV = Buffer.alloc(12); // a chave é única por (R, destinatário, j): nunca há reuso de nonce

export function encryptMemo(text, ss, j) {
  const msg = Buffer.from(text ?? '', 'utf8');
  if (msg.length > MEMO_MAX_BYTES) throw new Error(`memo longo demais (${msg.length} bytes; máximo ${MEMO_MAX_BYTES})`);
  const plain = Buffer.alloc(MEMO_PLAIN);
  plain[0] = msg.length;
  msg.copy(plain, 1);
  const c = createCipheriv('aes-256-gcm', memoKey(ss, j), ZERO_IV);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([Buffer.from([MEMO_VERSION]), ct, c.getAuthTag()]);
}

/** Retorna o texto (possivelmente vazio) ou null se o bloco não é para esta saída. */
export function decryptMemo(payload, ss, j) {
  if (!payload || payload.length !== MEMO_BLOCK_SIZE || payload[0] !== MEMO_VERSION) return null;
  try {
    const d = createDecipheriv('aes-256-gcm', memoKey(ss, j), ZERO_IV);
    d.setAuthTag(payload.subarray(1 + MEMO_PLAIN));
    const plain = Buffer.concat([d.update(payload.subarray(1, 1 + MEMO_PLAIN)), d.final()]);
    if (plain[0] > MEMO_MAX_BYTES) return null;
    return plain.subarray(1, 1 + plain[0]).toString('utf8');
  } catch {
    return null;
  }
}
