// Prova de pagamento: "a saída j da transação T pagou V KRV ao endereço privado (C, D)".
//
// Quem pagou conhece o segredo r da saída (R = r·D está publicado na própria saída).
// A prova revela apenas S = r·C — o segredo compartilhado DAQUELA saída com AQUELE
// destinatário — e uma prova de igualdade de logaritmos discretos (Chaum–Pedersen /
// DLEQ) de que log_D(R) = log_C(S). Assim:
//   • r continua secreto e nenhuma outra saída da transação (como o troco) é exposta;
//   • nenhuma chave da carteira de quem pagou ou de quem recebeu é revelada;
//   • com S, qualquer pessoa recalcula a saída do destinatário, o valor e o memo;
//   • a prova fica amarrada ao txid, à saída e a uma mensagem opcional (ex.: "pedido 123"),
//     e não pode ser reaproveitada para outro endereço ou mensagem sem conhecer r.

import { modN, randomScalar, hedgedScalar, hashToScalar, scalarToBytes, scalarFromBytes, Point, multiexp, mulG } from '../crypto/secp256k1.js';
import { encode, decode } from '../util/bech32m.js';
import { outputScalar, decryptAmount, blindingFactor, decryptMemo, viewTag } from '../crypto/stealth.js';
import { commit } from '../crypto/pedersen.js';
import { decodeAddress } from '../address.js';

const VERSION = 0x02;

const challenge = (txid, j, R, D, C, S, T1, T2, message) =>
  hashToScalar('proof/payment', txid, j, R, D, C, S, T1, T2, Buffer.from(message ?? '', 'utf8'));

/** Cria a prova. txid: Buffer(32); r: segredo da saída j; address: endereço privado do destinatário. */
export function createPaymentProof(params, { txid, r, j = 0, address, message = '' }) {
  const addr = decodeAddress(params, address);
  if (addr.type !== 's') throw new Error('provas de pagamento são para endereços privados (pagamentos transparentes já são públicos)');
  const D = addr.B, C = addr.A;
  const R = D.mul(r), S = C.mul(r);
  for (;;) {
    const k = hedgedScalar('proof/nonce', scalarToBytes(r), txid, j, D, C, Buffer.from(message ?? '', 'utf8'));
    const c = challenge(txid, j, R, D, C, S, D.mul(k), C.mul(k), message);
    if (c === 0n) continue;
    const s = modN(k - c * r);
    // confere antes de sair (D·s + R·c = D·k e C·s + S·c = C·k)
    if (challenge(txid, j, R, D, C, S, D.mul(s).add(R.mul(c)), C.mul(s).add(S.mul(c)), message) !== c) throw new Error('falha ao criar a prova (verificação)');
    return encode(params.hrp.p, Buffer.concat([Buffer.from([VERSION]), txid, Buffer.from([j]), S.toBytes(), scalarToBytes(c), scalarToBytes(s)]));
  }
}

export function decodePaymentProof(params, str) {
  const { hrp, bytes } = decode(str.trim());
  if (hrp !== params.hrp.p) throw new Error(`prova de outra rede ou formato (prefixo ${hrp}, esperado ${params.hrp.p})`);
  if (bytes.length !== 1 + 32 + 1 + 33 + 64 || bytes[0] !== VERSION) throw new Error('prova malformada');
  return {
    txid: bytes.subarray(1, 33),
    j: bytes[33],
    S: Point.fromBytes(bytes.subarray(34, 67)),
    c: scalarFromBytes(bytes.subarray(67, 99)),
    s: scalarFromBytes(bytes.subarray(99, 131)),
  };
}

/**
 * Verifica contra a transação (obtida de um nó). Retorna
 * { valid, reason?, outputs:[{j, amount}], total, memo }.
 */
export function verifyPaymentProof(params, { proof, address, tx, message = '' }) {
  const no = (reason) => ({ valid: false, reason, outputs: [], total: 0n, memo: null });
  let p, addr;
  try { p = decodePaymentProof(params, proof); } catch (e) { return no(e.message); }
  try { addr = decodeAddress(params, address); } catch (e) { return no(e.message); }
  if (addr.type !== 's') return no('o endereço precisa ser privado (krs1…)');
  if (!p.txid.equals(tx.id)) return no('a prova é de outra transação');
  const o = tx.sOut[p.j];
  if (!o) return no('a transação não tem essa saída privada');
  const D = addr.B, C = addr.A, R = Point.fromBytes(o.R);
  const T1 = multiexp([p.s, p.c], [D, R]);
  const T2 = multiexp([p.s, p.c], [C, p.S]);
  if (challenge(tx.id, p.j, R, D, C, p.S, T1, T2, message) !== p.c) {
    return no('assinatura da prova não confere (prova adulterada, endereço errado ou mensagem diferente)');
  }
  const ss = p.S.toBytes(), j = p.j;
  if (viewTag(ss, j) !== o.viewTag || !mulG(outputScalar(ss, j)).add(D).equals(Point.fromBytes(o.P))) {
    return no('a saída não foi paga a este endereço');
  }
  const amount = decryptAmount(o.encAmount, ss, j);
  if (!commit(amount, blindingFactor(ss, j)).equals(Point.fromBytes(o.C))) return no('valor não confere com o compromisso');
  const memo = j === 0 ? decryptMemo(tx.payload, ss, 0) : null;
  return { valid: true, outputs: [{ j, amount }], total: amount, memo: memo || null };
}
