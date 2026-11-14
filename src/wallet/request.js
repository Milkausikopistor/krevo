// Pedido de pagamento: link "krevo:" no estilo do BIP-21 do Bitcoin, pronto para QR code.
//
//   krevo:<endereço>?amount=2.5&memo=Pedido%20123&label=Padaria%20Sol&exp=1794500000
//   krevo:@padaria?amount=2.5      — também com um nome registrado na rede (resolvido ao pagar)
//
//   amount — valor em KRV (ponto decimal)          memo  — vai cifrado no pagamento (só endereço privado)
//   label  — nome de quem cobra (só exibido)       exp   — expira em (segundos Unix)
// Parâmetros desconhecidos são ignorados, exceto os que começam com "req-"
// (obrigatórios): esses fazem a carteira recusar o link, como no BIP-21.
// A rede é verificada pelo prefixo do endereço (krv/krs na mainnet, krvdev/krsdev na devnet…).

import { randomBytes } from 'node:crypto';
import { decodeAddress } from '../address.js';
import { checkName } from '../consensus/names.js';
import { COIN, parseKRV } from '../params.js';
import { MEMO_MAX_BYTES } from '../crypto/stealth.js';

export const URI_SCHEME = 'krevo';

export function formatAmountURI(grains) {
  const w = grains / COIN, f = (grains % COIN).toString().padStart(8, '0').replace(/0+$/, '');
  return f ? `${w}.${f}` : `${w}`;
}

function checkMemo(memo, type) {
  if (!memo) return;
  if (type !== 's') throw new Error('memo só é possível em cobranças para endereço privado (krs1…)');
  if (Buffer.byteLength(memo, 'utf8') > MEMO_MAX_BYTES) throw new Error(`memo longo demais (máximo ${MEMO_MAX_BYTES} bytes)`);
}

export function buildPaymentURI(params, { address, amount = null, memo = null, label = null, expires = null }) {
  if (String(address).startsWith('@')) address = '@' + checkName(address);
  else checkMemo(memo, decodeAddress(params, address).type);
  if (amount !== null && amount <= 0n) throw new Error('valor da cobrança precisa ser positivo');
  const q = [];
  if (amount !== null) q.push('amount=' + formatAmountURI(amount));
  if (memo) q.push('memo=' + encodeURIComponent(memo));
  if (label) q.push('label=' + encodeURIComponent(label));
  if (expires) q.push('exp=' + Math.floor(expires));
  return `${URI_SCHEME}:${address}` + (q.length ? '?' + q.join('&') : '');
}

export function parsePaymentURI(params, uri) {
  const m = /^krevo:([^?]+)(?:\?(.*))?$/i.exec(String(uri).trim());
  if (!m) throw new Error('link de pagamento inválido (precisa começar com "krevo:")');
  let address = decodeURIComponent(m[1]);
  // @nome: resolvido na hora de pagar (o memo só vale se o nome apontar para um endereço privado)
  const isName = address.startsWith('@');
  if (isName) address = '@' + checkName(address);
  const type = isName ? 'n' : decodeAddress(params, address).type; // valida checksum e rede
  const out = { address, type, amount: null, memo: null, label: null, expires: null };
  for (const part of (m[2] ?? '').split('&')) {
    if (!part) continue;
    const i = part.indexOf('=');
    const k = decodeURIComponent(i < 0 ? part : part.slice(0, i));
    const v = i < 0 ? '' : decodeURIComponent(part.slice(i + 1).replace(/\+/g, ' '));
    if (k === 'amount') {
      out.amount = parseKRV(v);
      if (out.amount <= 0n) throw new Error('valor do link precisa ser positivo');
    } else if (k === 'memo') out.memo = v;
    else if (k === 'label') out.label = v;
    else if (k === 'exp') {
      if (!/^\d+$/.test(v)) throw new Error('data de expiração inválida no link');
      out.expires = Number(v);
    } else if (k.startsWith('req-')) throw new Error(`o link exige um recurso desconhecido ("${k}"); atualize a carteira`);
  }
  if (!isName) checkMemo(out.memo, type);
  return out;
}

export const isExpired = (req, now = Date.now()) => !!req.expires && now / 1000 > req.expires;

/** Código curto e único para identificar o pedido (ex.: KRV-7F3K9Q). */
export function newOrderCode() {
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford: sem I, L, O, U
  return 'KRV-' + [...randomBytes(6)].map((b) => alphabet[b & 31]).join('');
}
