// Payment request: "krevo:" link in the style of Bitcoin's BIP-21, ready for a QR code.
//
//   krevo:<address>?amount=2.5&memo=Order%20123&label=Sun%20Bakery&exp=1794500000
//   krevo:@bakery?amount=2.5      — also with a name registered on the network (resolved when paying)
//
//   amount — amount in KRV (decimal point)        memo  — goes encrypted in the payment (private address only)
//   label  — name of the requester (display only)  exp   — expires at (Unix seconds)
// Unknown parameters are ignored, except those starting with "req-"
// (mandatory): those make the wallet refuse the link, as in BIP-21.
// The network is checked by the address prefix (krv/krs on mainnet, krvdev/krsdev on devnet…).

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
  if (type !== 's') throw new Error('a memo is only possible in requests to a private address (krs1…)');
  if (Buffer.byteLength(memo, 'utf8') > MEMO_MAX_BYTES) throw new Error(`memo too long (maximum ${MEMO_MAX_BYTES} bytes)`);
}

export function buildPaymentURI(params, { address, amount = null, memo = null, label = null, expires = null }) {
  if (String(address).startsWith('@')) address = '@' + checkName(address);
  else checkMemo(memo, decodeAddress(params, address).type);
  if (amount !== null && amount <= 0n) throw new Error('the requested amount must be positive');
  const q = [];
  if (amount !== null) q.push('amount=' + formatAmountURI(amount));
  if (memo) q.push('memo=' + encodeURIComponent(memo));
  if (label) q.push('label=' + encodeURIComponent(label));
  if (expires) q.push('exp=' + Math.floor(expires));
  return `${URI_SCHEME}:${address}` + (q.length ? '?' + q.join('&') : '');
}

export function parsePaymentURI(params, uri) {
  const m = /^krevo:([^?]+)(?:\?(.*))?$/i.exec(String(uri).trim());
  if (!m) throw new Error('invalid payment link (it must start with "krevo:")');
  let address = decodeURIComponent(m[1]);
  // @name: resolved at payment time (the memo only applies if the name points to a private address)
  const isName = address.startsWith('@');
  if (isName) address = '@' + checkName(address);
  const type = isName ? 'n' : decodeAddress(params, address).type; // validates checksum and network
  const out = { address, type, amount: null, memo: null, label: null, expires: null };
  for (const part of (m[2] ?? '').split('&')) {
    if (!part) continue;
    const i = part.indexOf('=');
    const k = decodeURIComponent(i < 0 ? part : part.slice(0, i));
    const v = i < 0 ? '' : decodeURIComponent(part.slice(i + 1).replace(/\+/g, ' '));
    if (k === 'amount') {
      out.amount = parseKRV(v);
      if (out.amount <= 0n) throw new Error('the link amount must be positive');
    } else if (k === 'memo') out.memo = v;
    else if (k === 'label') out.label = v;
    else if (k === 'exp') {
      if (!/^\d+$/.test(v)) throw new Error('invalid expiry date in the link');
      out.expires = Number(v);
    } else if (k.startsWith('req-')) throw new Error(`the link requires an unknown feature ("${k}"); update the wallet`);
  }
  if (!isName) checkMemo(out.memo, type);
  return out;
}

export const isExpired = (req, now = Date.now()) => !!req.expires && now / 1000 > req.expires;

/** Short unique code to identify the request (e.g. KRV-7F3K9Q). */
export function newOrderCode() {
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford: no I, L, O, U
  return 'KRV-' + [...randomBytes(6)].map((b) => alphabet[b & 31]).join('');
}
