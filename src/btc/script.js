// Script do Bitcoin: codificação de dados/números e o contrato HTLC da troca atômica.
//
// HTLC ("contrato com trava de hash e de tempo"), o mesmo formato usado por trocas atômicas
// desde 2017 (BIP-199):
//
//   OP_IF
//       OP_SIZE 32 OP_EQUALVERIFY OP_SHA256 <hash> OP_EQUALVERIFY <chave de quem resgata>
//   OP_ELSE
//       <prazo> OP_CHECKLOCKTIMEVERIFY OP_DROP <chave de quem reembolsa>
//   OP_ENDIF
//   OP_CHECKSIG
//
//   resgate:    <assinatura> <segredo de 32 bytes> 01 <script>
//   reembolso:  <assinatura> <vazio> <script>          (só depois do prazo: nLockTime ≥ prazo)
//
// OP_SIZE 32 obriga o segredo a ter exatamente 32 bytes — a Krevo exige o mesmo; sem isso, um
// segredo de tamanho aceito numa rede e recusado na outra poderia travar a troca.

import { sha256 } from './address.js';

export const OP = {
  OP_0: 0x00, OP_PUSHDATA1: 0x4c, OP_PUSHDATA2: 0x4d, OP_1NEGATE: 0x4f, OP_1: 0x51, OP_16: 0x60,
  OP_IF: 0x63, OP_NOTIF: 0x64, OP_ELSE: 0x67, OP_ENDIF: 0x68, OP_VERIFY: 0x69, OP_DROP: 0x75,
  OP_DUP: 0x76, OP_SIZE: 0x82, OP_EQUAL: 0x87, OP_EQUALVERIFY: 0x88, OP_SHA256: 0xa8,
  OP_HASH160: 0xa9, OP_CHECKSIG: 0xac, OP_CHECKLOCKTIMEVERIFY: 0xb1, OP_CHECKSEQUENCEVERIFY: 0xb2,
};

/** Empilhar dados com a codificação mínima. */
export function pushData(b) {
  b = Buffer.from(b);
  if (b.length === 0) return Buffer.from([OP.OP_0]);
  if (b.length <= 75) return Buffer.concat([Buffer.from([b.length]), b]);
  if (b.length <= 255) return Buffer.concat([Buffer.from([OP.OP_PUSHDATA1, b.length]), b]);
  if (b.length <= 520) { const l = Buffer.alloc(2); l.writeUInt16LE(b.length); return Buffer.concat([Buffer.from([OP.OP_PUSHDATA2]), l, b]); }
  throw new Error('dado grande demais para o script');
}

/** Número de script (little-endian, bit de sinal, mínimo). */
export function scriptNum(n) {
  n = BigInt(n);
  if (n === 0n) return Buffer.alloc(0);
  const neg = n < 0n;
  let a = neg ? -n : n;
  const out = [];
  while (a > 0n) { out.push(Number(a & 0xffn)); a >>= 8n; }
  if (out[out.length - 1] & 0x80) out.push(neg ? 0x80 : 0);
  else if (neg) out[out.length - 1] |= 0x80;
  return Buffer.from(out);
}

export function decodeScriptNum(b, maxLen = 4) {
  if (b.length > maxLen) throw new Error('número de script grande demais');
  if (b.length && (b[b.length - 1] & 0x7f) === 0 && (b.length === 1 || !(b[b.length - 2] & 0x80))) throw new Error('número de script não mínimo');
  let v = 0n;
  for (let i = b.length - 1; i >= 0; i--) v = (v << 8n) | BigInt(i === b.length - 1 ? b[i] & 0x7f : b[i]);
  return b.length && b[b.length - 1] & 0x80 ? -v : v;
}

export function pushNum(n) {
  n = Number(n);
  if (n === 0) return Buffer.from([OP.OP_0]);
  if (n === -1) return Buffer.from([OP.OP_1NEGATE]);
  if (n >= 1 && n <= 16) return Buffer.from([OP.OP_1 + n - 1]);
  return pushData(scriptNum(n));
}

export function htlcScript({ hash, claimPub, refundPub, locktime }) {
  if (hash.length !== 32 || claimPub.length !== 33 || refundPub.length !== 33) throw new Error('parâmetros da HTLC inválidos');
  if (!Number.isInteger(locktime) || locktime <= 0 || locktime >= 2 ** 31) throw new Error('prazo da HTLC inválido');
  return Buffer.concat([
    Buffer.from([OP.OP_IF, OP.OP_SIZE]), pushNum(32), Buffer.from([OP.OP_EQUALVERIFY, OP.OP_SHA256]),
    pushData(hash), Buffer.from([OP.OP_EQUALVERIFY]), pushData(claimPub),
    Buffer.from([OP.OP_ELSE]), pushNum(locktime), Buffer.from([OP.OP_CHECKLOCKTIMEVERIFY, OP.OP_DROP]), pushData(refundPub),
    Buffer.from([OP.OP_ENDIF, OP.OP_CHECKSIG]),
  ]);
}

/** scriptPubKey P2WSH (versão 0 + SHA-256 do script). */
export const p2wshScript = (witnessScript) => Buffer.concat([Buffer.from([0x00, 0x20]), sha256(witnessScript)]);

/** Decompõe um script em operações: [{ op, data? }]. */
export function parseScript(script) {
  const s = Buffer.from(script), ops = [];
  let pc = 0;
  while (pc < s.length) {
    const op = s[pc++];
    let len = -1;
    if (op >= 1 && op <= 75) len = op;
    else if (op === OP.OP_PUSHDATA1) { if (pc + 1 > s.length) throw new Error('script truncado'); len = s[pc++]; }
    else if (op === OP.OP_PUSHDATA2) { if (pc + 2 > s.length) throw new Error('script truncado'); len = s.readUInt16LE(pc); pc += 2; }
    if (len >= 0) {
      if (pc + len > s.length) throw new Error('script truncado');
      ops.push({ op, data: Buffer.from(s.subarray(pc, pc + len)) });
      pc += len;
    } else ops.push({ op });
  }
  return ops;
}
