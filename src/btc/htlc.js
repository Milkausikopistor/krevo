// Lado Bitcoin da troca atômica: endereço da HTLC e as transações de resgate e reembolso.

import { BtcTx, SIGHASH_ALL } from './tx.js';
import { htlcScript, p2wshScript } from './script.js';
import { encodeSegwit, decodeBtcAddress, sha256 } from './address.js';
import { ecdsaSign, derEncode } from './ecdsa.js';

export const DUST = 546n; // menor saída que qualquer tipo de endereço aceita sem ser "poeira"

/** Contrato HTLC: { script, scriptPubKey, address, locktime }. locktime = horário Unix (CLTV). */
export function btcHtlc(net, { hash, claimPub, refundPub, locktime }) {
  const script = htlcScript({ hash, claimPub, refundPub, locktime });
  return { script, scriptPubKey: p2wshScript(script), address: encodeSegwit(net.hrp, 0, sha256(script)), locktime };
}

/**
 * Gasta todas as `utxos` da HTLC para o endereço `to`.
 *   com `secret` → resgate (revela o segredo na testemunha);
 *   sem `secret` → reembolso (nLockTime = prazo; só vale depois dele).
 * feeRate em sat/vB. Retorna { tx, hex, txid, fee, value }.
 */
export function spendBtcHtlc({ net, htlc, utxos, to, feeRate, key, secret = null }) {
  if (!utxos.length) throw new Error('nada para gastar na HTLC do Bitcoin');
  const refund = !secret;
  if (secret && secret.length !== 32) throw new Error('o segredo precisa ter 32 bytes');
  const dest = decodeBtcAddress(net, to).script;
  const total = utxos.reduce((a, u) => a + BigInt(u.value), 0n);
  const tx = new BtcTx({
    version: 2, locktime: refund ? htlc.locktime : 0,
    inputs: utxos.map((u) => ({ txid: u.txid, vout: u.vout, sequence: refund ? 0xfffffffe : 0xffffffff })),
    outputs: [{ value: total, script: dest }],
  });
  const witnessFor = (sig) => (refund ? [sig, Buffer.alloc(0), htlc.script] : [sig, secret, Buffer.from([1]), htlc.script]);
  tx.inputs.forEach((i) => { i.witness = witnessFor(Buffer.alloc(73)); }); // tamanho máximo, para a taxa
  const fee = BigInt(Math.ceil(tx.vsize * Math.max(1, feeRate)));
  const value = total - fee;
  if (value < DUST) throw new Error(`o valor travado não cobre a taxa do Bitcoin (${total} sat, taxa ${fee} sat)`);
  tx.outputs[0].value = value;
  tx.inputs.forEach((inp, n) => {
    const h = tx.sighashV0(n, htlc.script, BigInt(utxos[n].value), SIGHASH_ALL);
    // key: chave crua (BigInt) ou um assinador do cofre (src/crypto/vault.js)
    const sig = typeof key === 'bigint' ? ecdsaSign(key, h) : key.ecdsa(h);
    inp.witness = witnessFor(Buffer.concat([derEncode(sig), Buffer.from([SIGHASH_ALL])]));
  });
  return { tx, hex: tx.toHex(), txid: tx.txid, fee, value };
}

/** Procura, nas testemunhas de quem gastou a HTLC, o segredo cujo SHA-256 é `hash`. */
export function findSecretInWitnesses(witnesses, hash) {
  for (const w of witnesses) {
    if (w.length === 4 && w[1].length === 32 && sha256(w[1]).equals(hash)) return Buffer.from(w[1]);
  }
  return null;
}
