// Bitcoin side of the atomic swap: the HTLC address and the claim and refund transactions.

import { BtcTx, SIGHASH_ALL } from './tx.js';
import { htlcScript, p2wshScript } from './script.js';
import { encodeSegwit, decodeBtcAddress, sha256 } from './address.js';
import { ecdsaSign, derEncode } from './ecdsa.js';

export const DUST = 546n; // smallest output any address type accepts without being "dust"

/** HTLC contract: { script, scriptPubKey, address, locktime }. locktime = Unix time (CLTV). */
export function btcHtlc(net, { hash, claimPub, refundPub, locktime }) {
  const script = htlcScript({ hash, claimPub, refundPub, locktime });
  return { script, scriptPubKey: p2wshScript(script), address: encodeSegwit(net.hrp, 0, sha256(script)), locktime };
}

/**
 * Spends all the HTLC's `utxos` to the address `to`.
 *   with `secret` → claim (reveals the secret in the witness);
 *   without `secret` → refund (nLockTime = deadline; only valid after it).
 * feeRate in sat/vB. Returns { tx, hex, txid, fee, value }.
 */
export function spendBtcHtlc({ net, htlc, utxos, to, feeRate, key, secret = null }) {
  if (!utxos.length) throw new Error('nothing to spend in the Bitcoin HTLC');
  const refund = !secret;
  if (secret && secret.length !== 32) throw new Error('the secret must have 32 bytes');
  const dest = decodeBtcAddress(net, to).script;
  const total = utxos.reduce((a, u) => a + BigInt(u.value), 0n);
  const tx = new BtcTx({
    version: 2, locktime: refund ? htlc.locktime : 0,
    inputs: utxos.map((u) => ({ txid: u.txid, vout: u.vout, sequence: refund ? 0xfffffffe : 0xffffffff })),
    outputs: [{ value: total, script: dest }],
  });
  const witnessFor = (sig) => (refund ? [sig, Buffer.alloc(0), htlc.script] : [sig, secret, Buffer.from([1]), htlc.script]);
  tx.inputs.forEach((i) => { i.witness = witnessFor(Buffer.alloc(73)); }); // maximum size, for the fee
  const fee = BigInt(Math.ceil(tx.vsize * Math.max(1, feeRate)));
  const value = total - fee;
  if (value < DUST) throw new Error(`the locked amount does not cover the Bitcoin fee (${total} sat, fee ${fee} sat)`);
  tx.outputs[0].value = value;
  tx.inputs.forEach((inp, n) => {
    const h = tx.sighashV0(n, htlc.script, BigInt(utxos[n].value), SIGHASH_ALL);
    // key: raw key (BigInt) or a signer from the vault (src/crypto/vault.js)
    const sig = typeof key === 'bigint' ? ecdsaSign(key, h) : key.ecdsa(h);
    inp.witness = witnessFor(Buffer.concat([derEncode(sig), Buffer.from([SIGHASH_ALL])]));
  });
  return { tx, hex: tx.toHex(), txid: tx.txid, fee, value };
}

/** Looks, in the witnesses of whoever spent the HTLC, for the secret whose SHA-256 is `hash`. */
export function findSecretInWitnesses(witnesses, hash) {
  for (const w of witnesses) {
    if (w.length === 4 && w[1].length === 32 && sha256(w[1]).equals(hash)) return Buffer.from(w[1]);
  }
  return null;
}
