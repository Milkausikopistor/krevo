// ESCROW contract: buyer, seller and arbiter — no company in the middle.
//
// The buyer's money sits on a policy address (an existing consensus rule):
//   path 0: 2 of 3 {buyer, seller, arbiter}, at any time
//     · all good           → buyer + seller release to the seller
//     · buyer disappeared  → seller + arbiter release to the seller
//     · dispute            → the arbiter decides together with one of the parties (release or refund)
//   path 1: the buyer ALONE, after the deadline — if nobody acts, the money goes back
// The arbiter alone gets nothing; neither does the seller alone; and the money is never stuck
// forever. Payments through path 0 use the multisig proposals (a file that circulates; each one
// checks WHAT they are signing before signing).
//
// Contract code (for everyone to import): krm1… = [0xE5][policy][roles][amount][label]

import { encode, decode } from '../util/bech32m.js';
import { Writer, Reader, toHex } from '../util/bytes.js';
import { encodePolicyPaths } from '../consensus/policy.js';
import { formatKRV } from '../params.js';
import { rpc } from '../node/rpcclient.js';
import { MultisigGroup, decodeMultisigKey, multisigKey, proposePayment, signProposal, describeProposal, finalizeProposal, spendAlone, formatWait } from './multisig.js';

const MAGIC = 0xe5;
const LEGACY_KINDS = { liberar: 'release', reembolsar: 'refund' }; // proposals created by older versions
const ROLE_NAMES = { buyer: 'buyer', seller: 'seller', arbiter: 'arbiter' };

export class EscrowContract {
  /** keys: { buyer, seller, arbiter } (Points); delay in blocks; amount in grains. */
  constructor(params, { buyer, seller, arbiter, delay, amount, label = '' }) {
    if (buyer.equals(seller) || buyer.equals(arbiter) || seller.equals(arbiter)) throw new Error('buyer, seller and arbiter need different keys');
    if (!(delay > 0)) throw new Error('invalid deadline');
    if (amount <= 0n) throw new Error('invalid amount');
    this.params = params;
    this.keys = { buyer, seller, arbiter };
    this.delay = delay;
    this.amount = BigInt(amount);
    this.label = String(label).slice(0, 60);
    this.policyBytes = encodePolicyPaths([
      { m: 2, keys: [buyer, seller, arbiter], delay: 0 },
      { m: 1, keys: [buyer], delay },
    ]);
    this.group = new MultisigGroup(params, this.policyBytes, this.label);
  }

  static create(params, { buyer, seller, arbiter, delay, amount, label }) {
    const dec = (k) => (typeof k === 'string' ? decodeMultisigKey(params, k) : k);
    return new EscrowContract(params, { buyer: dec(buyer), seller: dec(seller), arbiter: dec(arbiter), delay, amount, label });
  }

  get address() { return this.group.address; }
  get lock() { return this.group.lock; }

  /** Code to share with the other parties (includes roles, amount and deadline). */
  get code() {
    const w = new Writer();
    w.u8(MAGIC);
    w.varbytes(this.policyBytes);
    const keys = this.group.paths[0].keys;
    w.u8(keys.findIndex((k) => k.equals(this.keys.seller)));
    w.u8(keys.findIndex((k) => k.equals(this.keys.arbiter)));
    w.u64(this.amount);
    w.varbytes(Buffer.from(this.label, 'utf8'));
    return encode(this.params.hrp.m, w.done());
  }

  static fromCode(params, code) {
    const { hrp, bytes } = decode(String(code).trim());
    if (hrp !== params.hrp.m) throw new Error(`code from another network or format (${hrp})`);
    const r = new Reader(bytes);
    if (r.u8() !== MAGIC) throw new Error('this code is not an escrow contract');
    const group = new MultisigGroup(params, r.varbytes(4096));
    const [p0, p1] = group.paths;
    if (group.paths.length !== 2 || p0.m !== 2 || p0.n !== 3 || p1.m !== 1 || p1.n !== 1 || p0.delay !== 0) throw new Error('a policy that is not an escrow');
    const si = r.u8(), ai = r.u8();
    const buyer = p1.keys[0];
    const seller = p0.keys[si], arbiter = p0.keys[ai];
    if (!seller || !arbiter || si === ai || !p0.keys.some((k) => k.equals(buyer)) || seller.equals(buyer) || arbiter.equals(buyer)) throw new Error('invalid roles in the code');
    const amount = r.u64();
    const label = r.varbytes(240).toString('utf8');
    r.end();
    const c = new EscrowContract(params, { buyer, seller, arbiter, delay: p1.delay, amount, label });
    if (!c.policyBytes.equals(group.bytes)) throw new Error('tampered code');
    return c;
  }

  /** Role of a key in this contract: 'buyer' | 'seller' | 'arbiter' | null. */
  roleOf(P) {
    for (const [role, k] of Object.entries(this.keys)) if (k.equals(P)) return role;
    return null;
  }
  roleName(role) { return ROLE_NAMES[role] ?? role; }
}

/** The wallet's role (by its multisig key). */
export const myRole = (contract, walletKeys) => contract.roleOf(multisigKey(walletKeys).P);

/** Balance, whether the deposit was made, and how long until the buyer can take it back alone. */
export async function escrowStatus(params, rpcUrl, contract) {
  const { daaScore, utxos } = await rpc(rpcUrl, 'getutxos', { locks: [toHex(contract.lock)] });
  const balance = utxos.reduce((a, u) => a + BigInt(u.amount), 0n);
  const left = utxos.length ? Math.max(...utxos.map((u) => Math.max(0, contract.delay - (daaScore - u.daa)))) : null;
  return {
    balance, funded: balance >= contract.amount, empty: utxos.length === 0,
    refundInBlocks: left, refundIn: left === null ? null : formatWait(left, params), refundable: left === 0 && utxos.length > 0,
  };
}

/** The buyer deposits the agreed amount at the contract address. */
export async function escrowFund(wallet, contract) {
  if (myRole(contract, wallet.keys) !== 'buyer') throw new Error('only the buyer deposits into the escrow');
  return wallet.send({ to: contract.address, amount: contract.amount });
}

/**
 * Exit proposal through the 2-of-3 path: kind 'release' (to the seller) or 'refund'
 * (to the buyer). It already carries the proposer's signature; one more is needed.
 */
export async function escrowPropose({ params, rpcUrl, contract, walletKeys, kind, to }) {
  kind = LEGACY_KINDS[kind] ?? kind;
  const role = myRole(contract, walletKeys);
  if (!role) throw new Error('your wallet is not a party to this contract');
  if (kind !== 'release' && kind !== 'refund') throw new Error('use release (to the seller) or refund (to the buyer)');
  if (!to) throw new Error(kind === 'release' ? 'enter --to SELLER_ADDRESS' : 'enter --to BUYER_ADDRESS');
  const prop = await proposePayment({ params, rpcUrl, group: contract.group, to, amount: 0n, path: 0, sweep: true });
  prop.escrow = { code: contract.code, kind, proposedBy: role };
  signProposal(params, prop, walletKeys);
  return prop;
}

/** Describes the proposal in terms of the contract (who proposed, where it goes, how much). */
export function describeEscrowProposal(params, prop) {
  if (!prop.escrow) throw new Error('this proposal is not from an escrow contract');
  const contract = EscrowContract.fromCode(params, prop.escrow.code);
  const d = describeProposal(params, prop);
  if (!d.group.lock.equals(contract.lock)) throw new Error('the proposal is not for this contract');
  if (d.payments.length !== 1 || d.change !== 0n) throw new Error('an escrow proposal must pay everything to a single destination — do NOT sign');
  const signedBy = d.signers.map((i) => contract.roleOf(d.group.paths[0].keys[i]));
  return { contract, d, kind: LEGACY_KINDS[prop.escrow.kind] ?? prop.escrow.kind, to: d.payments[0].to, amount: d.payments[0].amount, signedBy };
}

/** Signs (after checking) and, with 2 signatures, sends it to the network. */
export async function escrowSign({ params, rpcUrl, prop, walletKeys }) {
  const info = describeEscrowProposal(params, prop);
  const role = myRole(info.contract, walletKeys);
  if (!role) throw new Error('your wallet is not a party to this contract');
  signProposal(params, prop, walletKeys);
  const have = Object.keys(prop.signatures).length;
  if (have < 2) return { sent: false, have, info };
  const tx = finalizeProposal(params, prop);
  const res = await rpc(rpcUrl, 'sendrawtransaction', { tx: toHex(tx.serialize()) });
  return { sent: true, txid: res.txid, fee: tx.fee, have, info };
}

/** The buyer, after the deadline, takes everything back alone (path 1). */
export async function escrowReclaim({ params, rpcUrl, contract, walletKeys, to }) {
  if (myRole(contract, walletKeys) !== 'buyer') throw new Error('only the buyer can reclaim after the deadline');
  return spendAlone({ params, rpcUrl, group: contract.group, path: 1, keys: walletKeys, to, amount: 0n, sweep: true });
}

export const describeAmount = (c) => formatKRV(c.amount);
