// Contrato de GARANTIA (escrow): comprador, vendedor e árbitro — sem empresa no meio.
//
// O dinheiro do comprador fica num endereço de política (regra de consenso já existente):
//   caminho 0: 2 de 3 {comprador, vendedor, árbitro}, a qualquer momento
//     · tudo certo         → comprador + vendedor liberam para o vendedor
//     · comprador sumiu    → vendedor + árbitro liberam para o vendedor
//     · disputa            → o árbitro decide junto com uma das partes (liberar ou reembolsar)
//   caminho 1: o comprador SOZINHO, depois do prazo — se ninguém agir, o dinheiro volta
// O árbitro sozinho não pega nada; o vendedor sozinho também não; e o dinheiro nunca fica
// preso para sempre. Pagamentos pelo caminho 0 usam as propostas da multiassinatura
// (arquivo que circula; cada um confere O QUE está assinando antes de assinar).
//
// Código do contrato (para todos importarem): krm1… = [0xE5][política][papéis][valor][rótulo]

import { encode, decode } from '../util/bech32m.js';
import { Writer, Reader, toHex } from '../util/bytes.js';
import { encodePolicyPaths } from '../consensus/policy.js';
import { formatKRV } from '../params.js';
import { rpc } from '../node/rpcclient.js';
import { MultisigGroup, decodeMultisigKey, multisigKey, proposePayment, signProposal, describeProposal, finalizeProposal, spendAlone, formatWait } from './multisig.js';

const MAGIC = 0xe5;
const ROLE_NAMES = { buyer: 'comprador', seller: 'vendedor', arbiter: 'árbitro' };

export class EscrowContract {
  /** keys: { buyer, seller, arbiter } (Points); delay em blocos; amount em grãos. */
  constructor(params, { buyer, seller, arbiter, delay, amount, label = '' }) {
    if (buyer.equals(seller) || buyer.equals(arbiter) || seller.equals(arbiter)) throw new Error('comprador, vendedor e árbitro precisam ter chaves diferentes');
    if (!(delay > 0)) throw new Error('prazo inválido');
    if (amount <= 0n) throw new Error('valor inválido');
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

  /** Código para compartilhar com as outras partes (inclui papéis, valor e prazo). */
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
    if (hrp !== params.hrp.m) throw new Error(`código de outra rede ou formato (${hrp})`);
    const r = new Reader(bytes);
    if (r.u8() !== MAGIC) throw new Error('este código não é de um contrato de garantia');
    const group = new MultisigGroup(params, r.varbytes(4096));
    const [p0, p1] = group.paths;
    if (group.paths.length !== 2 || p0.m !== 2 || p0.n !== 3 || p1.m !== 1 || p1.n !== 1 || p0.delay !== 0) throw new Error('política que não é de garantia');
    const si = r.u8(), ai = r.u8();
    const buyer = p1.keys[0];
    const seller = p0.keys[si], arbiter = p0.keys[ai];
    if (!seller || !arbiter || si === ai || !p0.keys.some((k) => k.equals(buyer)) || seller.equals(buyer) || arbiter.equals(buyer)) throw new Error('papéis inválidos no código');
    const amount = r.u64();
    const label = r.varbytes(240).toString('utf8');
    r.end();
    const c = new EscrowContract(params, { buyer, seller, arbiter, delay: p1.delay, amount, label });
    if (!c.policyBytes.equals(group.bytes)) throw new Error('código adulterado');
    return c;
  }

  /** Papel de uma chave neste contrato: 'buyer' | 'seller' | 'arbiter' | null. */
  roleOf(P) {
    for (const [role, k] of Object.entries(this.keys)) if (k.equals(P)) return role;
    return null;
  }
  roleName(role) { return ROLE_NAMES[role] ?? role; }
}

/** Papel da carteira (pela chave de multiassinatura dela). */
export const myRole = (contract, walletKeys) => contract.roleOf(multisigKey(walletKeys).P);

/** Saldo, se o depósito já foi feito e quanto falta para o comprador poder pegar de volta sozinho. */
export async function escrowStatus(params, rpcUrl, contract) {
  const { daaScore, utxos } = await rpc(rpcUrl, 'getutxos', { locks: [toHex(contract.lock)] });
  const balance = utxos.reduce((a, u) => a + BigInt(u.amount), 0n);
  const left = utxos.length ? Math.max(...utxos.map((u) => Math.max(0, contract.delay - (daaScore - u.daa)))) : null;
  return {
    balance, funded: balance >= contract.amount, empty: utxos.length === 0,
    refundInBlocks: left, refundIn: left === null ? null : formatWait(left, params), refundable: left === 0 && utxos.length > 0,
  };
}

/** Comprador deposita o valor combinado no endereço do contrato. */
export async function escrowFund(wallet, contract) {
  if (myRole(contract, wallet.keys) !== 'buyer') throw new Error('só o comprador deposita na garantia');
  return wallet.send({ to: contract.address, amount: contract.amount });
}

/**
 * Proposta de saída pelo caminho 2-de-3: kind 'liberar' (para o vendedor) ou 'reembolsar'
 * (para o comprador). Já vai assinada por quem propõe; falta uma assinatura.
 */
export async function escrowPropose({ params, rpcUrl, contract, walletKeys, kind, to }) {
  const role = myRole(contract, walletKeys);
  if (!role) throw new Error('sua carteira não é parte deste contrato');
  if (kind !== 'liberar' && kind !== 'reembolsar') throw new Error('use liberar (para o vendedor) ou reembolsar (para o comprador)');
  if (!to) throw new Error(kind === 'liberar' ? 'informe --para ENDEREÇO_DO_VENDEDOR' : 'informe --para ENDEREÇO_DO_COMPRADOR');
  const prop = await proposePayment({ params, rpcUrl, group: contract.group, to, amount: 0n, path: 0, sweep: true });
  prop.escrow = { code: contract.code, kind, proposedBy: role };
  signProposal(params, prop, walletKeys);
  return prop;
}

/** Descreve a proposta em termos do contrato (quem propôs, para onde vai, quanto). */
export function describeEscrowProposal(params, prop) {
  if (!prop.escrow) throw new Error('esta proposta não é de um contrato de garantia');
  const contract = EscrowContract.fromCode(params, prop.escrow.code);
  const d = describeProposal(params, prop);
  if (!d.group.lock.equals(contract.lock)) throw new Error('a proposta não é deste contrato');
  if (d.payments.length !== 1 || d.change !== 0n) throw new Error('proposta de garantia deve pagar tudo para um único destino — NÃO assine');
  const signedBy = d.signers.map((i) => contract.roleOf(d.group.paths[0].keys[i]));
  return { contract, d, kind: prop.escrow.kind, to: d.payments[0].to, amount: d.payments[0].amount, signedBy };
}

/** Assina (confere antes) e, com 2 assinaturas, envia para a rede. */
export async function escrowSign({ params, rpcUrl, prop, walletKeys }) {
  const info = describeEscrowProposal(params, prop);
  const role = myRole(info.contract, walletKeys);
  if (!role) throw new Error('sua carteira não é parte deste contrato');
  signProposal(params, prop, walletKeys);
  const have = Object.keys(prop.signatures).length;
  if (have < 2) return { sent: false, have, info };
  const tx = finalizeProposal(params, prop);
  const res = await rpc(rpcUrl, 'sendrawtransaction', { tx: toHex(tx.serialize()) });
  return { sent: true, txid: res.txid, fee: tx.fee, have, info };
}

/** Comprador, depois do prazo, pega tudo de volta sozinho (caminho 1). */
export async function escrowReclaim({ params, rpcUrl, contract, walletKeys, to }) {
  if (myRole(contract, walletKeys) !== 'buyer') throw new Error('só o comprador pode resgatar depois do prazo');
  return spendAlone({ params, rpcUrl, group: contract.group, path: 1, keys: walletKeys, to, amount: 0n, sweep: true });
}

export const describeAmount = (c) => formatKRV(c.amount);
