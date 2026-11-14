// Coordenação de multiassinatura M-de-N (o lado da carteira).
//
//  1. Cada participante mostra sua chave de multiassinatura (krk1…).
//  2. Qualquer um cria o grupo com M e as N chaves → endereço krv1… e um "descritor"
//     (krm1…) para os outros importarem. Mesmas chaves + mesmo M = mesmo endereço.
//  3. Pagamento: alguém cria uma PROPOSTA (arquivo JSON) com a transação sem assinaturas.
//     O arquivo circula; cada signatário confere O QUE está assinando — lendo a própria
//     transação, não o resumo de quem propôs — e acrescenta sua assinatura.
//  4. Com M assinaturas, qualquer um junta tudo e envia para a rede.
//
// Como o txid não inclui as assinaturas, todos assinam exatamente a mesma mensagem e a
// ordem em que assinam não importa (cada um pode assinar quando puder, offline).

import { encode, decode } from '../util/bech32m.js';
import { Point, hashToScalar, mulG, modN } from '../crypto/secp256k1.js';
import { schnorrSign, schnorrVerify } from '../crypto/schnorr.js';
import { outputScalar, decryptAmount, blindingFactor, sharedSecret, decryptMemo } from '../crypto/stealth.js';
import { commit } from '../crypto/pedersen.js';
import { encodePolicy, encodePolicyPaths, parsePolicy, multisigLock, encodeWitness, verifyMultisigWitness } from '../consensus/policy.js';
import { encodeAddress, decodeAddress } from '../address.js';
import { Transaction, parseOutpointKey } from '../consensus/tx.js';
import { buildTransaction } from './builder.js';
import { rpc } from '../node/rpcclient.js';
import { toHex, fromHex } from '../util/bytes.js';

// ------------------------------------------------------------ chaves e grupo
/** Chave de multiassinatura do participante, derivada da semente (recuperável pela frase). */
export function multisigKey(keys) {
  const signer = keys.multisigSigner(); // a chave fica no cofre
  return { P: signer.P, signer };
}
export const encodeMultisigKey = (params, P) => encode(params.hrp.k, P.toBytes());
export function decodeMultisigKey(params, s) {
  const { hrp, bytes } = decode(String(s).trim());
  if (hrp !== params.hrp.k) throw new Error(`chave de multiassinatura de outra rede ou formato (${hrp})`);
  return Point.fromBytes(bytes);
}

export class MultisigGroup {
  constructor(params, policyBytes, name = '') {
    this.params = params;
    this.policy = parsePolicy(policyBytes);
    if (this.policy.bytes.length !== policyBytes.length) throw new Error('descritor com bytes extras');
    this.bytes = this.policy.bytes;
    this.name = name;
    this.lock = multisigLock(this.bytes);
  }
  static create(params, m, keyStrings, name) {
    return new MultisigGroup(params, encodePolicy(m, keyStrings.map((k) => decodeMultisigKey(params, k))), name);
  }
  static fromDescriptor(params, descriptor, name) {
    const { hrp, bytes } = decode(String(descriptor).trim());
    if (hrp !== params.hrp.m) throw new Error(`descritor de outra rede ou formato (${hrp})`);
    return new MultisigGroup(params, bytes, name);
  }
  /** Herança: caminho 0 = dono (sozinho, sem espera); caminho 1 = herdeiros (M-de-N após a espera). */
  static createInheritance(params, ownerKey, heirKeys, heirM, delayBlocks, name) {
    const dec = (k) => (typeof k === 'string' ? decodeMultisigKey(params, k) : k);
    const bytes = encodePolicyPaths([
      { m: 1, keys: [dec(ownerKey)], delay: 0 },
      { m: heirM, keys: heirKeys.map(dec), delay: delayBlocks },
    ]);
    return new MultisigGroup(params, bytes, name);
  }
  get paths() { return this.policy.paths; }
  get isInheritance() { return this.policy.paths.length === 2 && this.policy.paths[1].delay > 0; }
  get m() { return this.policy.m; }
  get n() { return this.policy.n; }
  get address() { return encodeAddress(this.params, this.lock); }
  get descriptor() { return encode(this.params.hrp.m, this.bytes); }
  indexOf(P, path = 0) { return this.policy.paths[path].keys.findIndex((k) => k.equals(P)); }
}

// ------------------------------------------------------------- propostas
export async function groupUtxos(rpcUrl, group) {
  const r = await rpc(rpcUrl, 'getutxos', { locks: [toHex(group.lock)] });
  return r.utxos;
}

/** Cria a proposta de pagamento (sem assinaturas). */
export async function proposePayment({ params, rpcUrl, group, to, amount, memo, path = 0, sweep = false }) {
  const dest = decodeAddress(params, to);
  if (memo && dest.type !== 's') throw new Error('memo só é possível para endereço privado (krs1…)');
  const p = group.paths[path];
  if (!p) throw new Error('caminho inexistente nesta política');
  const { daaScore, utxos } = await rpc(rpcUrl, 'getutxos', { locks: [toHex(group.lock)] });
  // só saídas que já cumpriram a espera deste caminho
  const coins = utxos.filter((u) => u.mature && !u.inMempool && daaScore - u.daa >= p.delay)
    .sort((a, b) => (BigInt(b.amount) > BigInt(a.amount) ? 1 : -1));
  const tInputs = [];
  let acc = 0n;
  for (const u of coins) {
    if (!sweep && acc >= amount + 1_000_000n) break;
    tInputs.push({ outpoint: parseOutpointKey(u.outpoint), amount: BigInt(u.amount), policy: group.bytes, path });
    acc += BigInt(u.amount);
  }
  if (!tInputs.length || (!sweep && acc < amount)) {
    const locked = utxos.filter((u) => daaScore - u.daa < p.delay);
    if (locked.length) {
      const wait = Math.min(...locked.map((u) => p.delay - (daaScore - u.daa)));
      throw new Error(`saldo ainda bloqueado por tempo neste caminho (libera em ${wait} blocos ≈ ${formatWait(wait, params)})`);
    }
    throw new Error('saldo do grupo insuficiente');
  }
  const outDesc = dest.type === 's' ? { type: 's', A: dest.A, B: dest.B } : { type: 't', lock: dest.data };
  const { tx, fee, change, r } = sweep
    ? buildTransaction({ params, tInputs, sweep: outDesc, memo })
    : buildTransaction({ params, tInputs, outputs: [{ ...outDesc, amount }], change: { type: 't', lock: group.lock }, memo });
  if (sweep) amount = acc - fee;
  return {
    krevo: 'proposta-multiassinatura', version: 1, network: params.name, group: group.descriptor, path,
    txid: tx.idHex, tx: toHex(tx.serialize()), to, amount: amount.toString(), fee: fee.toString(), change: change.toString(),
    inputs: tInputs.map((i) => ({ outpoint: `${toHex(i.outpoint.txid)}:${i.outpoint.index}`, amount: i.amount.toString() })),
    // segredo da saída privada do destinatário: permite aos signatários conferir valor e destino
    outputSecret: dest.type === 's' && r ? r.toString(16) : null,
    signatures: {},
  };
}

/**
 * Lê a transação da proposta e descreve, de forma independente, o que ela faz.
 * Não confia no resumo de quem propôs: recalcula destino, valor e troco a partir da tx.
 */
export function describeProposal(params, prop) {
  if (prop.krevo !== 'proposta-multiassinatura' || prop.network !== params.name) throw new Error('arquivo não é uma proposta desta rede');
  const group = MultisigGroup.fromDescriptor(params, prop.group);
  const tx = Transaction.deserialize(fromHex(prop.tx));
  if (tx.idHex !== prop.txid) throw new Error('proposta adulterada (txid não confere)');
  const lockHex = toHex(group.lock);
  const payments = [];
  let change = 0n;
  for (const o of tx.tOut) {
    if (toHex(o.lock) === lockHex) change += o.amount;
    else payments.push({ to: encodeAddress(params, o.lock), amount: o.amount, private: false });
  }
  if (tx.sOut.length) {
    // a 1ª saída privada é a do destinatário; o segredo r permite verificar valor e endereço
    const dest = decodeAddress(params, prop.to);
    let verified = false, amount = null, memo = null;
    if (prop.outputSecret && dest.type === 's') {
      const r = BigInt('0x' + prop.outputSecret), o = tx.sOut[0];
      const ss = sharedSecret(r, dest.A);
      const P = mulG(outputScalar(ss, 0)).add(dest.B);
      if (dest.B.mul(r).equals(Point.fromBytes(o.R)) && P.equals(Point.fromBytes(o.P))) {
        amount = decryptAmount(o.encAmount, ss, 0);
        verified = commit(amount, blindingFactor(ss, 0)).equals(Point.fromBytes(o.C));
        memo = decryptMemo(tx.payload, ss, 0) || null;
      }
    }
    if (!verified) throw new Error('não foi possível conferir a saída privada da proposta — NÃO assine');
    payments.push({ to: prop.to, amount, private: true, memo });
    if (tx.sOut.length > 1) throw new Error('proposta com saídas privadas extras — NÃO assine');
  }
  const signers = Object.keys(prop.signatures).map(Number).sort((a, b) => a - b);
  const path = prop.path ?? 0;
  if (!group.paths[path]) throw new Error('caminho inexistente na política');
  return {
    group, tx, payments, change, fee: tx.fee, inputs: tx.tIn.length, signers, have: signers.length,
    need: group.paths[path].m, path, delay: group.paths[path].delay,
  };
}

/** Confere na rede que as entradas são do grupo e soma os valores (taxa coerente). */
export async function checkProposalInputs(params, rpcUrl, prop) {
  const d = describeProposal(params, prop);
  const utxos = new Map((await groupUtxos(rpcUrl, d.group)).map((u) => [u.outpoint, BigInt(u.amount)]));
  let total = 0n;
  for (const i of d.tx.tIn) {
    const k = `${toHex(i.outpoint.txid)}:${i.outpoint.index}`;
    if (!utxos.has(k)) throw new Error(`entrada ${k.slice(0, 16)}… não é um saldo disponível do grupo`);
    total += utxos.get(k);
  }
  const out = d.payments.reduce((a, p) => a + p.amount, 0n) + d.change;
  if (total !== out + d.fee) throw new Error('valores da proposta não fecham (entradas ≠ saídas + taxa)');
  return { ...d, totalIn: total };
}

/** Acrescenta a assinatura deste participante. */
export function signProposal(params, prop, keys) {
  const d = describeProposal(params, prop);
  const { signer, P } = multisigKey(keys);
  const idx = d.group.indexOf(P, d.path);
  if (idx < 0) throw new Error(d.path ? 'sua chave não faz parte deste caminho da política' : 'sua chave não faz parte deste grupo');
  const sig = signer.sign(d.tx.sighash());
  prop.signatures[idx] = toHex(sig);
  return { index: idx, have: Object.keys(prop.signatures).length, need: d.need };
}

/** Junta assinaturas de várias cópias da mesma proposta. */
export function mergeProposals(props) {
  const base = { ...props[0], signatures: { ...props[0].signatures } };
  for (const p of props.slice(1)) {
    if (p.txid !== base.txid) throw new Error('as propostas são de transações diferentes');
    Object.assign(base.signatures, p.signatures);
  }
  return base;
}

/** Monta as testemunhas com M assinaturas válidas e devolve a transação pronta. */
export function finalizeProposal(params, prop) {
  const d = describeProposal(params, prop);
  const msg = d.tx.sighash();
  const sigs = new Map();
  for (const [i, s] of Object.entries(prop.signatures)) {
    const idx = Number(i), sig = fromHex(s);
    const key = d.group.paths[d.path].keys[idx];
    if (key && schnorrVerify(key, msg, sig)) sigs.set(idx, sig);
  }
  if (sigs.size < d.need) throw new Error(`assinaturas válidas: ${sigs.size} de ${d.need} necessárias`);
  const witness = encodeWitness(d.group.bytes, sigs, d.path);
  d.tx.tIn.forEach((i) => { i.sig = witness; });
  d.tx.invalidate();
  for (const i of d.tx.tIn) if (!verifyMultisigWitness(d.group.lock, i.sig, msg)) throw new Error('testemunha inválida');
  return d.tx;
}
export { modN };

// ------------------------------------------------------------------ herança
export function formatWait(blocks, params) {
  const sec = blocks / params.bps;
  if (sec < 120) return `${Math.ceil(sec)} s`;
  if (sec < 7200) return `${Math.ceil(sec / 60)} min`;
  if (sec < 172800) return `${(sec / 3600).toFixed(1).replace('.', ',')} h`;
  return `${(sec / 86400).toFixed(1).replace('.', ',')} dias`;
}

const UNITS = { s: 1, seg: 1, min: 60, h: 3600, d: 86400, m: 2629800, mes: 2629800, meses: 2629800, a: 31557600, y: 31557600, ano: 31557600, anos: 31557600 };

/** Converte "365d", "6m" (meses), "1a" (anos), "12h", "30min", "20s" ou "5000b" (blocos) em blocos. */
export function parseWait(str, params) {
  const m = /^(\d+(?:[.,]\d+)?)\s*([a-z]+)?$/i.exec(String(str).trim());
  const unit = (m?.[2] ?? 'd').toLowerCase();
  if (!m || (!(unit in UNITS) && unit !== 'b' && unit !== 'blocos')) {
    throw new Error(`tempo inválido: "${str}" (exemplos: 365d, 6m, 1a, 12h, 30min, 20s)`);
  }
  const n = Number(m[1].replace(',', '.'));
  return Math.round(unit === 'b' || unit === 'blocos' ? n : n * UNITS[unit] * params.bps);
}

/** Situação de um plano de herança: saldo e quando os herdeiros poderão gastar. */
export async function inheritanceStatus(params, rpcUrl, group) {
  const delay = group.paths[1].delay;
  const { daaScore, utxos } = await rpc(rpcUrl, 'getutxos', { locks: [toHex(group.lock)] });
  const items = utxos.map((u) => ({ amount: BigInt(u.amount), left: Math.max(0, delay - (daaScore - u.daa)) }));
  return {
    balance: items.reduce((a, i) => a + i.amount, 0n),
    claimable: items.filter((i) => i.left === 0).reduce((a, i) => a + i.amount, 0n),
    delay, count: items.length,
    nextUnlock: items.length ? Math.min(...items.map((i) => i.left)) : null, // primeira saída a liberar
    fullUnlock: items.length ? Math.max(...items.map((i) => i.left)) : null, // quando todo o saldo libera
  };
}

/** Gasto por um caminho que só precisa de UMA assinatura (dono, ou herdeiro num plano 1-de-N). */
export async function spendAlone({ params, rpcUrl, group, path, keys, to, amount, sweep = false, memo }) {
  if (group.paths[path].m !== 1) throw new Error('este caminho exige mais de uma assinatura: use multisig propor/assinar/enviar com --caminho');
  const prop = await proposePayment({ params, rpcUrl, group, to, amount, memo, path, sweep });
  signProposal(params, prop, keys);
  const tx = finalizeProposal(params, prop);
  const res = await rpc(rpcUrl, 'sendrawtransaction', { tx: toHex(tx.serialize()) });
  return { txid: res.txid, fee: tx.fee, amount: BigInt(prop.amount) };
}
