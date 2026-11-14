// Nomes legíveis na carteira: registrar @padaria, apontar para um endereço, renovar,
// transferir e liberar. As regras ficam no consenso (src/consensus/names.js); aqui só
// montamos as transações.
//
// Registro em duas etapas (proteção contra quem tenta copiar o nome no meio do caminho):
//   nameCommit  → publica só um hash do nome (ninguém sabe qual é)
//   nameReveal  → depois de nameCommitMin blocos, revela o nome e cria o registro
// O "sal" do compromisso vem da frase de 24 palavras: dá para revelar até de outra cópia.

import { H } from '../crypto/hash.js';
import { toHex, fromHex } from '../util/bytes.js';
import { parseOutpointKey } from '../consensus/tx.js';
import { checkName, nameFee, encodeNameRecord, nameCommitHash, nameCommitLock, commitWitnessPrefix } from '../consensus/names.js';
import { decodeAddress } from '../address.js';
import { buildTransaction } from './builder.js';
import { pqAvailable } from '../crypto/pq.js';

const COMMIT_VALUE = 1_000_000n; // 0,01 KRV no compromisso; volta como troco na revelação
const expiryMargin = (p) => Math.min(600, Math.floor(p.namePeriod / 20));
const saltFor = (w, name, n) => w.keys.vault.nameSalt(name, n); // H("wallet/name/salt", semente, nome, n), no cofre

/** Chave desta carteira que corresponde à trava (hex) de dono, ou null. */
function signerFor(w, lock) {
  const h = typeof lock === 'string' ? lock.toLowerCase() : toHex(lock); // o RPC devolve hex
  const t = w.keys.tKey(0), q = pqAvailable() ? w.keys.qKey(0) : null;
  if (toHex(t.lock) === h) return { lock: t.lock, signer: t.signer };
  if (q && toHex(q.lock) === h) return { lock: q.lock, signer: q.signer, pq: q };
  return null;
}
/** Dono padrão: o endereço krv — ou o krq, se a carteira estiver no modo quântico. */
function defaultOwner(w) { return signerFor(w, w.quantum ? w.keys.qKey(0).lock : w.keys.tKey(0).lock); }

/** Para onde o nome aponta: 'privado' (krs principal), 'transparente', ou um endereço. */
export function targetData(w, target = 'privado') {
  if (target === 'privado' || target === 'private') return w.keys.shieldedData;
  if (target === 'transparente' || target === 'transparent') return w._changeLock;
  const a = decodeAddress(w.params, target);
  if (!['t', 's', 'm', 'q'].includes(a.type)) throw new Error('um nome só pode apontar para um endereço krv, krs, krq ou de multiassinatura');
  return a.data;
}

function ownerLockFrom(w, address) {
  const a = decodeAddress(w.params, address);
  if (!['t', 'm', 'q'].includes(a.type)) throw new Error('o novo dono precisa ser um endereço krv, krq ou de multiassinatura (krs não pode assinar)');
  return a.data;
}

/** Etapa 1: compromisso. Retorna { name, txid, waitSeconds, nameFee }. */
export async function nameCommit(w, raw, { target = 'privado', feeRate } = {}) {
  const name = checkName(raw);
  const info = await w.resolveName(name);
  if (info.status !== 'livre') throw new Error(`@${name} já tem dono (${info.status})`);
  const owner = defaultOwner(w);
  const tgt = targetData(w, target);
  const n = (w.data.nameSaltN = (w.data.nameSaltN ?? 0) + 1);
  const lock = nameCommitLock(nameCommitHash(name, saltFor(w, name, n), owner.lock));
  const r = await w.sendOutputs([{ type: 't', lock, amount: COMMIT_VALUE }], { feeRate });
  (w.data.names ??= {})[name] = { name, saltN: n, owner: toHex(owner.lock), target: toHex(tgt), commitTxid: r.txid, state: 'compromisso', time: Date.now() };
  w.save();
  return { name, txid: r.txid, fee: r.fee, nameFee: BigInt(info.fee), waitSeconds: w.params.nameCommitMin / w.params.bps };
}

async function pendingCommit(w, name) {
  const p = w.data.names?.[name];
  if (!p || p.state !== 'compromisso') throw new Error(`não há compromisso pendente para @${name} nesta carteira`);
  const owner = signerFor(w, p.owner);
  if (!owner) throw new Error('a chave do compromisso não é desta carteira');
  const salt = saltFor(w, name, p.saltN);
  const r = await w.call('getutxos', { locks: [toHex(nameCommitLock(nameCommitHash(name, salt, owner.lock)))] });
  const u = r.utxos.find((x) => !x.inMempool);
  return { p, owner, salt, u, daa: r.daaScore };
}

/** Quantos segundos faltam para poder revelar (0 = já pode; null = compromisso ainda não confirmado). */
export async function nameRevealWait(w, raw) {
  const { u, daa } = await pendingCommit(w, checkName(raw));
  if (!u) return null;
  return Math.max(0, w.params.nameCommitMin - (daa - u.daa)) / w.params.bps;
}

/** Etapa 2: revelação — cria o registro (paga a taxa anual, que vai para o Fundo de Segurança). */
export async function nameReveal(w, raw, { feeRate } = {}) {
  const name = checkName(raw);
  const { p, owner, salt, u, daa } = await pendingCommit(w, name);
  if (!u) throw new Error('o compromisso ainda não foi confirmado');
  const missing = w.params.nameCommitMin - (daa - u.daa);
  if (missing > 0) throw new Error(`aguarde mais ${Math.ceil(missing / w.params.bps)} s antes de revelar`);
  const info = await w.resolveName(name);
  if (info.status !== 'livre') throw new Error(`@${name} foi registrado por outra pessoa antes`);
  const expiry = daa + w.params.namePeriod - expiryMargin(w.params);
  const record = encodeNameRecord({ name, expiry, owner: owner.lock, target: fromHex(p.target) });
  const commitIn = { outpoint: parseOutpointKey(u.outpoint), amount: BigInt(u.amount), signer: owner.signer, pq: owner.pq, prefix: commitWitnessPrefix(name, salt, owner.lock) };
  const fee = nameFee(w.params, name);
  const res = await w.sendOutputs([{ type: 't', lock: record, amount: w.params.nameMinDeposit }], { extraInputs: [commitIn], extraFee: fee, feeRate });
  p.state = 'registrado'; p.revealTxid = res.txid;
  w.save();
  return { name, txid: res.txid, fee: res.fee, nameFee: fee, expiry };
}

/** Gasta o registro atual (só o dono consegue) e o recria com mudanças — ou o libera. */
async function recordOp(w, raw, { target, newOwner, renew = false, release = false, feeRate } = {}) {
  const name = checkName(raw);
  const info = await w.resolveName(name);
  if (info.status === 'livre') throw new Error(`@${name} não está registrado`);
  const signer = signerFor(w, info.ownerLock);
  if (!signer) throw new Error(`@${name} não pertence a esta carteira (dono: ${info.owner})`);
  const input = { outpoint: parseOutpointKey(info.outpoint), amount: BigInt(info.deposit), signer: signer.signer, pq: signer.pq };
  if (release) {
    const { tx, fee } = buildTransaction({ params: w.params, tInputs: [input], sweep: { type: 't', lock: w._changeLock }, feeRate });
    const res = await w.call('sendrawtransaction', { tx: toHex(tx.serialize()) });
    return { name, txid: res.txid, fee, refunded: BigInt(info.deposit) - fee };
  }
  if (info.status !== 'ativo' && !renew) throw new Error(`@${name} venceu: renove para mantê-lo`);
  const expiry = renew ? Math.max(info.expiry, info.daaScore) + w.params.namePeriod - expiryMargin(w.params) : info.expiry;
  const record = encodeNameRecord({
    name, expiry,
    owner: newOwner ? ownerLockFrom(w, newOwner) : fromHex(info.ownerLock),
    target: target ? targetData(w, target) : fromHex(info.targetData),
  });
  const extraFee = renew ? nameFee(w.params, name) : 0n;
  const res = await w.sendOutputs([{ type: 't', lock: record, amount: BigInt(info.deposit) }], { extraInputs: [input], extraFee, feeRate });
  return { name, txid: res.txid, fee: res.fee, nameFee: extraFee, expiry };
}

export const nameRenew = (w, name, o = {}) => recordOp(w, name, { ...o, renew: true });
export const nameUpdate = (w, name, target, o = {}) => recordOp(w, name, { ...o, target });
export const nameTransfer = (w, name, to, o = {}) => recordOp(w, name, { ...o, newOwner: to });
export const nameRelease = (w, name, o = {}) => recordOp(w, name, { ...o, release: true });

/** Nomes que pertencem a esta carteira (pelo endereço krv ou krq) — funciona após restaurar a frase. */
export function myNames(w) {
  const owners = [toHex(w.keys.tKey(0).lock)];
  if (pqAvailable()) owners.push(toHex(w.keys.qKey(0).lock));
  return w.call('listnames', { owners });
}
