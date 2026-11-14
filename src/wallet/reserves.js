// PROVA DE RESERVAS — para corretoras (ou qualquer custodiante) provarem que têm o dinheiro
// dos clientes, sem expor quem são os clientes.
//
// 1) ATIVOS: o que a carteira da corretora controla AGORA, amarrado a uma mensagem do momento
//    (ex.: "Exchange X — auditoria de 13/11/2026"), que impede reaproveitar provas antigas.
//      • moedas transparentes: uma assinatura Schnorr por moeda com a chave do endereço;
//      • moedas privadas: revela valor e máscara (abre o compromisso C = x·G + v·H), a imagem de
//        chave I e uma prova DLEQ de que log_G(P) = log_Hp(P)(I) — ou seja, quem prova tem a chave
//        da saída e I é a imagem dela. Como I ainda não aparece na rede, a moeda NÃO foi gasta,
//        e duas corretoras não conseguem contar a mesma moeda (a mesma saída tem uma só I).
//      Custo de privacidade: as saídas da CORRETORA ficam identificadas (as dos clientes, não).
//
// 2) PASSIVOS: árvore de Merkle com SOMAS (Maxwell). Cada folha é H(conta, sal, saldo) — o sal
//    de cada cliente é entregue só a ele —, cada nó soma os filhos e a raiz traz o total devido.
//    Cada cliente confere que o seu saldo está na raiz publicada; a corretora prova
//    ATIVOS ≥ total da raiz.

import { randomBytes } from 'node:crypto';
import { Point, mulG, modN, randomScalar, hedgedScalar, hashToScalar, scalarToBytes } from '../crypto/secp256k1.js';
import { schnorrSign, schnorrVerify } from '../crypto/schnorr.js';
import { commit } from '../crypto/pedersen.js';
import { hashPointForKeyImage, keyImage } from '../crypto/clsag.js';
import { H } from '../crypto/hash.js';
import { dleqVerify as dleqCheck } from '../crypto/dleq.js';
import { transparentData } from '../address.js';
import { formatKRV, parseKRV } from '../params.js';
import { rpc } from '../node/rpcclient.js';
import { toHex, fromHex, scalarToBytesHex } from './reserves-util.js';

const ctxOf = (network, message, outpoint) => H('reserves/ctx', network, message, outpoint);

// a prova DLEQ é feita no cofre (src/crypto/vault.js → src/crypto/dleq.js no plano B)
const dleqHex = ({ c, s }) => ({ c: scalarToBytesHex(c), s: scalarToBytesHex(s) });
const dleqVerify = (P, I, ctx, proof) => dleqCheck(P, I, ctx, { c: BigInt('0x' + proof.c), s: BigInt('0x' + proof.s) });

/** Monta a prova de ativos com TODAS as moedas não gastas da carteira (já sincronizada). */
export async function proveReserves(wallet, message) {
  if (!message || message.length < 8) throw new Error('use uma mensagem do momento, ex.: "Exchange X — auditoria de 13/11/2026"');
  await wallet.sync();
  const network = wallet.params.name;
  const t = wallet.keys.tKey(0);
  const transparent = wallet.tUtxos.filter((u) => u.kind === 't' && !u.inMempool).map((u) => ({
    outpoint: u.outpoint, amount: String(u.amount), pubkey: toHex(t.P.toBytes()),
    sig: toHex(t.signer.sign(ctxOf(network, message, u.outpoint), 'reserves')),
  }));
  const priv = wallet.data.sOwned.filter((o) => !o.spent && !o.pending && !o.unverified).map((o) => {
    if (o.k === undefined) throw new Error('sincronize a carteira antes (formato antigo)');
    const P = Point.fromBytes(fromHex(o.P)), spend = wallet.keys.spender(BigInt('0x' + o.k), o.sub ?? 0);
    const I = spend.keyImage(P);
    return {
      index: o.index, outpoint: o.outpoint, amount: o.amount, mask: scalarToBytesHex(BigInt(o.mask)), keyImage: toHex(I.toBytes()),
      proof: dleqHex(spend.dleq(P, I, ctxOf(network, message, o.outpoint))),
    };
  });
  const total = [...transparent, ...priv].reduce((a, x) => a + BigInt(x.amount), 0n);
  return { krevo: 'prova-de-reservas', version: 1, network, message, createdAt: Date.now(), transparent, private: priv, total: total.toString() };
}

/**
 * Confere a prova contra um nó. Retorna { valid, total, transparent, private, issues }.
 * Só soma o que passa em TODAS as checagens; qualquer problema vai para `issues`.
 */
export async function verifyReserves(params, rpcUrl, proof, { message } = {}) {
  const issues = [];
  if (proof.krevo !== 'prova-de-reservas' || proof.network !== params.name) throw new Error('arquivo não é uma prova de reservas desta rede');
  if (message !== undefined && message !== proof.message) issues.push('a mensagem da prova é diferente da combinada (pode ser uma prova antiga)');
  const seen = new Set();
  let tTotal = 0n, sTotal = 0n;
  // transparentes: existem, não estão sendo gastas, valor confere e a assinatura é do dono
  const byLock = new Map();
  for (const e of proof.transparent ?? []) {
    if (seen.has(e.outpoint)) { issues.push(`moeda repetida ${e.outpoint.slice(0, 16)}…`); continue; }
    seen.add(e.outpoint);
    let P;
    try { P = Point.fromBytes(fromHex(e.pubkey)); } catch { issues.push('chave pública inválida'); continue; }
    if (!schnorrVerify(P, ctxOf(params.name, proof.message, e.outpoint), fromHex(e.sig), 'reserves')) { issues.push(`assinatura inválida em ${e.outpoint.slice(0, 16)}…`); continue; }
    const lock = toHex(transparentData(P));
    (byLock.get(lock) ?? byLock.set(lock, []).get(lock)).push(e);
  }
  for (const [lock, entries] of byLock) {
    const { utxos } = await rpc(rpcUrl, 'getutxos', { locks: [lock] });
    const live = new Map(utxos.filter((u) => !u.inMempool).map((u) => [u.outpoint, BigInt(u.amount)]));
    for (const e of entries) {
      if (!live.has(e.outpoint)) { issues.push(`moeda transparente ${e.outpoint.slice(0, 16)}… não existe ou já foi gasta`); continue; }
      if (live.get(e.outpoint) !== BigInt(e.amount)) { issues.push(`valor declarado errado em ${e.outpoint.slice(0, 16)}…`); continue; }
      tTotal += live.get(e.outpoint);
    }
  }
  // privadas: a saída existe, o compromisso abre no valor declarado, DLEQ confere e I não foi usada
  const privs = (proof.private ?? []).filter((e) => {
    if (seen.has(e.outpoint)) { issues.push(`moeda repetida ${e.outpoint.slice(0, 16)}…`); return false; }
    seen.add(e.outpoint);
    return true;
  });
  const kis = new Set();
  const okPriv = [];
  for (let k = 0; k < privs.length; k += 500) {
    const chunk = privs.slice(k, k + 500);
    const r = await rpc(rpcUrl, 'getshieldedbyindex', { indices: chunk.map((e) => Number(e.index)) });
    const byIndex = new Map(r.outputs.map((o) => [o.index, o]));
    for (const e of chunk) {
      const o = byIndex.get(Number(e.index));
      if (!o || o.outpoint !== e.outpoint) { issues.push(`saída privada ${e.outpoint.slice(0, 16)}… não existe nesse índice`); continue; }
      const P = Point.fromBytes(fromHex(o.P)), C = Point.fromBytes(fromHex(o.C));
      let I;
      try { I = Point.fromBytes(fromHex(e.keyImage)); } catch { issues.push('imagem de chave inválida'); continue; }
      if (kis.has(e.keyImage)) { issues.push('imagem de chave repetida'); continue; }
      if (!commit(BigInt(e.amount), BigInt('0x' + e.mask)).equals(C)) { issues.push(`valor declarado não abre o compromisso de ${e.outpoint.slice(0, 16)}…`); continue; }
      if (!dleqVerify(P, I, ctxOf(params.name, proof.message, e.outpoint), e.proof)) { issues.push(`prova de posse inválida em ${e.outpoint.slice(0, 16)}…`); continue; }
      kis.add(e.keyImage);
      okPriv.push(e);
    }
  }
  if (okPriv.length) {
    const st = await rpc(rpcUrl, 'getkeyimages', { keyImages: okPriv.map((e) => e.keyImage) });
    st.forEach((s, n) => {
      if (s.spent || s.inMempool) issues.push(`moeda privada ${okPriv[n].outpoint.slice(0, 16)}… já foi gasta`);
      else sTotal += BigInt(okPriv[n].amount);
    });
  }
  const total = tTotal + sTotal;
  if (total !== BigInt(proof.total ?? 0)) issues.push(`total declarado ${formatKRV(BigInt(proof.total ?? 0))}, total provado ${formatKRV(total)}`);
  return { valid: issues.length === 0, total, transparent: tTotal, private: sTotal, coins: seen.size, issues };
}

// ------------------------------------------------------------------ passivos (árvore de somas)
const leafHash = (id, salt, balance) => H('reserves/leaf', id, salt, balance);
const nodeHash = (l, r) => H('reserves/node', l.hash, l.sum, r.hash, r.sum);

/** accounts: [{ id, balance (grãos) }] → { root, proofs } (uma prova por conta, para entregar ao cliente). */
export function buildLiabilities(accounts, { label = '' } = {}) {
  if (!accounts.length) throw new Error('nenhuma conta');
  const ids = new Set();
  const leaves = accounts.map((a) => {
    const balance = BigInt(a.balance);
    if (balance < 0n) throw new Error(`saldo negativo na conta ${a.id}`);
    if (ids.has(a.id)) throw new Error(`conta repetida: ${a.id}`);
    ids.add(a.id);
    const salt = randomBytes(16);
    return { id: String(a.id), salt, balance, hash: leafHash(String(a.id), salt, balance), sum: balance };
  });
  const levels = [leaves];
  while (levels[levels.length - 1].length > 1) {
    const cur = levels[levels.length - 1], next = [];
    for (let i = 0; i < cur.length; i += 2) {
      next.push(i + 1 < cur.length ? { hash: nodeHash(cur[i], cur[i + 1]), sum: cur[i].sum + cur[i + 1].sum } : cur[i]);
    }
    levels.push(next);
  }
  const top = levels[levels.length - 1][0];
  const root = { krevo: 'raiz-de-passivos', version: 1, label, hash: toHex(top.hash), total: top.sum.toString(), accounts: leaves.length, createdAt: Date.now() };
  const proofs = leaves.map((leaf, idx) => {
    const path = [];
    let i = idx;
    for (let l = 0; l < levels.length - 1; l++) {
      const sib = i ^ 1;
      if (sib < levels[l].length) path.push({ side: sib < i ? 'L' : 'R', hash: toHex(levels[l][sib].hash), sum: levels[l][sib].sum.toString() });
      else path.push(null); // nó ímpar sobe sozinho
      i >>= 1;
    }
    return { krevo: 'prova-de-passivo', version: 1, rootHash: root.hash, id: leaf.id, salt: toHex(leaf.salt), balance: leaf.balance.toString(), path };
  });
  return { root, proofs };
}

/** O cliente confere que a SUA conta, com o SEU saldo, está somada na raiz publicada. */
export function verifyLiability(proof, root) {
  if (proof.rootHash !== root.hash) return { valid: false, reason: 'a prova é de outra raiz' };
  let node = { hash: leafHash(proof.id, fromHex(proof.salt), BigInt(proof.balance)), sum: BigInt(proof.balance) };
  for (const step of proof.path) {
    if (step === null) continue;
    const sib = { hash: fromHex(step.hash), sum: BigInt(step.sum) };
    if (sib.sum < 0n) return { valid: false, reason: 'soma negativa na árvore' };
    node = step.side === 'L' ? { hash: nodeHash(sib, node), sum: sib.sum + node.sum } : { hash: nodeHash(node, sib), sum: node.sum + sib.sum };
  }
  if (toHex(node.hash) !== root.hash) return { valid: false, reason: 'o caminho não leva à raiz publicada' };
  if (node.sum.toString() !== root.total) return { valid: false, reason: 'o total não confere com a raiz' };
  return { valid: true, balance: BigInt(proof.balance), total: BigInt(root.total) };
}

/**
 * Lê uma conta por linha: "conta;saldo" (saldo com vírgula, ex.: ana;12,5) ou "conta,saldo"
 * (saldo com ponto, ex.: ana,12.5). Ignora cabeçalho e linhas vazias.
 */
export function parseAccountsCsv(text) {
  const out = [];
  for (const line of String(text).split(/\r?\n/)) {
    const t = line.trim();
    if (!t || /^(conta|id|account)\s*[,;]/i.test(t)) continue;
    const parts = t.split(t.includes(';') ? ';' : ',').map((x) => x.trim());
    if (parts.length !== 2 || !parts[0]) throw new Error(`linha inválida: "${t}" (use conta;saldo — ou conta,saldo com ponto decimal)`);
    out.push({ id: parts[0], balance: parseKRV(parts[1]) });
  }
  return out;
}
