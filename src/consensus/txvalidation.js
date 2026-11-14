// Regras de validade das transações.
//
// validateTxStateless — independe do estado (estrutura, limites, provas de intervalo).
// validateTxInContext — contra uma visão UTXO (existência, maturidade, gasto duplo,
//                        assinaturas, assinaturas em anel, balanço).
//
// Regra de balanço (vale para QUALQUER mistura transparente/privada):
//   E = Σ pseudo_compromissos + (Σ entradas_transparentes)·H
//       − Σ compromissos_de_saída − (Σ saídas_transparentes + taxa)·H
// Sem partes privadas: exige-se E = 0 numericamente.
// Com partes privadas: E precisa ser k·G e o remetente prova conhecer k com uma
// assinatura Schnorr ("assinatura de balanço"). Como ninguém conhece log_G(H),
// isso só é possível se os VALORES se cancelam exatamente — sem criar moeda.
//
// Nomes (@nome, src/consensus/names.js): no máximo um registro por transação; um nome só
// pode ter um registro vivo; registrar exige revelar um compromisso maduro e pagar a taxa;
// renovar exige a taxa; alterar/transferir exige a assinatura do dono (que gasta o registro).

import { MAX_SUPPLY } from '../params.js';
import { Point, INF, sumPoints } from '../crypto/secp256k1.js';
import { schnorrVerify } from '../crypto/schnorr.js';
import { mulH } from '../crypto/pedersen.js';
import { verifyRange, rangeProofSize, MAX_AGGREGATION } from '../crypto/bulletproofs.js';
import { clsagVerify, decodeClsag, clsagSize } from '../crypto/clsag.js';
import { fcmpProofSize, fcmpVerifyInto, newFcmpBatch } from '../fcmp/fcmp.js';
import { parseAddressData } from '../address.js';
import { verifyMultisigWitness, witnessDelay, LOCK_MULTISIG } from './policy.js';
import { verifyPqWitness } from './pqlock.js';
import { LOCK_NAME, LOCK_NAME_COMMIT, parseNameRecord, parseCommitWitness, nameCommitHash, nameFee } from './names.js';
import { computeMass, storageMass } from './mass.js';
import { outpointKey } from './tx.js';
import { toHex } from '../util/bytes.js';

export class TxRuleError extends Error {}
const fail = (m) => { throw new TxRuleError(m); };

// Caches de verificação criptográfica (os dados referenciados por um outpoint são
// imutáveis — o txid compromete as saídas —, então o resultado é determinístico).
const rangeOk = new Set();
const cryptoOk = new Set();
function remember(set, k) { if (set.size > 100_000) set.clear(); set.add(k); }

const OWNER_TYPES = new Set(['t', 'm', 'q']); // quem pode ser dono de um nome (travas gastáveis)

/**
 * Registro de nome e compromisso são gastos com a testemunha do DONO. Devolve
 * { lock, witness, commit? } com a trava e a testemunha "de dentro", ou null se não conferir.
 */
function unwrapSpend(lock, witness) {
  if (lock[0] === LOCK_NAME) {
    try { return { lock: parseNameRecord(lock).owner, witness }; } catch { return null; }
  }
  if (lock[0] === LOCK_NAME_COMMIT) {
    const c = parseCommitWitness(witness);
    if (!c || !nameCommitHash(c.name, c.salt, c.owner).equals(lock.subarray(1))) return null;
    return { lock: c.owner, witness: c.inner, commit: c };
  }
  return { lock, witness };
}

/** Regras dos nomes. Devolve a taxa de nome paga (vai inteira para o Fundo de Segurança). */
function checkNameRules(tx, view, povDaa, params, inners, entries) {
  const out = tx.tOut.find((o) => o.lock[0] === LOCK_NAME);
  if (!out) return 0n;
  const rec = parseNameRecord(out.lock);
  const fee = nameFee(params, rec.name);
  if (out.amount < params.nameMinDeposit) fail(`o registro de um nome precisa guardar ao menos ${params.nameMinDeposit} grãos de depósito`);
  if (rec.expiry <= povDaa) fail('vencimento do nome no passado (renove pagando a taxa)');
  const spent = new Set(tx.tIn.map((i) => outpointKey(i.outpoint.txid, i.outpoint.index)));
  let prev = null;
  for (const { key, e } of view.nameEntries(rec.name)) {
    const r = parseNameRecord(e.lock);
    if (povDaa > r.expiry + params.nameGrace) continue; // passou da carência: não vale mais
    if (!spent.has(key)) fail(`@${rec.name} já tem dono`);
    prev = r;
  }
  if (prev) {
    // o dono (cuja assinatura é exigida para gastar o registro) altera, transfere ou renova
    if (rec.expiry <= prev.expiry) return 0n;
    if (tx.fee < fee) fail(`renovar @${rec.name} custa ${fee} grãos`);
    if (rec.expiry > Math.max(prev.expiry, povDaa) + params.namePeriod) fail('renovação além de um período');
    return fee;
  }
  if (tx.fee < fee) fail(`registrar @${rec.name} custa ${fee} grãos`);
  if (rec.expiry > povDaa + params.namePeriod) fail('registro além de um período');
  const ok = inners.some((u, n) => u.commit && u.commit.name === rec.name && u.commit.owner.equals(rec.owner)
    && povDaa - entries[n].daa >= params.nameCommitMin && povDaa - entries[n].daa <= params.nameCommitMax);
  if (!ok) fail(`registrar @${rec.name} exige revelar um compromisso feito entre ${params.nameCommitMin} e ${params.nameCommitMax} blocos atrás`);
  return fee;
}

export function validateTxStateless(tx, params) {
  if (tx.version !== 1) fail('versão de transação desconhecida');
  if (tx.isCoinbase()) fail('transação sem entradas');
  if (tx.tOut.length + tx.sOut.length === 0) fail('transação sem saídas');
  if (tx.payload.length > params.maxTxPayload) fail('payload grande demais');
  if (tx.fee > MAX_SUPPLY) fail('taxa inválida');
  const seen = new Set();
  for (const i of tx.tIn) {
    const k = outpointKey(i.outpoint.txid, i.outpoint.index);
    if (seen.has(k)) fail('entrada duplicada');
    seen.add(k);
  }
  const kis = new Set();
  for (const si of tx.sIn) {
    if (!si.ring.length) {
      // prova de pertencimento à cadeia inteira contra a árvore com as `anchor` primeiras saídas
      if (!Number.isSafeInteger(si.anchor) || si.anchor < 1) fail('âncora de entrada privada inválida');
      if (!si.fcmp || si.fcmp.length !== fcmpProofSize(si.anchor, params.fcmpBranch)) fail('prova de pertencimento com tamanho inválido');
    } else {
      if (!params.ringInputs) fail('assinaturas em anel não são aceitas nesta rede: a entrada privada precisa provar pertencer à árvore de TODAS as saídas (FCMP)');
      if (si.ring.length !== params.ringSize) fail(`anel deve ter ${params.ringSize} membros`);
      const members = new Set(si.ring.map((m) => outpointKey(m.txid, m.index)));
      if (members.size !== si.ring.length) fail('membro de anel repetido');
      if (si.clsag.length !== clsagSize(si.ring.length)) fail('assinatura em anel com tamanho inválido');
    }
    const ki = toHex(si.keyImage);
    if (kis.has(ki)) fail('imagem de chave repetida na transação');
    kis.add(ki);
    try { Point.fromBytes(si.pseudo); Point.fromBytes(si.keyImage); } catch { fail('ponto inválido em entrada privada'); }
  }
  let outSum = 0n, nameOuts = 0;
  for (const o of tx.tOut) {
    if (o.amount < 1n || o.amount > MAX_SUPPLY) fail('valor de saída inválido');
    outSum += o.amount;
    let a;
    try { a = parseAddressData(o.lock); } catch { fail('trava de saída inválida'); }
    if (a.type === 's') fail('trava de saída inválida');
    if (a.type === 'n') {
      nameOuts++;
      let owner, target;
      try { owner = parseAddressData(a.record.owner); target = parseAddressData(a.record.target); } catch { fail('registro de nome com dono ou destino inválido'); }
      if (!OWNER_TYPES.has(owner.type)) fail('o dono de um nome precisa ser um endereço krv, krq ou de multiassinatura');
      if (!['t', 's', 'm', 'q'].includes(target.type)) fail('destino de nome inválido');
    }
  }
  if (nameOuts > 1) fail('no máximo um registro de nome por transação');
  if (outSum + tx.fee > MAX_SUPPLY) fail('soma de saídas acima da oferta máxima');
  const hasShielded = tx.sIn.length > 0 || tx.sOut.length > 0;
  if (tx.sOut.length) {
    if (tx.sOut.length > MAX_AGGREGATION) fail('saídas privadas demais');
    if (tx.rangeProof.length !== rangeProofSize(tx.sOut.length)) fail('prova de intervalo com tamanho inválido');
    let Cs;
    try { Cs = tx.sOut.map((o) => { Point.fromBytes(o.R); Point.fromBytes(o.P); return Point.fromBytes(o.C); }); }
    catch { fail('ponto inválido em saída privada'); }
    const key = tx.hashHex;
    if (!rangeOk.has(key)) {
      if (!verifyRange(Cs, tx.rangeProof)) fail('prova de intervalo inválida');
      remember(rangeOk, key);
    }
  } else if (tx.rangeProof.length) fail('prova de intervalo sem saídas privadas');
  if (hasShielded !== !!tx.bindingSig) fail('assinatura de balanço ausente ou indevida');
  const cm = computeMass(tx, params);
  if (tx.mass < cm) fail(`massa declarada (${tx.mass}) menor que a de computação (${cm})`);
  if (tx.mass > params.maxTxMass) fail('transação pesada demais');
}

/**
 * Valida contra a visão UTXO. Retorna { fee } ou lança TxRuleError.
 * povDaa = daaScore do ponto de vista (bloco que aceita a transação).
 */
export function validateTxInContext(tx, view, povDaa, params) {
  const tInAmounts = [];
  const inners = [], entries = [];
  for (const i of tx.tIn) {
    const e = view.getT(outpointKey(i.outpoint.txid, i.outpoint.index));
    if (!e) fail('entrada inexistente ou já gasta');
    if (e.coinbase && povDaa - e.daa < params.coinbaseMaturity) fail('coinbase imatura');
    const u = unwrapSpend(e.lock, i.sig);
    if (!u) fail('testemunha não confere com a saída (compromisso de nome errado?)');
    if (u.lock[0] === LOCK_MULTISIG) {
      // bloqueio por tempo relativo: checado sempre (depende do momento, não só da transação)
      const delay = witnessDelay(u.witness);
      if (delay === null) fail('testemunha de multiassinatura malformada');
      if (povDaa - e.daa < delay) fail(`bloqueado por tempo: faltam ${delay - (povDaa - e.daa)} blocos`);
    }
    tInAmounts.push(e.amount);
    inners.push(u);
    entries.push(e);
  }
  const rings = [];
  for (const si of tx.sIn) {
    if (view.hasKI(toHex(si.keyImage))) fail('gasto duplo (imagem de chave já usada)');
    if (!si.ring.length) {
      // A âncora precisa estar no estado do pai selecionado (a ordem global é a da cadeia
      // selecionada) e ser madura: TODAS as saídas da árvore escolhida já podem ser gastas.
      const base = view.base;
      if (si.anchor > base.sList.length) fail('âncora além das saídas privadas conhecidas');
      const last = base.s.get(base.sList[si.anchor - 1]);
      if (povDaa - last.daa < params.fcmpMaturity) fail(`âncora recente demais: use uma árvore com ao menos ${params.fcmpMaturity} blocos`);
      rings.push(null);
      continue;
    }
    const ring = [];
    for (const m of si.ring) {
      const e = view.getS(outpointKey(m.txid, m.index));
      if (!e) fail('membro de anel inexistente');
      const need = e.coinbase ? Math.max(params.ringMaturity, params.coinbaseMaturity) : params.ringMaturity;
      if (povDaa - e.daa < need) fail('membro de anel imaturo');
      ring.push(e);
    }
    rings.push(ring);
  }
  if (storageMass(tx, tInAmounts, params) > tx.mass) fail('massa de armazenamento acima da declarada');
  const nameFeePaid = checkNameRules(tx, view, povDaa, params, inners, entries);

  const tIn = tInAmounts.reduce((a, b) => a + b, 0n);
  const tOut = tx.tOut.reduce((a, o) => a + o.amount, 0n);
  const hasShielded = tx.sIn.length > 0 || tx.sOut.length > 0;
  if (!hasShielded && tIn !== tOut + tx.fee) fail('entradas ≠ saídas + taxa');

  const key = tx.hashHex;
  if (!cryptoOk.has(key)) {
    const msg = tx.sighash();
    tx.tIn.forEach((i, n) => {
      const { lock: inner, witness } = inners[n];
      let lock;
      try { lock = parseAddressData(inner); } catch { fail('trava não gastável'); }
      if (lock.type === 'm') {
        if (!verifyMultisigWitness(lock.data, witness, msg)) fail('multiassinatura inválida (faltam assinaturas ou alguma não confere)');
      } else if (lock.type === 'q') {
        if (!verifyPqWitness(lock.data, witness, msg)) fail('assinatura híbrida quântica inválida (Schnorr e ML-DSA precisam conferir)');
      } else if (lock.type === 't') {
        if (witness.length !== 64 || !schnorrVerify(lock.pubkey, msg, witness)) fail('assinatura inválida');
      } else fail('esta saída não pode ser gasta');
    });
    const pseudos = [];
    const batch = newFcmpBatch();
    let fcmps = 0;
    tx.sIn.forEach((si, n) => {
      const pseudo = Point.fromBytes(si.pseudo);
      pseudos.push(pseudo);
      if (!si.ring.length) {
        try {
          fcmpVerifyInto(batch, { branch: params.fcmpBranch, N: si.anchor, root: view.base.tree.root(si.anchor), proof: si.fcmp, keyImage: Point.fromBytes(si.keyImage), pseudo, msg });
        } catch (e) { fail('prova de pertencimento inválida (' + e.message + ')'); }
        fcmps++;
        return;
      }
      const ring = rings[n].map((e) => ({ P: Point.fromBytes(e.P), C: Point.fromBytes(e.C) }));
      const sig = decodeClsag(si.clsag, si.ring.length, Point.fromBytes(si.keyImage));
      if (!clsagVerify(msg, ring, pseudo, sig)) fail('assinatura em anel inválida');
    });
    // todas as provas de pertencimento da transação numa única multiexponenciação por curva
    if (fcmps && !(batch.e1.check() && batch.e2.check())) fail('prova de pertencimento inválida');
    if (hasShielded) {
      const outC = sumPoints(tx.sOut.map((o) => Point.fromBytes(o.C)));
      const E = sumPoints(pseudos).add(mulH(tIn)).sub(outC).sub(mulH(tOut + tx.fee));
      if (E.isInf() || !schnorrVerify(E, msg, tx.bindingSig, 'binding')) fail('balanço inválido');
    }
    remember(cryptoOk, key);
  }
  return { fee: tx.fee, tIn, nameFee: nameFeePaid };
}

/**
 * Quanto uma transação muda o saldo do pool privado (catraca, como o ZIP-209 do Zcash).
 * Calculado só com valores PÚBLICOS: (entradas transparentes) − (saídas transparentes + taxa).
 *   > 0  → moedas entraram no pool privado (blindagem)
 *   < 0  → moedas saíram do pool privado (desblindagem)
 * Transações puramente transparentes não tocam no pool (delta 0).
 */
export function shieldedDelta(tx, tInSum) {
  if (!tx.sIn.length && !tx.sOut.length) return 0n;
  return tInSum - tx.tOut.reduce((a, o) => a + o.amount, 0n) - tx.fee;
}
export { INF };
