// Montagem e assinatura de transações (qualquer mistura transparente/privada).
//
// tInputs:  [{ outpoint:{txid,index}, amount, signer }]   (signer = chave no cofre, src/crypto/vault.js)
//           ou { …, x } com a chave privada crua (testes, ferramentas)
//           ou { outpoint, amount, policy, path? } — multiassinatura: a testemunha fica com um
//           espaço reservado do tamanho exato e é preenchida depois pelos signatários
//           ou { outpoint, amount, x, pq:{ sPub, mldsa:{priv,pub} } } — endereço quântico (krq1…):
//           assinatura híbrida Schnorr + ML-DSA-44
//           + prefix (opcional): bytes antes da assinatura (ex.: revelação de compromisso de nome)
// sInputs:  [{ outpoint, amount, mask, spend (ou p cru), P, C, fcmp:{ branch, anchor, path, leafPos } }]
//           — prova de pertencimento à cadeia inteira (padrão); ou, só na simnet (legado):
//           [{ outpoint, amount, mask, p, ring:[{outpoint, P, C}] }]     (ring inclui a real)
// outputs:  [{ type:'t', lock, amount } | { type:'s', A, B, amount }]
// change:   saída de troco (mesmo formato, sem amount) — usada se sobrar valor
// feeRate:  grãos por grama de massa
// memo:     texto opcional, cifrado para o destinatário da 1ª saída privada (só ele lê)
// sweep:    em vez de outputs, UMA saída que leva tudo menos a taxa (renovar / resgatar)
// extraFee: taxa adicional além da de massa (ex.: taxa anual de um @nome)

import { randomScalar, modN } from '../crypto/secp256k1.js';
import { schnorrSign } from '../crypto/schnorr.js';
import { commit } from '../crypto/pedersen.js';
import { makeShieldedOutput, encryptMemo } from '../crypto/stealth.js';
import { proveRange, rangeProofSize } from '../crypto/bulletproofs.js';
import { clsagSign, keyImage, encodeClsag, clsagSize } from '../crypto/clsag.js';
import { fcmpProve, fcmpFinish, fcmpProofSize } from '../fcmp/fcmp.js';
import { Transaction } from '../consensus/tx.js';
import { computeMass, storageMass } from '../consensus/mass.js';
import { toHex } from '../util/bytes.js';
import { witnessSize } from '../consensus/policy.js';
import { PQ_WITNESS_SIZE, PQ_WITNESS_VERSION, encodePqWitness } from '../consensus/pqlock.js';
import { mldsaSign } from '../crypto/pq.js';

// espaço reservado com o byte de versão certo, para a massa ser medida exatamente
const pqPlaceholder = () => { const w = Buffer.alloc(PQ_WITNESS_SIZE); w[0] = PQ_WITNESS_VERSION; return w; };

const withPrefix = (i, w) => (i.prefix ? Buffer.concat([i.prefix, w]) : w);
// assinatura de uma entrada transparente: pelo cofre (signer) ou com a chave crua (x)
const signT = (i, msg) => (i.signer ? i.signer.sign(msg) : schnorrSign(i.x, msg));
const signPq = (i, msg) => (i.pq.mldsa.sign ? i.pq.mldsa.sign(msg) : mldsaSign(i.pq.mldsa.priv, msg));
const kiOf = (si, P) => (si.spend ? si.spend.keyImage(P) : keyImage(si.p, P));

const DUST_T = 100_000n; // troco transparente menor que isso vira taxa (evita massa de armazenamento alta)

function assembleBody({ tInputs, sInputs, outputs, fee, payload, memo }) {
  const sSecrets = [];
  const rs = [];   // um segredo r_j por saída privada (R_j = r_j·D vai na própria saída)
  let firstSS = null;
  const tOut = [], sOut = [];
  for (const o of outputs) {
    if (o.type === 't') tOut.push({ amount: o.amount, lock: o.lock });
    else {
      const r = randomScalar();
      const so = makeShieldedOutput({ A: o.A, B: o.B }, r, sOut.length, o.amount);
      if (firstSS === null) firstSS = so.ss;
      rs.push(r);
      sOut.push({ R: so.R.toBytes(), P: so.P.toBytes(), C: so.C.toBytes(), encAmount: so.encAmount, viewTag: so.viewTag });
      sSecrets.push({ v: o.amount, x: so.x });
    }
  }
  // Toda transação com saída privada leva um bloco de memo de tamanho fixo (vazio se não
  // houver texto): observadores não distinguem transações com e sem mensagem.
  if (firstSS !== null) payload = encryptMemo(memo ?? '', firstSS, 0);
  const pseudoMasks = sInputs.map(() => randomScalar());
  const sIn = sInputs.map((si, i) => {
    if (si.fcmp) {
      return {
        ring: [], anchor: si.fcmp.anchor,
        pseudo: commit(si.amount, pseudoMasks[i]).toBytes(),
        keyImage: kiOf(si, si.P).toBytes(),
        fcmp: Buffer.alloc(fcmpProofSize(si.fcmp.anchor, si.fcmp.branch)),
      };
    }
    const real = si.ring.find((m) => toHex(m.outpoint.txid) === toHex(si.outpoint.txid) && m.outpoint.index === si.outpoint.index);
    if (!real) throw new Error('anel não contém a saída real');
    return {
      ring: si.ring.map((m) => m.outpoint),
      pseudo: commit(si.amount, pseudoMasks[i]).toBytes(),
      keyImage: kiOf(si, real.P).toBytes(),
      clsag: Buffer.alloc(clsagSize(si.ring.length)),
    };
  });
  const tx = new Transaction({
    tIn: tInputs.map((i) => ({ outpoint: i.outpoint, sig: withPrefix(i, i.pq ? pqPlaceholder() : Buffer.alloc(i.policy ? witnessSize(i.policy, i.path ?? 0) : 64)) })),
    sIn, tOut, sOut, fee, payload: payload ?? Buffer.alloc(0),
    rangeProof: sOut.length ? Buffer.alloc(rangeProofSize(sOut.length)) : Buffer.alloc(0),
    bindingSig: (sIn.length || sOut.length) ? Buffer.alloc(64) : null,
  });
  return { tx, r: rs[0] ?? null, sSecrets, pseudoMasks };
}

function measure(parts, params) {
  const { tx } = assembleBody(parts);
  tx.mass = 0xffffffff; // tamanho fixo do campo
  tx.invalidate();
  const cm = computeMass(tx, params);
  const sm = storageMass(tx, parts.tInputs.map((i) => i.amount), params);
  return Math.max(cm, sm);
}

/**
 * Constrói e assina. Retorna { tx, fee, change, r } (r = segredo da 1ª saída privada, serve de
 * prova de pagamento para saídas privadas).
 */
export function buildTransaction({ params, tInputs = [], sInputs = [], outputs, change, feeRate = params.minRelayFeeRate, payload, memo, sweep, extraFee = 0n }) {
  if (sweep) return buildSweep({ params, tInputs, sInputs, sweep, feeRate, payload, memo, extraFee });
  if (!outputs.length) throw new Error('nenhuma saída');
  if (memo && outputs[0].type !== 's') {
    throw new Error('memo só é possível em pagamentos para endereço privado (krs1…): num pagamento transparente ele ficaria público');
  }
  const inTotal = tInputs.reduce((a, i) => a + i.amount, 0n) + sInputs.reduce((a, i) => a + i.amount, 0n);
  const outTotal = outputs.reduce((a, o) => a + o.amount, 0n);
  let fee = 0n, outs = outputs, mass = 0, changeAmt = 0n, done = false;
  for (let iter = 0; iter < 20 && !done; iter++) {
    const rest = inTotal - outTotal - fee;
    if (rest < 0n) throw new Error(`saldo insuficiente (faltam ${-rest} grãos)`);
    outs = outputs; changeAmt = 0n;
    if (rest > 0n && change && !(change.type === 't' && rest < DUST_T)) {
      outs = [...outputs, { ...change, amount: rest }];
      changeAmt = rest;
    }
    const effFee = inTotal - outTotal - changeAmt; // sem troco, a sobra vira taxa
    mass = measure({ tInputs, sInputs, outputs: outs, fee: 0n, payload, memo }, params);
    const need = BigInt(mass) * feeRate + extraFee;
    if (effFee >= need) { fee = effFee; done = true; } else fee = need;
  }
  if (!done) throw new Error('não foi possível calcular a taxa');
  return finish({ params, tInputs, sInputs, outs, fee, mass, payload, memo, changeAmt });
}

/** Uma única saída com todo o saldo das entradas, menos a taxa. */
function buildSweep({ params, tInputs, sInputs, sweep, feeRate, payload, memo, extraFee = 0n }) {
  const inTotal = tInputs.reduce((a, i) => a + i.amount, 0n) + sInputs.reduce((a, i) => a + i.amount, 0n);
  let fee = 0n, mass = 0, outs, done = false;
  for (let iter = 0; iter < 20 && !done; iter++) {
    if (inTotal - fee <= 0n) throw new Error('saldo insuficiente para pagar a taxa');
    outs = [{ ...sweep, amount: inTotal - fee }];
    mass = measure({ tInputs, sInputs, outputs: outs, fee: 0n, payload, memo }, params);
    const need = BigInt(mass) * feeRate + extraFee;
    if (fee >= need) done = true; else fee = need;
  }
  if (!done) throw new Error('não foi possível calcular a taxa');
  return finish({ params, tInputs, sInputs, outs, fee, mass, payload, memo, changeAmt: 0n });
}

function finish({ params, tInputs, sInputs, outs, fee, mass, payload, memo, changeAmt }) {
  if (mass > params.maxTxMass) throw new Error(`transação pesada demais (${mass} > ${params.maxTxMass}); use menos entradas ou valores maiores`);

  const { tx, r, sSecrets, pseudoMasks } = assembleBody({ tInputs, sInputs, outputs: outs, fee, payload, memo });
  tx.mass = mass;
  if (sSecrets.length) {
    tx.rangeProof = proveRange(sSecrets.map((s) => s.v), sSecrets.map((s) => s.x)).proof;
  }
  tx.invalidate();
  const msg = tx.sighash(); // o corpo (incluindo massa e taxa) está final; assinaturas não mudam o id
  tInputs.forEach((i, n) => {
    if (i.policy) return; // multiassinatura: os signatários preenchem depois
    const w = i.pq ? encodePqWitness(i.pq.sPub, i.pq.mldsa.pub, signT(i, msg), signPq(i, msg)) : signT(i, msg);
    tx.tIn[n].sig = withPrefix(i, w);
  });
  sInputs.forEach((si, n) => {
    if (si.fcmp) {
      const { branch, anchor, path, leafPos } = si.fcmp;
      const secrets = { p: si.p, spend: si.spend, x: si.mask, v: si.amount, pseudoMask: pseudoMasks[n], msg };
      // parte cara já preparada (em paralelo, ver src/fcmp/parallel.js) ou tudo aqui, em sequência
      const { proof } = si.fcmp.pre ? fcmpFinish(si.fcmp.pre, { ...secrets, P: si.P })
        : fcmpProve({ branch, N: anchor, path, leafPos, C: si.C, ...secrets, P: si.P });
      tx.sIn[n].fcmp = proof;
      return;
    }
    const ring = si.ring.map((m) => ({ P: m.P, C: m.C }));
    const pi = si.ring.findIndex((m) => toHex(m.outpoint.txid) === toHex(si.outpoint.txid) && m.outpoint.index === si.outpoint.index);
    const pseudo = commit(si.amount, pseudoMasks[n]);
    const z = modN(si.mask - pseudoMasks[n]);
    const sig = si.spend ? si.spend.clsag(msg, ring, pseudo, pi, z) : clsagSign(msg, ring, pseudo, pi, si.p, z);
    tx.sIn[n].clsag = encodeClsag(sig);
  });
  if (tx.bindingSig) {
    let e = pseudoMasks.reduce((a, x) => a + x, 0n) - sSecrets.reduce((a, s) => a + s.x, 0n);
    e = modN(e);
    tx.bindingSig = schnorrSign(e, msg, 'binding');
  }
  tx.invalidate();
  return { tx, fee, change: changeAmt, r };
}
