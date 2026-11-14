// "Massa" = custo de recursos de uma transação. Taxa = massa × taxa por grama.
//
// massa de computação: bytes + custo de verificação de assinaturas/provas.
// massa de armazenamento (KIP-9 do Kaspa): C · (Σ 1/saída − |E|²/Σ entrada).
//   Criar muitas saídas minúsculas ("poeira") fica caro; consolidar fica barato.
//   É isso que mantém o conjunto UTXO pequeno — e o hardware dos nós acessível —
//   mesmo com taxas quase zero.
// massa final = max(computação, armazenamento) e é declarada na própria transação.

import { isPqWitness } from './pqlock.js';
import { parseWitnessPath } from './policy.js';
import { COMMIT_WITNESS, parseCommitWitness } from './names.js';

/** Quantas verificações de assinatura uma testemunha transparente exige (para a massa). */
function sigCount(w) {
  if (w.length === 64) return 1;                  // Schnorr simples
  if (isPqWitness(w)) return 2;                   // Schnorr + ML-DSA (verificar ML-DSA custa ~o mesmo)
  if (w[0] === COMMIT_WITNESS) {                  // revelação de nome: conta a testemunha do dono
    const c = parseCommitWitness(w);
    if (c) return sigCount(c.inner);
  }
  const p = parseWitnessPath(w);                  // multiassinatura: M assinaturas
  return p ? p.p.m : Math.max(1, Math.floor(w.length / 65));
}

export function computeMass(tx, params) {
  let m = tx.size * params.massPerByte;
  // multiassinatura: cada testemunha traz M assinaturas (contagem conservadora pelo tamanho)
  for (const i of tx.tIn) m += sigCount(i.sig) * params.massPerSig;
  for (const si of tx.sIn) m += si.ring.length ? si.ring.length * params.massPerRingMember : params.massPerFcmpInput;
  m += tx.sOut.length * params.massPerShieldedOutput;
  return m;
}

/**
 * inputAmounts: valores das entradas transparentes (as privadas são ocultas e
 * contam como zero — conservador).
 */
export function storageMass(tx, inputAmounts, params) {
  const C = params.storageMassC;
  let harmonic = 0n;
  for (const o of tx.tOut) {
    if (o.amount <= 0n) return Number.MAX_SAFE_INTEGER;
    harmonic += C / o.amount;
  }
  let arith = 0n;
  const sumIn = inputAmounts.reduce((a, b) => a + b, 0n);
  if (sumIn > 0n) {
    const n = BigInt(inputAmounts.length);
    arith = (C * n * n) / sumIn;
  }
  let m = harmonic > arith ? harmonic - arith : 0n;
  m += BigInt(tx.sOut.length * params.shieldedStorageMass);
  return m > BigInt(Number.MAX_SAFE_INTEGER) ? Number.MAX_SAFE_INTEGER : Number(m);
}
