// Resolve a prova de trabalho de um modelo de bloco (minerador de CPU simples).
import { PowState, compactToTarget, targetToLE, hashMeetsTarget } from '../consensus/pow.js';

/**
 * Procura um nonce. Retorna true se achou (e grava no cabeçalho), false se
 * esgotou `maxTries` ou `shouldStop()` pediu parada.
 */
export function solve(block, { startNonce = 0n, maxTries = Infinity, shouldStop = null, state = null } = {}) {
  const h = block.header;
  const st = state ?? new PowState(h.prePowHash());
  const tgt = targetToLE(compactToTarget(h.bits));
  let n = startNonce;
  for (let i = 0; i < maxTries; i++, n++) {
    if (shouldStop && (i & 1023) === 0 && shouldStop()) return false;
    if (hashMeetsTarget(st.hash(h.timestamp, n), tgt)) {
      h.nonce = n;
      block._hash = null;
      return true;
    }
  }
  return false;
}
