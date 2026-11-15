// Solves the proof of work of a block template (simple CPU miner).
import { PowState, compactToTarget, targetToLE, hashMeetsTarget } from '../consensus/pow.js';

/**
 * Looks for a nonce. Returns true if it found one (and writes it into the header), false if
 * `maxTries` ran out or `shouldStop()` asked to stop.
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
