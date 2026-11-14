// Ajuste de dificuldade (DAA) a cada bloco.
//
// Janela = os W blocos mais recentes do passado do bloco (azuis E vermelhos,
// pois todos representam hashrate). Novo alvo = alvo médio × tempo real / tempo
// esperado. Para resistir a timestamps manipulados, o tempo real é medido entre
// os percentis 5% e 95% dos timestamps da janela: um atacante com < 5% dos
// blocos não consegue esticar nem encolher a janela.

import { compactToTarget, targetToCompact } from './pow.js';

export function daaWindow(store, headers, gd, size) {
  const out = [];
  let cur = gd;
  const cmpDesc = (a, b) => -compareGd(store, a, b);
  while (cur && out.length < size) {
    const ms = [...cur.mergesetBlues, ...cur.mergesetReds].sort(cmpDesc);
    for (const h of ms) { out.push(h); if (out.length >= size) break; }
    if (!cur.selectedParent) break;
    cur = store.gd.get(cur.selectedParent);
  }
  return out;
}
function compareGd(store, a, b) {
  const wa = store.gd.get(a).blueWork, wb = store.gd.get(b).blueWork;
  if (wa !== wb) return wa < wb ? -1 : 1;
  return a < b ? -1 : a > b ? 1 : 0;
}

export function requiredBits(params, store, headers, gd, powLimitBits) {
  const win = daaWindow(store, headers, gd, params.daaWindowSize);
  if (win.length < params.daaMinWindow) return powLimitBits;
  const ts = win.map((h) => headers.get(h).timestamp).sort((a, b) => a - b);
  const cut = Math.floor(win.length * 0.05);
  const lo = cut, hi = win.length - 1 - cut;
  const span = BigInt(Math.max(ts[hi] - ts[lo], 1));
  const expected = BigInt((hi - lo) * params.targetTimeMs);
  let sum = 0n;
  for (const h of win) sum += compactToTarget(headers.get(h).bits);
  const avg = sum / BigInt(win.length);
  let next = (avg * span) / expected;
  if (next > avg * 4n) next = avg * 4n;
  if (next < avg / 4n) next = avg / 4n;
  const limit = compactToTarget(powLimitBits);
  if (next > limit) next = limit;
  if (next < 1n) next = 1n;
  return targetToCompact(next);
}

/** Tempo mediano passado: timestamp de um novo bloco precisa ser ≥ a ele. */
export function pastMedianTime(params, store, headers, gd) {
  const win = daaWindow(store, headers, gd, params.pastMedianTimeWindow);
  const ts = win.map((h) => headers.get(h).timestamp).sort((a, b) => a - b);
  return ts.length ? ts[Math.floor(ts.length / 2)] : 0;
}
