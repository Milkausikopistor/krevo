// Emissão: redução suave e previsível, sem autoridade.
//
// recompensa por bloco no mês m (m = daaScore / blocos_por_mês):
//   r(m) = r0 · 2^(−m/48)
// Ou seja: cai um pouquinho todo mês (~1,43%) e chega à metade a cada 4 anos —
// sem "choques" de halving. Tudo em inteiros: os 48 fatores 2^(−j/48) são raízes
// inteiras exatas, idênticas em qualquer implementação.
//
// O teto MAX_SUPPLY é imposto pelo consenso: o total cunhado é rastreado por bloco
// da cadeia e a recompensa é cortada para nunca ultrapassá-lo.

import { MAX_SUPPLY } from '../params.js';

function iroot(x, k) { // floor(x^(1/k)) exato
  if (x < 2n) return x;
  const kb = BigInt(k);
  let r = 1n << BigInt(Math.ceil(x.toString(2).length / k));
  for (;;) {
    const s = ((kb - 1n) * r + x / r ** (kb - 1n)) / kb;
    if (s >= r) break;
    r = s;
  }
  while (r ** kb > x) r--;
  while ((r + 1n) ** kb <= x) r++;
  return r;
}

const TABLE_CACHE = new Map();
function factorTable(steps) {
  let t = TABLE_CACHE.get(steps);
  if (!t) {
    // t[j] = floor(2^64 · 2^(−j/steps)) = floor((2^(64·steps − j))^(1/steps))
    t = Array.from({ length: steps }, (_, j) => iroot(1n << BigInt(64 * steps - j), steps));
    TABLE_CACHE.set(steps, t);
  }
  return t;
}

export const blocksPerMonth = (params) => BigInt(params.bps * params.secondsPerMonth);

export function subsidyForMonth(month, params) {
  const steps = BigInt(params.reductionsPerHalving);
  const halvings = month / steps;
  if (halvings >= 64n) return 0n;
  const r0 = params.rewardPerSecond0 / BigInt(params.bps);
  return (r0 * factorTable(params.reductionsPerHalving)[Number(month % steps)]) >> (64n + halvings);
}

/** Subsídio programado de um bloco com o dado daaScore (antes do corte do teto). */
export const scheduledSubsidy = (daaScore, params) =>
  subsidyForMonth(BigInt(daaScore) / blocksPerMonth(params), params);

/** Subsídio efetivo dado o total já cunhado (aplica o teto absoluto). */
export function cappedSubsidy(daaScore, minted, params) {
  const s = scheduledSubsidy(daaScore, params);
  const room = MAX_SUPPLY - minted;
  return s > room ? (room > 0n ? room : 0n) : s;
}

/** Tabela anual da emissão programada (para documentação e testes). */
export function emissionSchedule(params) {
  const bpm = blocksPerMonth(params);
  const rows = [];
  let total = 0n, month = 0n;
  for (;;) {
    const r = subsidyForMonth(month, params);
    if (r === 0n) break;
    total += r * bpm;
    if (month % 12n === 11n) rows.push({ year: Number(month / 12n) + 1, perBlock: r, total });
    month++;
  }
  return { rows, total, lastMonth: month };
}
