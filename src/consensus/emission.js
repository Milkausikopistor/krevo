// Emission: smooth and predictable reduction, with no authority.
//
// reward per block in month m (m = daaScore / blocks_per_month):
//   r(m) = r0 · 2^(−m/48)
// That is: it falls a little every month (~1.43%) and halves every 4 years — no halving
// "shocks". All in integers: the 48 factors 2^(−j/48) are exact integer roots, identical in
// any implementation.
//
// The MAX_SUPPLY cap is enforced by consensus: the total minted is tracked per chain block
// and the reward is cut so it never exceeds it.

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

/** Scheduled subsidy of a block with the given daaScore (before the cap cut). */
export const scheduledSubsidy = (daaScore, params) =>
  subsidyForMonth(BigInt(daaScore) / blocksPerMonth(params), params);

/** Effective subsidy given the total already minted (applies the absolute cap). */
export function cappedSubsidy(daaScore, minted, params) {
  const s = scheduledSubsidy(daaScore, params);
  const room = MAX_SUPPLY - minted;
  return s > room ? (room > 0n ? room : 0n) : s;
}

/** Yearly table of the scheduled emission (for documentation and tests). */
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
