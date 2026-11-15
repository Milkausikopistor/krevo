// Krevo (KRV) consensus parameters.
// Everything here is a consensus rule: changing any value creates an incompatible network.

export const COIN = 100_000_000n;                 // 1 KRV = 100,000,000 grains
export const MAX_SUPPLY = 1_000_000_000n * COIN;  // absolute cap: 1 billion KRV

/**
 * GHOSTDAG k from the block rate λ (blocks/s), the maximum network delay D (s) and the
 * failure probability δ: the smallest k such that
 * P[Poisson(2Dλ) > k] < δ  (Sompolinsky, Wyborski, Zohar — PHANTOM/GHOSTDAG).
 */
export function computeGhostdagK(bps, delaySeconds, delta = 0.01) {
  const mean = 2 * delaySeconds * bps;
  let term = Math.exp(-mean), cdf = term, k = 0;
  while (1 - cdf >= delta) { k++; term *= mean / k; cdf += term; }
  return k;
}

const SECONDS_PER_MONTH = 2_629_800; // 365,25 dias / 12

const common = {
  bps: 10,                          // 10 blocks per second
  targetTimeMs: 100,
  maxParents: 16,
  mergesetSizeLimit: 512,
  maxFutureMs: 120_000,             // local policy: blocks from the future wait
  coinbaseMaturity: 1000,           // 100 s
  ringSize: 16,                     // fixed ring size (all private transactions look alike)
  ringMaturity: 300,                // ring members must be 30 s old
  // Private inputs: full-chain membership proof (FCMP, curve tree)
  ringInputs: false,                // rings are not accepted: every private input hides among ALL outputs
  fcmpBranch: 256,                  // children per tree node (256³ = 16.7 million outputs at depth 3)
  fcmpMaturity: 1000,               // the anchor (root used by the proof) must be 100 s old: every output in it is mature
  maxBlockMass: 500_000,
  maxTxMass: 250_000,
  massPerByte: 1,
  massPerSig: 1_000,
  massPerRingMember: 1_500,
  massPerFcmpInput: 20_000,         // verifying a membership proof costs ~2 multi-exponentiations of 2048 terms
  massPerShieldedOutput: 3_000,
  storageMassC: 1_000_000_000n,     // KIP-9: discourages creating "dust"
  shieldedStorageMass: 2_000,
  minRelayFeeRate: 1n,              // 1 grain per gram of mass (policy, not consensus)
  feePoolShareNum: 1n,              // 1/2 of the fees go to the Security Fund
  feePoolShareDen: 2n,
  feePoolDecay: 864_000n,           // each block releases 1/864,000 of the fund (~16 h half-life)
  rewardPerSecond0: 545_000_000n,   // 5.45 KRV/s in the first month
  secondsPerMonth: SECONDS_PER_MONTH,
  reductionsPerHalving: 48,         // smooth monthly reduction; half every 4 years
  maxCoinbasePayload: 200,
  maxTxPayload: 256,
  // Human-readable names (@name): registered on the network itself, no authority
  namePeriod: 315_576_000,          // 1 year in blocks (365.25 days × 86,400 s × 10/s)
  nameGrace: 25_920_000,            // 30-day grace period after expiry: only the owner can renew
  nameCommitMin: 300,               // 30 s between commitment and reveal (prevents front-running)
  nameCommitMax: 864_000,           // the commitment is valid for 1 day
  nameMinDeposit: 1_000_000n,       // 0.01 KRV stays locked in the record (returned when the name is released)
  nameFees: [10_000_000_000n, 2_000_000_000n, 500_000_000n, 100_000_000n], // per year: 3 letters 100 KRV, 4 → 20, 5 → 5, 6+ → 1 KRV
  lightProofDepth: 100,             // light wallet: blocks with PoW required on top of a payment (10 s) — local policy
};

export const NETWORKS = {
  mainnet: {
    ...common,
    name: 'mainnet',
    ghostdagK: computeGhostdagK(10, 5),
    mergeDepth: 3_600,
    daaWindowSize: 2_640,
    daaMinWindow: 60,
    pastMedianTimeWindow: 263,
    p2pMagic: 0x4b525631,
    defaultP2pPort: 16110,
    defaultRpcPort: 16111,
    hrp: { t: 'krv', s: 'krs', v: 'krw', p: 'krp', k: 'krk', m: 'krm', q: 'krq', x: 'krx' },
    // The mainnet genesis must only be fixed on the day of the fair launch,
    // with a message containing the hash of a recent Bitcoin block (proof that
    // nobody mined before). See docs/WHITEPAPER.md, section "Fair launch".
    genesis: { timestamp: 1798761600000, bits: 0x1f00ffff, message: 'Krevo mainnet — TO BE SET AT LAUNCH' },
  },
  testnet: {
    ...common,
    name: 'testnet',
    ghostdagK: computeGhostdagK(10, 5),
    mergeDepth: 3_600,
    daaWindowSize: 2_640,
    daaMinWindow: 60,
    pastMedianTimeWindow: 263,
    p2pMagic: 0x4b525654,
    defaultP2pPort: 16210,
    defaultRpcPort: 16211,
    hrp: { t: 'krvtest', s: 'krstest', v: 'krwtest', p: 'krptest', k: 'krktest', m: 'krmtest', q: 'krqtest', x: 'krxtest' },
    genesis: { timestamp: 1794355200000, bits: 0x1f0fffff, message: 'Krevo testnet' },
  },
  devnet: {
    ...common,
    name: 'devnet',
    ghostdagK: computeGhostdagK(10, 5),
    mergeDepth: 1_200,
    daaWindowSize: 300,
    daaMinWindow: 30,
    pastMedianTimeWindow: 41,
    coinbaseMaturity: 100,          // 10 s
    ringMaturity: 20,               // 2 s
    fcmpMaturity: 100,              // 10 s
    nameCommitMin: 50,              // 5 s (faster demonstrations)
    lightProofDepth: 30,            // 3 s
    p2pMagic: 0x4b525644,
    defaultP2pPort: 16310,
    defaultRpcPort: 16311,
    hrp: { t: 'krvdev', s: 'krsdev', v: 'krwdev', p: 'krpdev', k: 'krkdev', m: 'krmdev', q: 'krqdev', x: 'krxdev' },
    genesis: { timestamp: 1794355200000, bits: 0x1f0fffff, message: 'Krevo devnet' },
  },
};

// simnet: automated tests only (trivial difficulty, small ring).
NETWORKS.simnet = {
  ...NETWORKS.devnet,
  name: 'simnet',
  daaMinWindow: 1e9,                // dificuldade fixa
  coinbaseMaturity: 10,
  ringMaturity: 2,
  ringSize: 4,
  ringInputs: true,                 // simnet: rings remain valid (fast tests); FCMP too
  fcmpBranch: 4,                    // narrow tree: the tests exercise depths 1, 2, 3…
  fcmpMaturity: 10,
  namePeriod: 400,                  // short periods to test expiry and grace
  nameGrace: 100,
  nameCommitMin: 3,
  nameCommitMax: 200,
  lightProofDepth: 3,
  p2pMagic: 0x4b525653,
  defaultP2pPort: 16410,
  defaultRpcPort: 16411,
  hrp: { t: 'krvsim', s: 'krssim', v: 'krwsim', p: 'krpsim', k: 'krksim', m: 'krmsim', q: 'krqsim', x: 'krxsim' },
  genesis: { timestamp: 1794355200000, bits: 0x207fffff, message: 'Krevo simnet' },
};

export function getParams(name = 'devnet') {
  const p = NETWORKS[name];
  if (!p) throw new Error(`unknown network: ${name}`);
  return p;
}

export const formatKRV = (grains) => {
  const neg = grains < 0n; if (neg) grains = -grains;
  const whole = grains / COIN, frac = (grains % COIN).toString().padStart(8, '0').replace(/0+$/, '');
  return (neg ? '-' : '') + whole.toLocaleString('en-US') + (frac ? '.' + frac : '') + ' KRV';
};
export function parseKRV(str) {
  // "1,234.5" (thousands separator) and "1234,5" (decimal comma, as in Portuguese) are both accepted
  let s = String(str).trim();
  s = s.includes('.') ? s.replace(/,/g, '') : s.replace(',', '.');
  if (!/^\d+(\.\d{1,8})?$/.test(s)) throw new Error(`invalid amount: ${str}`);
  const [w, f = ''] = s.split('.');
  return BigInt(w) * COIN + BigInt(f.padEnd(8, '0'));
}
