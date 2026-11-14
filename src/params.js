// Parâmetros de consenso do Krevo (KRV).
// Tudo aqui é regra de consenso: mudar qualquer valor cria uma rede incompatível.

export const COIN = 100_000_000n;                 // 1 KRV = 100.000.000 grãos
export const MAX_SUPPLY = 1_000_000_000n * COIN;  // teto absoluto: 1 bilhão de KRV

/**
 * k do GHOSTDAG a partir da taxa de blocos λ (blocos/s), do atraso máximo de
 * rede D (s) e da probabilidade de falha δ: o menor k tal que
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
  bps: 10,                          // 10 blocos por segundo
  targetTimeMs: 100,
  maxParents: 16,
  mergesetSizeLimit: 512,
  maxFutureMs: 120_000,             // política local: blocos do futuro esperam
  coinbaseMaturity: 1000,           // 100 s
  ringSize: 16,                     // tamanho fixo do anel (todas as tx privadas iguais)
  ringMaturity: 300,                // membros do anel precisam de 30 s de idade
  // Entradas privadas: prova de pertencimento à cadeia inteira (FCMP, árvore de curvas)
  ringInputs: false,                // anéis não são aceitos: toda entrada privada se esconde entre TODAS as saídas
  fcmpBranch: 256,                  // filhos por nó da árvore (256³ = 16,7 milhões de saídas com profundidade 3)
  fcmpMaturity: 1000,               // a âncora (raiz usada na prova) precisa ter 100 s: todas as saídas nela estão maduras
  maxBlockMass: 500_000,
  maxTxMass: 250_000,
  massPerByte: 1,
  massPerSig: 1_000,
  massPerRingMember: 1_500,
  massPerFcmpInput: 20_000,         // verificar uma prova de pertencimento custa ~2 multiexponenciações de 2048 termos
  massPerShieldedOutput: 3_000,
  storageMassC: 1_000_000_000n,     // KIP-9: desestimula criar "poeira"
  shieldedStorageMass: 2_000,
  minRelayFeeRate: 1n,              // 1 grão por grama de massa (política, não consenso)
  feePoolShareNum: 1n,              // 1/2 das taxas vão para o Fundo de Segurança
  feePoolShareDen: 2n,
  feePoolDecay: 864_000n,           // cada bloco libera 1/864.000 do fundo (~meia-vida de 16 h)
  rewardPerSecond0: 545_000_000n,   // 5,45 KRV/s no 1º mês
  secondsPerMonth: SECONDS_PER_MONTH,
  reductionsPerHalving: 48,         // redução suave mensal; metade a cada 4 anos
  maxCoinbasePayload: 200,
  maxTxPayload: 256,
  // Nomes legíveis (@nome): registro na própria rede, sem autoridade
  namePeriod: 315_576_000,          // 1 ano em blocos (365,25 dias × 86.400 s × 10/s)
  nameGrace: 25_920_000,            // 30 dias de carência depois de vencer: só o dono renova
  nameCommitMin: 300,               // 30 s entre o compromisso e a revelação (impede "furar a fila")
  nameCommitMax: 864_000,           // o compromisso vale por 1 dia
  nameMinDeposit: 1_000_000n,       // 0,01 KRV fica guardado no registro (volta ao liberar o nome)
  nameFees: [10_000_000_000n, 2_000_000_000n, 500_000_000n, 100_000_000n], // por ano: 3 letras 100 KRV, 4 → 20, 5 → 5, 6+ → 1 KRV
  lightProofDepth: 100,             // carteira leve: blocos com PoW exigidos por cima de um pagamento (10 s) — política local
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
    // O gênesis da mainnet só deve ser fixado no dia do lançamento justo,
    // com a mensagem contendo o hash de um bloco recente do Bitcoin (prova de
    // que ninguém minerou antes). Ver docs/WHITEPAPER.md, seção "Lançamento justo".
    genesis: { timestamp: 1798761600000, bits: 0x1f00ffff, message: 'Krevo mainnet — PREENCHER NO LANÇAMENTO' },
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
    nameCommitMin: 50,              // 5 s (demonstrações mais rápidas)
    lightProofDepth: 30,            // 3 s
    p2pMagic: 0x4b525644,
    defaultP2pPort: 16310,
    defaultRpcPort: 16311,
    hrp: { t: 'krvdev', s: 'krsdev', v: 'krwdev', p: 'krpdev', k: 'krkdev', m: 'krmdev', q: 'krqdev', x: 'krxdev' },
    genesis: { timestamp: 1794355200000, bits: 0x1f0fffff, message: 'Krevo devnet' },
  },
};

// simnet: só para testes automatizados (dificuldade trivial, anel pequeno).
NETWORKS.simnet = {
  ...NETWORKS.devnet,
  name: 'simnet',
  daaMinWindow: 1e9,                // dificuldade fixa
  coinbaseMaturity: 10,
  ringMaturity: 2,
  ringSize: 4,
  ringInputs: true,                 // simnet: anéis continuam válidos (testes rápidos); FCMP também
  fcmpBranch: 4,                    // árvore estreita: os testes exercitam profundidades 1, 2, 3…
  fcmpMaturity: 10,
  namePeriod: 400,                  // prazos curtos para testar vencimento e carência
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
  if (!p) throw new Error(`rede desconhecida: ${name}`);
  return p;
}

export const formatKRV = (grains) => {
  const neg = grains < 0n; if (neg) grains = -grains;
  const whole = grains / COIN, frac = (grains % COIN).toString().padStart(8, '0').replace(/0+$/, '');
  return (neg ? '-' : '') + whole.toLocaleString('pt-BR') + (frac ? ',' + frac : '') + ' KRV';
};
export function parseKRV(str) {
  const s = String(str).trim().replace(',', '.');
  if (!/^\d+(\.\d{1,8})?$/.test(s)) throw new Error(`valor inválido: ${str}`);
  const [w, f = ''] = s.split('.');
  return BigInt(w) * COIN + BigInt(f.padEnd(8, '0'));
}
